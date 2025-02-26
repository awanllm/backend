package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db  *gorm.DB
	rdb *redis.Client
)

// Configuration holds all application configuration
type Config struct {
	Port        string
	Environment string
	FrontendURL string
	JWTSecret   string
	DB          DBConfig
	Redis       RedisConfig
	Ollama      OllamaConfig
}

// DBConfig holds database configuration
type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string
	Port     string
	Username string
	Password string
}

// OllamaConfig holds Ollama API configuration
type OllamaConfig struct {
	Host         string
	DefaultModel string
}

// User represents the user model
type User struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
	Username     string         `gorm:"uniqueIndex"`
	Email        string         `gorm:"uniqueIndex"`
	PasswordHash string
}

// Chat represents a chat room
type Chat struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      string
	IsPrivate bool
	UserID    uuid.UUID `gorm:"type:uuid"` // Creator of the chat
}

// Message represents a chat message
type Message struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	ChatID    uuid.UUID `gorm:"type:uuid"`
	Role      string    `gorm:"type:varchar(10);check:role IN ('user', 'assistant')"` // Role can be 'user' or 'assistant'
	Content   string
	Timestamp time.Time
}

// loadConfig loads configuration from environment variables
func loadConfig() (*Config, error) {
	config := &Config{
		Environment: getEnvWithDefault("APP_ENV", "development"),
		Port:        getEnvWithDefault("PORT", "8080"),
		FrontendURL: getEnvWithDefault("FRONTEND_URL", "http://localhost:3000"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		DB: DBConfig{
			Host:     getEnvWithDefault("DB_HOST", "localhost"),
			Port:     getEnvWithDefault("DB_PORT", "5432"),
			User:     getEnvWithDefault("DB_USER", "postgres"),
			Password: os.Getenv("DB_PASSWORD"),
			Name:     getEnvWithDefault("DB_NAME", "hop"),
			SSLMode:  getEnvWithDefault("DB_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Host:     getEnvWithDefault("REDIS_HOST", "localhost"),
			Port:     getEnvWithDefault("REDIS_PORT", "6379"),
			Username: os.Getenv("REDIS_USERNAME"),
			Password: os.Getenv("REDIS_PASSWORD"),
		},
		Ollama: OllamaConfig{
			Host:         getEnvWithDefault("OLLAMA_HOST", "http://localhost:11434"),
			DefaultModel: getEnvWithDefault("OLLAMA_DEFAULT_MODEL", "llama3.3"),
		},
	}

	// Validate critical configuration
	if config.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}

	return config, nil
}

// getEnvWithDefault returns environment variable value or default if not set
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// initDB initializes database connection
func initDB(config *Config) error {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		config.DB.Host, config.DB.User, config.DB.Password,
		config.DB.Name, config.DB.Port, config.DB.SSLMode,
	)

	logLevel := logger.Silent
	if config.Environment == "development" {
		logLevel = logger.Info
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	}

	var err error
	db, err = gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	// Set reasonable connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto migrate the schema
	if err := db.AutoMigrate(&User{}, &Chat{}, &Message{}); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	log.Println("✅ Successfully connected to database")
	return nil
}

// initRedis initializes Redis connection
func initRedis(config *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	redisAddr := fmt.Sprintf("%s:%s", config.Redis.Host, config.Redis.Port)
	log.Printf("Connecting to Redis at %s...", redisAddr)

	rdb = redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Username:     config.Redis.Username,
		Password:     config.Redis.Password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
		PoolSize:     50, // Maximum number of connections
		MinIdleConns: 10, // Minimum number of idle connections
	})

	// Try to ping Redis
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		log.Printf("⚠️  Warning: Failed to connect to Redis: %v", err)
		log.Println("⚠️  Application will continue without Redis caching")
		return nil // Non-fatal error
	}

	log.Println("✅ Successfully connected to Redis")
	return nil
}

// setupRouter configures and returns the Gin router
func setupRouter(config *Config) *gin.Engine {
	// Set Gin mode based on environment
	if config.Environment != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New() // Use New() instead of Default() for custom middleware

	// Add middleware
	r.Use(gin.Recovery())
	r.Use(requestLoggerMiddleware())
	r.Use(setupCORS(config.FrontendURL))

	// Health check endpoint
	r.GET("/health", healthCheckHandler)

	// API routes
	api := r.Group("/api")
	{
		// Auth routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", registerHandler)
			auth.POST("/login", loginHandler)
		}

		// Chat routes - protected by authentication
		chats := api.Group("/chats", authMiddleware())
		{
			chats.GET("", listChatsHandler)
			chats.POST("", createChatHandler)
			chats.GET("/:chatId", getChatHandler)
			chats.GET("/:chatId/messages", getChatMessagesHandler)
			chats.POST("/:chatId/messages", streamAIResponseHandler)
		}
	}

	return r
}

// requestLoggerMiddleware logs HTTP requests
func requestLoggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
				param.ClientIP,
				param.TimeStamp.Format(time.RFC1123),
				param.Method,
				param.Path,
				param.Request.Proto,
				param.StatusCode,
				param.Latency,
				param.Request.UserAgent(),
				param.ErrorMessage,
			)
		},
	})
}

// setupCORS configures CORS middleware
func setupCORS(frontendURL string) gin.HandlerFunc {
	config := cors.DefaultConfig()

	// Handle multiple origins if provided
	origins := strings.Split(frontendURL, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	config.AllowOrigins = origins
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.ExposeHeaders = []string{"Content-Length"}
	config.AllowCredentials = true
	config.MaxAge = 12 * 60 * 60 // 12 hours

	return cors.New(config)
}

// healthCheckHandler handles health check requests
func healthCheckHandler(c *gin.Context) {
	// Check database connection
	sqlDB, err := db.DB()
	dbStatus := "ok"
	if err != nil || sqlDB.Ping() != nil {
		dbStatus = "error"
	}

	// Check Redis connection
	redisStatus := "ok"
	if _, err := rdb.Ping(context.Background()).Result(); err != nil {
		redisStatus = "error"
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"db":      dbStatus,
		"redis":   redisStatus,
		"version": "1.0.0",
	})
}

func main() {
	// Load .env file in development
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	if err := initDB(config); err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	// Initialize Redis connection
	if err := initRedis(config); err != nil {
		log.Fatalf("Redis initialization failed: %v", err)
	}

	// Setup router
	router := setupRouter(config)

	// Create server with timeouts
	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s in %s mode", config.Port, config.Environment)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Server shutting down...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Gracefully shutdown the server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	// Close database connection
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}

	// Close Redis connection
	if rdb != nil {
		rdb.Close()
	}

	log.Println("Server exited properly")
}
