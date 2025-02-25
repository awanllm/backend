package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	db    *gorm.DB
	rdb   *redis.Client
)

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

func initDB() {
	var err error
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SSLMODE"),
	)
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto migrate the schema
	db.AutoMigrate(&User{}, &Chat{}, &Message{})
}

func initRedis() {
	// Create a context with timeout for Redis operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get Redis configuration from environment
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort)

	log.Printf("Connecting to Redis at %s...", redisAddr)

	rdb = redis.NewClient(&redis.Options{
		Addr:         redisAddr,
		Username:     os.Getenv("REDIS_USERNAME"),
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		DialTimeout:  5 * time.Second,  // Connection timeout
		ReadTimeout:  3 * time.Second,  // Read timeout
		WriteTimeout: 3 * time.Second,  // Write timeout
		PoolTimeout:  4 * time.Second,  // Pool timeout
	})

	// Try to ping Redis
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Printf("⚠️  Warning: Failed to connect to Redis: %v", err)
		log.Println("⚠️  Application will continue without Redis caching")
		return
	}

	log.Println("✅ Successfully connected to Redis")
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	// Configure CORS middleware
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{os.Getenv("FRONTEND_URL")}
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.ExposeHeaders = []string{"Content-Length"}
	config.AllowCredentials = true
	r.Use(cors.New(config))

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	// API routes will be added here
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

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// Initialize database connections
	initDB()
	initRedis()

	// Setup and run the server
	r := setupRouter()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
