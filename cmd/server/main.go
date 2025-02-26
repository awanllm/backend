package main

import (
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"github.com/awanllm/backend/internal/api/handlers"
	"github.com/awanllm/backend/internal/api/middleware"
	"github.com/awanllm/backend/internal/config"
	"github.com/awanllm/backend/internal/database"
)

var (
	db          *gorm.DB
	redisClient *redis.Client
)

func main() {
	// Load configuration
	config, nil := config.LoadConfig()

	// Initialize database connections
	db = database.InitDB(config)
	redisClient = database.InitRedis(config)

	// Setup and run the server
	r := setupRouter(db, redisClient, config)
	port := config.ServerPort

	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func setupRouter(db *gorm.DB, redisClient *redis.Client, config *config.Config) *gin.Engine {
	r := gin.Default()

	// Configure CORS middleware
	headers := cors.DefaultConfig()
	headers.AllowOrigins = []string{config.FrontendURL}
	headers.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	headers.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	headers.ExposeHeaders = []string{"Content-Length"}
	headers.AllowCredentials = true
	r.Use(cors.New(headers))

	// Initialize handlers and middleware with dependencies
	handler := handlers.NewHandler(db, redisClient, config.OllamaHost, config)
	authMiddleware := middleware.NewAuthMiddleware(config.JWTSecret)

	// API routes
	api := r.Group("/api")
	{
		// Auth routes
		authGroup := api.Group("/auth")
		{
			authGroup.POST("/register", handler.RegisterHandler)
			authGroup.POST("/login", handler.LoginHandler)
		}

		// Chat routes - protected by authentication
		chats := api.Group("/chats", authMiddleware.AuthMiddleware())
		{
			chats.GET("", handler.ListChats)
			chats.POST("", handler.CreateChat)
			chats.GET("/:chatId/messages", handler.GetChatMessages)
			chats.POST("/:chatId/messages", handler.StreamAIResponse)
		}
	}

	return r
}
