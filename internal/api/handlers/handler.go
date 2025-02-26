package handlers

import (
	"github.com/awanllm/backend/internal/config"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

// handler is the core struct with all dependencies
type handler struct {
	db          *gorm.DB
	redisClient *redis.Client
	ollamaURL   string
	config      *config.Config
}

// NewHandler creates a new handler instance
func NewHandler(db *gorm.DB, redisClient *redis.Client, ollamaURL string, config *config.Config) *handler {
	return &handler{
		db,
		redisClient,
		ollamaURL,
		config,
	}
}
