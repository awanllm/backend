package database

import (
	"context"
	"log"
	"time"

	"github.com/awanllm/backend/internal/config"
	"github.com/go-redis/redis/v8"
)

// InitRedis initializes the Redis client.
func InitRedis(config *config.Config) *redis.Client {
	// Create a context with timeout for Redis operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get Redis configuration from config
	redisAddr := config.GetRedisAddr()

	log.Printf("Connecting to Redis at %s...", redisAddr)

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Username: config.RedisUsername,
		Password: config.RedisPassword,
	})

	// Try to ping Redis
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Printf("⚠️  Warning: Failed to connect to Redis: %v", err)
		log.Println("⚠️  Application will continue without Redis caching")
		return nil // Return nil client, and handle nil checks where Redis is used.
	}

	log.Println("✅ Successfully connected to Redis")
	return redisClient
}
