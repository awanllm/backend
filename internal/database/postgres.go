package database

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/awanllm/backend/internal/config"
	"github.com/awanllm/backend/internal/models"
)

// initializes PostgreSQL db connection
func InitDB(config *config.Config) *gorm.DB {
	var err error
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		config.DBHost,
		config.DBUser,
		config.DBPassword,
		config.DBName,
		config.DBPort,
		config.DBSSLMode,
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// auto migrate schema
	db.AutoMigrate(&models.User{}, &models.Chat{}, &models.Message{})
	return db
}
