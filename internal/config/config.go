package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config stores all the configuration of the application.
// Values are loaded from environment variables with optional
// loading from a .env file via godotenv.
type Config struct {
	// Database settings
	DBHost     string
	DBUser     string
	DBPassword string
	DBName     string
	DBPort     string
	DBSSLMode  string

	// Redis settings
	RedisHost     string
	RedisPort     string
	RedisUsername string
	RedisPassword string

	// Server settings
	ServerPort  string
	FrontendURL string
	JWTSecret   string

	// Ollama settings
	OllamaHost         string
	OllamaDefaultModel string
	OllamaTemperature  float64
}

// LoadConfig reads configuration from environment variables and .env file.
// It returns the loaded configuration or an error if required values are missing.
func LoadConfig() (*Config, error) {
	// Try to load .env file, but proceed even if it doesn't exist
	if err := godotenv.Load(); err != nil {
		if os.IsNotExist(err) {
			log.Println("No .env file found, using environment variables only")
		} else {
			log.Printf("Warning: Error loading .env file: %v", err)
		}
	} else {
		log.Println("Environment loaded from .env file")
	}

	config := &Config{
		// Database settings
		DBHost:     getEnv("DB_HOST", ""),
		DBUser:     getEnv("DB_USER", ""),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", ""),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),

		// Redis settings
		RedisHost:     getEnv("REDIS_HOST", ""),
		RedisPort:     getEnv("REDIS_PORT", "6379"),
		RedisUsername: getEnv("REDIS_USERNAME", ""),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),

		// Server settings
		ServerPort:  getEnv("PORT", "8080"),
		FrontendURL: getEnv("FRONTEND_URL", ""),
		JWTSecret:   getEnv("JWT_SECRET", ""),

		// Ollama settings
		OllamaHost:         getEnv("OLLAMA_HOST", ""),
		OllamaDefaultModel: getEnv("OLLAMA_DEFAULT_MODEL", ""),
		OllamaTemperature:  getEnvAsFloat64("OLLAMA_TEMPERATURE", 0.7),
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks if the required configuration values are set and logs warnings
// for optional values that aren't set.
func (c *Config) Validate() error {
	var missingEnvs []string

	// Check required database configuration
	if c.DBHost == "" {
		missingEnvs = append(missingEnvs, "DB_HOST")
	}
	if c.DBUser == "" {
		missingEnvs = append(missingEnvs, "DB_USER")
	}
	if c.DBName == "" {
		missingEnvs = append(missingEnvs, "DB_NAME")
	}

	// JWT secret is required
	if c.JWTSecret == "" {
		missingEnvs = append(missingEnvs, "JWT_SECRET")
	}

	// Return error if any required env vars are missing
	if len(missingEnvs) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missingEnvs, ", "))
	}

	// Log warnings for optional configurations
	if c.RedisHost == "" || c.RedisPort == "" {
		log.Println("Warning: Redis configuration is incomplete, Redis features will be disabled")
	}

	if c.FrontendURL == "" {
		log.Println("Warning: FRONTEND_URL is not set, CORS might not be configured correctly")
	}

	if c.OllamaHost == "" {
		log.Println("Warning: OLLAMA_HOST is not set, AI features will be disabled")
	}

	if c.OllamaDefaultModel == "" {
		log.Println("Warning: OLLAMA_DEFAULT_MODEL is not set, using default model in Ollama client")
	}

	return nil
}

// GetDSN returns the PostgreSQL data source name (connection string)
func (c *Config) GetDSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.DBHost, c.DBPort, c.DBUser, c.DBPassword, c.DBName, c.DBSSLMode)
}

// GetRedisAddr returns the Redis address in the format host:port
func (c *Config) GetRedisAddr() string {
	return fmt.Sprintf("%s:%s", c.RedisHost, c.RedisPort)
}

// getEnv retrieves the value of the environment variable named by the key.
// If the variable is not present, the defaultValue is returned.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsFloat64 retrieves the value of the environment variable named by the key as a float64.
// If the variable is not present or cannot be converted to a float64, the defaultValue is returned.
func getEnvAsFloat64(key string, defaultValue float64) float64 {
	valueStr := getEnv(key, "")
	if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
		return value
	}
	return defaultValue
}
