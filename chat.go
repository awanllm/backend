package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type CreateChatRequest struct {
	Name      string `json:"name" binding:"required"`
	IsPrivate bool   `json:"isPrivate"`
}

type ChatResponse struct {
	ID        uint      `json:"id"`
	Name      string    `json:"name"`
	IsPrivate bool      `json:"isPrivate"`
	CreatedAt time.Time `json:"createdAt"`
}

type MessageRequest struct {
	Content string `json:"content" binding:"required"`
	Model   string `json:"model" binding:"omitempty"` // Optional, will use OLLAMA_DEFAULT_MODEL if not provided
}

type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OllamaChatRequest struct {
	Model       string          `json:"model"`
	Messages    []OllamaMessage `json:"messages"`
	Stream      bool            `json:"stream"`
	Temperature float64         `json:"temperature,omitempty"`
}

type OllamaResponse struct {
	ID      string    `json:"id"`
	Object  string    `json:"object"`
	Created int64     `json:"created"`
	Model   string    `json:"model"`
	Choices []Choice  `json:"choices"`
	Error   *APIError `json:"error,omitempty"`
}

type Choice struct {
	Delta        Delta  `json:"delta"`
	Index        int    `json:"index"`
	FinishReason string `json:"finish_reason,omitempty"`
}

type Delta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

type MessageResponse struct {
	ID        uint      `json:"id"`
	ChatID    uint      `json:"chatId"`
	UserID    uint      `json:"userId"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

func listChatsHandler(c *gin.Context) {
	userID := c.GetUint("userID")
	var chats []Chat
	
	if err := db.Where("user_id = ?", userID).Find(&chats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chats"})
		return
	}

	var response []ChatResponse
	for _, chat := range chats {
		response = append(response, ChatResponse{
			ID:        chat.ID,
			Name:      chat.Name,
			IsPrivate: chat.IsPrivate,
			CreatedAt: chat.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

func createChatHandler(c *gin.Context) {
	var req CreateChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")
	chat := Chat{
		Name:      req.Name,
		IsPrivate: req.IsPrivate,
		UserID:    userID,
	}

	if err := db.Create(&chat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chat"})
		return
	}

	c.JSON(http.StatusCreated, ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	})
}

func getChatHandler(c *gin.Context) {
	chatID, err := strconv.ParseUint(c.Param("chatId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	var chat Chat
	if err := db.First(&chat, chatID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
		return
	}

	c.JSON(http.StatusOK, ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	})
}

func getChatMessagesHandler(c *gin.Context) {
	chatID, err := strconv.ParseUint(c.Param("chatId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	// Try to get messages from Redis first
	ctx := context.Background()
	cacheKey := fmt.Sprintf("chat:%d:messages", chatID)
	messages, err := rdb.LRange(ctx, cacheKey, 0, -1).Result()
	
	if err == nil && len(messages) > 0 {
		var response []MessageResponse
		for _, msg := range messages {
			var msgResponse MessageResponse
			if err := json.Unmarshal([]byte(msg), &msgResponse); err != nil {
				continue
			}
			response = append(response, msgResponse)
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// If not in Redis, get from database
	var dbMessages []Message
	if err := db.Where("chat_id = ?", chatID).Order("created_at DESC").Find(&dbMessages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
		return
	}

	var response []MessageResponse
	for _, msg := range dbMessages {
		response = append(response, MessageResponse{
			ID:        msg.ID,
			ChatID:    msg.ChatID,
			UserID:    msg.UserID,
			Content:   msg.Content,
			Timestamp: msg.Timestamp,
		})

		// Cache the message in Redis
		msgJSON, _ := json.Marshal(response[len(response)-1])
		rdb.RPush(ctx, cacheKey, msgJSON)
	}

	// Set expiration for cache
	rdb.Expire(ctx, cacheKey, time.Hour*24)

	c.JSON(http.StatusOK, response)
}

func streamAIResponseHandler(c *gin.Context) {
	chatID, err := strconv.ParseUint(c.Param("chatId"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	var req MessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetUint("userID")

	// Get previous messages from the chat
	var previousMessages []Message
	if err := db.Where("chat_id = ?", chatID).Order("created_at ASC").Find(&previousMessages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat history"})
		return
	}

	// Convert previous messages to Ollama format
	ollamaMessages := make([]OllamaMessage, 0, len(previousMessages)+1)
	for _, msg := range previousMessages {
		role := "assistant"
		if msg.UserID == userID {
			role = "user"
		}
		ollamaMessages = append(ollamaMessages, OllamaMessage{
			Role:    role,
			Content: msg.Content,
		})
	}

	// Add the current message
	ollamaMessages = append(ollamaMessages, OllamaMessage{
		Role:    "user",
		Content: req.Content,
	})

	// Prepare Ollama request
	model := req.Model
	if model == "" {
		model = os.Getenv("OLLAMA_DEFAULT_MODEL")
	}

	ollamaReq := OllamaChatRequest{
		Model:       model,
		Messages:    ollamaMessages,
		Stream:      true,
		Temperature: 0.7,
	}

	// Set headers for SSE
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")

	// Create channels for response handling
	responseChan := make(chan string)
	errorChan := make(chan error)

	// Make request to Ollama API
	go func() {
		// Log request
		reqBody, err := json.Marshal(ollamaReq)
		if err != nil {
			errorChan <- err
			return
		}
		log.Printf("🌐 Sending request to Ollama: %s", string(reqBody))

		// Get Ollama configuration from environment
		ollamaHost := os.Getenv("OLLAMA_HOST")
		ollamaURL := fmt.Sprintf("https://%s/chat/completions", ollamaHost)
		log.Printf("🔗 Connecting to Ollama at: %s", ollamaURL)

		resp, err := http.Post(ollamaURL, "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			log.Printf("❌ Error connecting to Ollama: %v", err)
			errorChan <- err
			return
		}
		defer resp.Body.Close()
		log.Printf("✅ Connected to Ollama (Status: %s)", resp.Status)

		// Create a scanner to read the streaming response line by line
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			// Log raw response
			rawResp := scanner.Bytes()
			log.Printf("📥 Raw response: %s", string(rawResp))

			var ollamaResp OllamaResponse
			if err := json.Unmarshal(rawResp, &ollamaResp); err != nil {
				log.Printf("❌ Error parsing response: %v", err)
				errorChan <- err
				return
			}

			if ollamaResp.Error != nil {
				log.Printf("❌ Ollama error: %s (%s)", ollamaResp.Error.Message, ollamaResp.Error.Type)
				errorChan <- fmt.Errorf("%s: %s", ollamaResp.Error.Type, ollamaResp.Error.Message)
				return
			}

			// Process each choice in the response
			for _, choice := range ollamaResp.Choices {
				if choice.Delta.Content != "" {
					log.Printf("📤 Streaming content: %s", choice.Delta.Content)
					responseChan <- choice.Delta.Content
				}

				if choice.FinishReason == "stop" {
					log.Println("✅ Stream completed")
					close(responseChan)
					break
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("❌ Scanner error: %v", err)
			errorChan <- err
		}
	}()

	// Stream the response
	var fullResponse string
	c.Stream(func(w io.Writer) bool {
		select {
		case token, ok := <-responseChan:
			if !ok {
				// Save the complete message to database and Redis
				message := Message{
					ChatID:    uint(chatID),
					UserID:    userID,
					Content:   fullResponse,
					Timestamp: time.Now(),
				}
				
				if err := db.Create(&message).Error; err != nil {
					errorChan <- err
					return false
				}

				// Cache in Redis
				ctx := context.Background()
				cacheKey := fmt.Sprintf("chat:%d:messages", chatID)
				msgResponse := MessageResponse{
					ID:        message.ID,
					ChatID:    message.ChatID,
					UserID:    message.UserID,
					Content:   message.Content,
					Timestamp: message.Timestamp,
				}
				msgJSON, _ := json.Marshal(msgResponse)
				rdb.RPush(ctx, cacheKey, msgJSON)
				rdb.Expire(ctx, cacheKey, time.Hour*24)

				return false
			}
			
			fullResponse += token
			c.SSEvent("message", token)
			return true
			
		case err := <-errorChan:
			c.SSEvent("error", err.Error())
			return false
			
		case <-c.Request.Context().Done():
			return false
		}
	})
}
