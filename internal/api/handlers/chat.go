package handlers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/awanllm/backend/internal/models"
)

type CreateChatRequest struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name" binding:"required"`
	IsPrivate bool      `json:"isPrivate"`
}

type ChatResponse struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	IsPrivate bool      `json:"isPrivate"`
	CreatedAt time.Time `json:"createdAt"`
}

type MessageRequest struct {
	Content string `json:"content" binding:"required"`
	Model   string `json:"model" binding:"omitempty"` // Optional, will use default model from config if not provided
}

type MessageResponse struct {
	ID        uuid.UUID `json:"id"`
	ChatID    uuid.UUID `json:"chatId"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

func (h *handler) CreateChat(c *gin.Context) {
	var req CreateChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(uuid.UUID)
	chat := models.Chat{
		ID:        req.ID,
		Name:      req.Name,
		IsPrivate: req.IsPrivate,
		UserID:    userID,
	}

	if err := h.db.Create(&chat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chat"})
		return
	}

	// Cache the chat data in Redis
	if h.redisClient != nil { // Check if Redis client is initialized
		ctx := context.Background()
		chatResponse := ChatResponse{
			ID:        chat.ID,
			Name:      chat.Name,
			IsPrivate: chat.IsPrivate,
			CreatedAt: chat.CreatedAt,
		}
		chatJSON, _ := json.Marshal(chatResponse)
		chatKey := fmt.Sprintf("chat:%s", chat.ID)
		if err := h.redisClient.Set(ctx, chatKey, chatJSON, time.Hour*24).Err(); err != nil {
			log.Printf("Failed to cache chat data: %v", err)
		}
	}

	c.JSON(http.StatusCreated, ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	})
}

func (h *handler) GetChatMessages(c *gin.Context) {
	chatID, err := uuid.Parse(c.Param("chatId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	var messages []models.Message

	if h.redisClient != nil { // Use cache only if Redis is initialized
		ctx := context.Background()
		cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())

		// Try to get messages from cache
		cachedMessages, cacheErr := h.getCachedMessages(ctx, cacheKey)
		if cacheErr == nil && len(cachedMessages) > 0 {
			c.JSON(http.StatusOK, h.convertMessagesToResponse(cachedMessages))
			return
		}
	}

	// If not in cache or Redis is not initialized, get from database
	var dbMessages []models.Message
	if err := h.db.Where("chat_id = ?", chatID).Order("created_at ASC").Find(&dbMessages).Error; err != nil { // Order by ASC for chat history
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
		return
	}
	messages = dbMessages // Assign dbMessages to messages for caching below

	// Cache the messages from database if Redis is available
	if h.redisClient != nil {
		ctx := context.Background()
		cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())
		if cacheErr := h.cacheMessagesFromDB(ctx, cacheKey, messages); cacheErr != nil {
			log.Printf("Failed to cache messages: %v", cacheErr)
		}
	}

	c.JSON(http.StatusOK, h.convertMessagesToResponse(messages))
}

func (h *handler) ListChats(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	var chats []models.Chat

	if err := h.db.Where("user_id = ?", userID).Find(&chats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chats"})
		return
	}

	var response = make([]ChatResponse, 0)
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

func (h *handler) cacheMessage(ctx context.Context, cacheKey string, msg MessageResponse) error {
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	msgPipe := h.redisClient.Pipeline()
	msgPipe.RPush(ctx, cacheKey, msgJSON)
	msgPipe.Expire(ctx, cacheKey, time.Hour*24)

	if _, err := msgPipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to cache message: %v", err)
	}
	return nil
}

func (h *handler) getCachedMessages(ctx context.Context, cacheKey string) ([]models.Message, error) {
	var messages []models.Message

	// Try to get messages from Redis
	cachedMsgs, err := h.redisClient.LRange(ctx, cacheKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get messages from cache: %v", err)
	}

	for _, msgStr := range cachedMsgs {
		var msgResponse MessageResponse
		if err := json.Unmarshal([]byte(msgStr), &msgResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal message: %v", err)
		}
		messages = append(messages, models.Message{
			ID:        msgResponse.ID,
			ChatID:    msgResponse.ChatID,
			Role:      msgResponse.Role,
			Content:   msgResponse.Content,
			Timestamp: msgResponse.Timestamp,
		})
	}

	return messages, nil
}

func (h *handler) createAndCacheMessage(ctx context.Context, chatID uuid.UUID, role, content string) (*models.Message, error) {
	message := models.Message{
		ChatID:    chatID,
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	}

	// Save to database
	if err := h.db.Create(&message).Error; err != nil {
		return nil, fmt.Errorf("failed to save message: %v", err)
	}

	// Cache in Redis
	if h.redisClient != nil {
		cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())
		msgResponse := MessageResponse{
			ID:        message.ID,
			ChatID:    message.ChatID,
			Role:      message.Role,
			Content:   message.Content,
			Timestamp: message.Timestamp,
		}

		if err := h.cacheMessage(ctx, cacheKey, msgResponse); err != nil {
			log.Printf("Failed to cache message: %v", err)
		}
	}

	return &message, nil
}

func (h *handler) cacheMessagesFromDB(ctx context.Context, cacheKey string, messages []models.Message) error {
	if h.redisClient == nil {
		return nil // Do not cache if Redis is not initialized
	}
	msgPipe := h.redisClient.Pipeline()
	msgPipe.Del(ctx, cacheKey)

	for _, msg := range messages {
		msgResponse := MessageResponse{
			ID:        msg.ID,
			ChatID:    msg.ChatID,
			Role:      msg.Role,
			Content:   msg.Content,
			Timestamp: msg.Timestamp,
		}
		msgJSON, err := json.Marshal(msgResponse)
		if err != nil {
			log.Printf("Failed to marshal message: %v", err)
			continue
		}
		msgPipe.RPush(ctx, cacheKey, msgJSON)
	}

	msgPipe.Expire(ctx, cacheKey, time.Hour*24)
	if _, err := msgPipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to cache messages: %v", err)
	}
	return nil
}

func (h *handler) convertToOllamaMessages(messages []models.Message) []models.OllamaMessage {
	ollamaMessages := make([]models.OllamaMessage, 0, len(messages))
	for _, msg := range messages {
		ollamaMessages = append(ollamaMessages, models.OllamaMessage{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}
	return ollamaMessages
}

func (h *handler) convertMessagesToResponse(messages []models.Message) []MessageResponse {
	response := make([]MessageResponse, len(messages))
	for i, msg := range messages {
		response[i] = MessageResponse{
			ID:        msg.ID,
			ChatID:    msg.ChatID,
			Role:      msg.Role,
			Content:   msg.Content,
			Timestamp: msg.Timestamp,
		}
	}
	return response
}

func (h *handler) prepareOllamaRequest(messages []models.OllamaMessage, model string) models.OllamaChatRequest {
	if model == "" {
		model = h.config.OllamaDefaultModel
	}

	return models.OllamaChatRequest{
		Model:       model,
		Messages:    messages,
		Stream:      true,
		Temperature: h.config.OllamaTemperature,
	}
}

func (h *handler) logOllamaRequest(ollamaReq models.OllamaChatRequest) error {
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}
	log.Printf("🌐 Sending request to Ollama: %s", string(reqBody))
	return nil
}

func (h *handler) getOllamaURL() string {
	ollamaURL := fmt.Sprintf("http://%s/chat/completions", h.config.OllamaHost)
	log.Printf("🔗 Connecting to Ollama at: %s", ollamaURL)
	return ollamaURL
}

func (h *handler) StreamAIResponse(c *gin.Context) {
	chatID, err := uuid.Parse(c.Param("chatId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	var req MessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	// Fetch previous messages
	cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())
	var previousMessages []models.Message
	previousMessages, fetchErr := h.getCachedMessages(ctx, cacheKey)
	if fetchErr != nil || len(previousMessages) == 0 {
		// Fallback to database
		if dbErr := h.db.Where("chat_id = ?", chatID).Order("created_at ASC").Find(&previousMessages).Error; dbErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat history"})
			return
		}

		// Cache the messages we got from database if Redis is available
		if h.redisClient != nil {
			if cacheErr := h.cacheMessagesFromDB(ctx, cacheKey, previousMessages); cacheErr != nil {
				log.Printf("Failed to cache messages from DB: %v", cacheErr)
			}
		}
	}

	// Convert previous messages to Ollama format
	ollamaMessages := h.convertToOllamaMessages(previousMessages)

	// Add the current message
	ollamaMessages = append(ollamaMessages, models.OllamaMessage{
		Role:    "user",
		Content: req.Content,
	})

	// Prepare Ollama request
	ollamaReq := h.prepareOllamaRequest(ollamaMessages, req.Model)

	// Set headers for SSE
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	// Save the user's message
	if _, saveErr := h.createAndCacheMessage(ctx, chatID, "user", req.Content); saveErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user message"})
		return
	}

	// Log request
	if err := h.logOllamaRequest(ollamaReq); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Prepare request body
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to marshal request: %v", err)})
		return
	}

	// Make request to Ollama API
	resp, err := http.Post(h.getOllamaURL(), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("❌ Error connecting to Ollama: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to connect to Ollama: %v", err)})
		return
	}
	defer resp.Body.Close()

	log.Printf("✅ Connected to Ollama (Status: %s)", resp.Status)

	// Stream the response directly while extracting content for saving
	var fullResponse string
	c.Stream(func(w io.Writer) bool {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()

			// Forward the raw SSE event directly to the client
			fmt.Fprintln(w, line)

			// Extract content for saving to database
			var ollamaResp models.OllamaResponse
			if err := json.Unmarshal([]byte(line), &ollamaResp); err == nil {
				for _, choice := range ollamaResp.Choices {
					if choice.Delta.Content != "" {
						fullResponse += choice.Delta.Content
					}
					if choice.FinishReason == "stop" {
						log.Println("✅ Response completed")
						// Save the assistant's complete response
						if _, saveErr := h.createAndCacheMessage(ctx, chatID, "assistant", fullResponse); saveErr != nil {
							log.Printf("Failed to save assistant response: %v", saveErr)
						}
						return false
					}
				}

				// Check for errors in the response
				if ollamaResp.Error != nil {
					log.Printf("❌ Ollama error: %s (%s)", ollamaResp.Error.Message, ollamaResp.Error.Type)
					return false
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("❌ Scanner error: %v", err)
			return false
		}

		// Save the response if we haven't already (in case there was no explicit stop)
		if fullResponse != "" {
			if _, saveErr := h.createAndCacheMessage(ctx, chatID, "assistant", fullResponse); saveErr != nil {
				log.Printf("Failed to save assistant response: %v", saveErr)
			}
		}

		return false
	})
}
