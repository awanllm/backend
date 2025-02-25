package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CreateChatRequest struct {
	ID		  uuid.UUID	`json:"id"`
	Name      string 	`json:"name" binding:"required"`
	IsPrivate bool   	`json:"isPrivate"`
}

type ChatResponse struct {
	ID        uuid.UUID `json:"id"`
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
	ID        uuid.UUID `json:"id"`
	ChatID    uuid.UUID `json:"chatId"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

func listChatsHandler(c *gin.Context) {
	userID := c.MustGet("userID").(uuid.UUID)
	var chats []Chat
	
	if err := db.Where("user_id = ?", userID).Find(&chats).Error; err != nil {
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

func createChatHandler(c *gin.Context) {
	var req CreateChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.MustGet("userID").(uuid.UUID)
	chat := Chat{
		ID:		   req.ID,
		Name:      req.Name,
		IsPrivate: req.IsPrivate,
		UserID:    userID,
	}

	if err := db.Create(&chat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chat"})
		return
	}

	// Cache the chat data in Redis
	ctx := context.Background()
	chatResponse := ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	}
	chatJSON, _ := json.Marshal(chatResponse)
	chatKey := fmt.Sprintf("chat:%s", chat.ID)
	if err := rdb.Set(ctx, chatKey, chatJSON, time.Hour*24).Err(); err != nil {
		log.Printf("Failed to cache chat data: %v", err)
	}

	c.JSON(http.StatusCreated, chatResponse)
}

func getChatHandler(c *gin.Context) {
	chatID, err := uuid.Parse(c.Param("chatId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	ctx := context.Background()
	chatKey := fmt.Sprintf("chat:%s", chatID)

	// Try to get chat from Redis first
	chatData, err := rdb.Get(ctx, chatKey).Bytes()
	if err == nil {
		var chatResponse ChatResponse
		if err := json.Unmarshal(chatData, &chatResponse); err == nil {
			c.JSON(http.StatusOK, chatResponse)
			return
		}
	}

	// If not in cache, get from database
	var chat Chat
	if err := db.First(&chat, "id = ?", chatID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
		return
	}

	// Cache the chat data
	chatResponse := ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	}
	chatJSON, _ := json.Marshal(chatResponse)
	if err := rdb.Set(ctx, chatKey, chatJSON, time.Hour*24).Err(); err != nil {
		log.Printf("Failed to cache chat data: %v", err)
	}

	c.JSON(http.StatusOK, chatResponse)
}

func cacheMessage(ctx context.Context, cacheKey string, msg MessageResponse) error {
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	msgPipe := rdb.Pipeline()
	msgPipe.RPush(ctx, cacheKey, msgJSON)
	msgPipe.Expire(ctx, cacheKey, time.Hour*24)

	if _, err := msgPipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to cache message: %v", err)
	}
	return nil
}

func getCachedMessages(ctx context.Context, cacheKey string) ([]Message, error) {
	var messages []Message

	// Try to get messages from Redis
	cachedMsgs, err := rdb.LRange(ctx, cacheKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get messages from cache: %v", err)
	}

	for _, msgStr := range cachedMsgs {
		var msgResponse MessageResponse
		if err := json.Unmarshal([]byte(msgStr), &msgResponse); err != nil {
			return nil, fmt.Errorf("failed to unmarshal message: %v", err)
		}
		messages = append(messages, Message{
			ID:        msgResponse.ID,
			ChatID:    msgResponse.ChatID,
			Role:      msgResponse.Role,
			Content:   msgResponse.Content,
			Timestamp: msgResponse.Timestamp,
		})
	}

	return messages, nil
}

func cacheMessagesFromDB(ctx context.Context, cacheKey string, messages []Message) error {
	msgPipe := rdb.Pipeline()
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

func convertToOllamaMessages(messages []Message) []OllamaMessage {
	ollamaMessages := make([]OllamaMessage, 0, len(messages))
	for _, msg := range messages {
		ollamaMessages = append(ollamaMessages, OllamaMessage{
			Role:    msg.Role,
			Content: msg.Content,
		})
	}
	return ollamaMessages
}

func convertMessagesToResponse(messages []Message) []MessageResponse {
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

func getChatMessagesHandler(c *gin.Context) {
	chatID, err := uuid.Parse(c.Param("chatId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	ctx := context.Background()
	cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())

	// Try to get messages from cache
	messages, err := getCachedMessages(ctx, cacheKey)
	if err == nil && len(messages) > 0 {
		c.JSON(http.StatusOK, convertMessagesToResponse(messages))
		return
	}

	// If not in cache, get from database
	var dbMessages []Message
	if err := db.Where("chat_id = ?", chatID).Order("created_at DESC").Find(&dbMessages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
		return
	}

	// Cache the messages from database
	if err := cacheMessagesFromDB(ctx, cacheKey, dbMessages); err != nil {
		log.Printf("Failed to cache messages: %v", err)
	}

	c.JSON(http.StatusOK, convertMessagesToResponse(dbMessages))
}

func prepareOllamaRequest(messages []OllamaMessage, model string) OllamaChatRequest {
	if model == "" {
		model = os.Getenv("OLLAMA_DEFAULT_MODEL")
	}

	return OllamaChatRequest{
		Model:       model,
		Messages:    messages,
		Stream:      true,
		Temperature: 0.7,
	}
}

func setupStreamHeaders(c *gin.Context) {
	c.Header("Content-Type", "text/plain")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")
}

func logOllamaRequest(ollamaReq OllamaChatRequest) error {
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}
	log.Printf("🌐 Sending request to Ollama: %s", string(reqBody))
	return nil
}

func getOllamaURL() string {
	ollamaHost := os.Getenv("OLLAMA_HOST")
	ollamaURL := fmt.Sprintf("https://%s/chat/completions", ollamaHost)
	log.Printf("🔗 Connecting to Ollama at: %s", ollamaURL)
	return ollamaURL
}

func createAndCacheMessage(ctx context.Context, chatID uuid.UUID, role, content string) (*Message, error) {
	message := Message{
		ChatID:    chatID,
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	}

	// Save to database
	if err := db.Create(&message).Error; err != nil {
		return nil, fmt.Errorf("failed to save message: %v", err)
	}

	// Cache in Redis
	cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())
	msgResponse := MessageResponse{
		ID:        message.ID,
		ChatID:    message.ChatID,
		Role:      message.Role,
		Content:   message.Content,
		Timestamp: message.Timestamp,
	}

	if err := cacheMessage(ctx, cacheKey, msgResponse); err != nil {
		log.Printf("Failed to cache message: %v", err)
	}

	return &message, nil
}

func streamAIResponseHandler(c *gin.Context) {
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

	cacheKey := fmt.Sprintf("chat:%s:messages", chatID.String())
	var previousMessages []Message
	previousMessages, fetchErr := getCachedMessages(ctx, cacheKey)
	if fetchErr != nil || len(previousMessages) == 0 {
		// Fallback to database
		if dbErr := db.Where("chat_id = ?", chatID).Order("created_at ASC").Find(&previousMessages).Error; dbErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat history"})
			return
		}

		// Cache the messages we got from database
		if cacheErr := cacheMessagesFromDB(ctx, cacheKey, previousMessages); cacheErr != nil {
			log.Printf("Failed to cache messages from DB: %v", cacheErr)
		}
	}

	// Convert previous messages to Ollama format
	ollamaMessages := convertToOllamaMessages(previousMessages)

	// Add the current message
	ollamaMessages = append(ollamaMessages, OllamaMessage{
		Role:    "user",
		Content: req.Content,
	})

	// Prepare and send Ollama request
	ollamaReq := prepareOllamaRequest(ollamaMessages, req.Model)
	setupStreamHeaders(c)

	// Create channels for response handling
	responseChan := make(chan string)
	errorChan := make(chan error)

	// Make request to Ollama API
	go func() {
		// Log request
		if err := logOllamaRequest(ollamaReq); err != nil {
			errorChan <- err
			return
		}

		// Get Ollama URL and prepare request
		ollamaURL := getOllamaURL()
		reqBody, err := json.Marshal(ollamaReq)
		if err != nil {
			errorChan <- fmt.Errorf("failed to marshal request body: %v", err)
			return
		}

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
			// Get raw response
			rawResp := scanner.Text()
			log.Printf("📥 Raw response: %s", rawResp)

			// Skip empty lines
			if rawResp == "" {
				continue
			}

			// Handle SSE format - remove "data: " prefix
			if !strings.HasPrefix(rawResp, "data: ") {
				log.Printf("❌ Invalid SSE format: %s", rawResp)
				continue
			}
			jsonData := strings.TrimPrefix(rawResp, "data: ")

			// Skip [DONE] message
			if jsonData == "[DONE]" {
				log.Println("✅ Received [DONE] message")
				return
			}

			// Parse the JSON response
			var ollamaResp OllamaResponse
			if err := json.Unmarshal([]byte(jsonData), &ollamaResp); err != nil {
				log.Printf("❌ Error parsing response: %v", err)
				continue
			}

			if ollamaResp.Error != nil {
				log.Printf("❌ Ollama error: %s (%s)", ollamaResp.Error.Message, ollamaResp.Error.Type)
				errorChan <- fmt.Errorf("%s: %s", ollamaResp.Error.Type, ollamaResp.Error.Message)
				return
			}

			// Process each choice in the response
			for _, choice := range ollamaResp.Choices {
				if choice.Delta.Content != "" {
					responseChan <- choice.Delta.Content
				}
				if choice.FinishReason == "stop" {
					log.Println("✅ Response completed")
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

	// Save and cache the user's message
	if _, saveErr := createAndCacheMessage(ctx, chatID, "user", req.Content); saveErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user message"})
		return
	}

	// Stream the response
	var fullResponse string
	c.Stream(func(w io.Writer) bool {
		select {
		case token, ok := <-responseChan:
			if !ok {
				// Save and cache the complete AI response
				_, saveErr := createAndCacheMessage(ctx, chatID, "assistant", fullResponse)
				if saveErr != nil {
					errorChan <- err
					return false
				}

				return false
			}
			
			fullResponse += token
			fmt.Fprint(w, token)
			return true
			
		case err := <-errorChan:
			fmt.Fprint(w, "Error: "+err.Error())
			return false
			
		case <-c.Request.Context().Done():
			return false
		}
	})
}
