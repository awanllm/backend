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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Constants for Redis
const (
	RedisCacheTTL      = time.Hour * 24
	ChatCacheKeyFormat = "chat:%s"
	MsgCacheKeyFormat  = "chat:%s:messages"
)

// Request and response types
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
	Model   string `json:"model" binding:"omitempty"` // Optional, will use OLLAMA_DEFAULT_MODEL if not provided
}

type MessageResponse struct {
	ID        uuid.UUID `json:"id"`
	ChatID    uuid.UUID `json:"chatId"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// Ollama API types
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

// Redis cache helper functions
func getChatCacheKey(chatID uuid.UUID) string {
	return fmt.Sprintf(ChatCacheKeyFormat, chatID)
}

func getMessagesCacheKey(chatID uuid.UUID) string {
	return fmt.Sprintf(MsgCacheKeyFormat, chatID.String())
}

func cacheObject(ctx context.Context, key string, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal object: %v", err)
	}

	return rdb.Set(ctx, key, data, RedisCacheTTL).Err()
}

func getCachedObject(ctx context.Context, key string, obj interface{}) error {
	data, err := rdb.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}

	return json.Unmarshal(data, obj)
}

// Message handling functions
func cacheMessage(ctx context.Context, chatID uuid.UUID, msg MessageResponse) error {
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	cacheKey := getMessagesCacheKey(chatID)
	pipe := rdb.Pipeline()
	pipe.RPush(ctx, cacheKey, msgJSON)
	pipe.Expire(ctx, cacheKey, RedisCacheTTL)

	_, err = pipe.Exec(ctx)
	return err
}

func createAndSaveMessage(ctx context.Context, chatID uuid.UUID, role, content string) (*Message, error) {
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

	// Cache the message
	msgResponse := messageToResponse(message)
	if err := cacheMessage(ctx, chatID, msgResponse); err != nil {
		log.Printf("Failed to cache message: %v", err)
	}

	return &message, nil
}

func getChatMessages(ctx context.Context, chatID uuid.UUID) ([]Message, error) {
	cacheKey := getMessagesCacheKey(chatID)

	// Try cache first
	messages, err := getCachedMessages(ctx, cacheKey)
	if err == nil && len(messages) > 0 {
		return messages, nil
	}

	// Fallback to database
	var dbMessages []Message
	if err := db.Where("chat_id = ?", chatID).Order("created_at ASC").Find(&dbMessages).Error; err != nil {
		return nil, err
	}

	// Cache results for next time
	if err := cacheMessagesFromDB(ctx, cacheKey, dbMessages); err != nil {
		log.Printf("Failed to cache messages: %v", err)
	}

	return dbMessages, nil
}

func getCachedMessages(ctx context.Context, cacheKey string) ([]Message, error) {
	var messages []Message

	cachedMsgs, err := rdb.LRange(ctx, cacheKey, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	for _, msgStr := range cachedMsgs {
		var msgResponse MessageResponse
		if err := json.Unmarshal([]byte(msgStr), &msgResponse); err != nil {
			return nil, err
		}
		messages = append(messages, responseToMessage(msgResponse))
	}

	return messages, nil
}

func cacheMessagesFromDB(ctx context.Context, cacheKey string, messages []Message) error {
	pipe := rdb.Pipeline()
	pipe.Del(ctx, cacheKey)

	for _, msg := range messages {
		msgJSON, err := json.Marshal(messageToResponse(msg))
		if err != nil {
			continue
		}
		pipe.RPush(ctx, cacheKey, msgJSON)
	}

	pipe.Expire(ctx, cacheKey, RedisCacheTTL)
	_, err := pipe.Exec(ctx)
	return err
}

// Conversion helpers
func messageToResponse(msg Message) MessageResponse {
	return MessageResponse{
		ID:        msg.ID,
		ChatID:    msg.ChatID,
		Role:      msg.Role,
		Content:   msg.Content,
		Timestamp: msg.Timestamp,
	}
}

func responseToMessage(resp MessageResponse) Message {
	return Message{
		ID:        resp.ID,
		ChatID:    resp.ChatID,
		Role:      resp.Role,
		Content:   resp.Content,
		Timestamp: resp.Timestamp,
	}
}

func messagesToResponses(messages []Message) []MessageResponse {
	responses := make([]MessageResponse, len(messages))
	for i, msg := range messages {
		responses[i] = messageToResponse(msg)
	}
	return responses
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

// Ollama API helpers
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

func getOllamaURL() string {
	ollamaHost := os.Getenv("OLLAMA_HOST")
	return fmt.Sprintf("https://%s/chat/completions", ollamaHost)
}

func setupOllamaRequest(messages []OllamaMessage, model string) (*http.Request, error) {
	ollamaReq := prepareOllamaRequest(messages, model)

	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Log the request for debugging
	log.Printf("🌐 Sending request to Ollama: %s", string(reqBody))

	// Create HTTP request
	req, err := http.NewRequest("POST", getOllamaURL(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// Chat handlers
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
		ID:        req.ID,
		Name:      req.Name,
		IsPrivate: req.IsPrivate,
		UserID:    userID,
	}

	if err := db.Create(&chat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chat"})
		return
	}

	// Cache the chat data
	chatResponse := ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	}

	if err := cacheObject(context.Background(), getChatCacheKey(chat.ID), chatResponse); err != nil {
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
	cacheKey := getChatCacheKey(chatID)

	// Try to get chat from Redis first
	var chatResponse ChatResponse
	if err := getCachedObject(ctx, cacheKey, &chatResponse); err == nil {
		c.JSON(http.StatusOK, chatResponse)
		return
	}

	// If not in cache, get from database
	var chat Chat
	if err := db.First(&chat, "id = ?", chatID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Chat not found"})
		return
	}

	// Cache the chat data
	chatResponse = ChatResponse{
		ID:        chat.ID,
		Name:      chat.Name,
		IsPrivate: chat.IsPrivate,
		CreatedAt: chat.CreatedAt,
	}

	if err := cacheObject(ctx, cacheKey, chatResponse); err != nil {
		log.Printf("Failed to cache chat data: %v", err)
	}

	c.JSON(http.StatusOK, chatResponse)
}

func getChatMessagesHandler(c *gin.Context) {
	chatID, err := uuid.Parse(c.Param("chatId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chat ID"})
		return
	}

	messages, err := getChatMessages(context.Background(), chatID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch messages"})
		return
	}

	c.JSON(http.StatusOK, messagesToResponses(messages))
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

	// Get previous messages
	previousMessages, err := getChatMessages(ctx, chatID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat history"})
		return
	}

	// Convert previous messages to Ollama format and add the current message
	ollamaMessages := convertToOllamaMessages(previousMessages)
	ollamaMessages = append(ollamaMessages, OllamaMessage{
		Role:    "user",
		Content: req.Content,
	})

	// Save the user message
	if _, err := createAndSaveMessage(ctx, chatID, "user", req.Content); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user message"})
		return
	}

	// Setup HTTP response for streaming
	c.Header("Content-Type", "text/plain")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")

	// Setup channels for communication
	responseChan := make(chan string)
	errorChan := make(chan error)

	// Make request to Ollama API
	go func() {
		// Create and send request
		request, err := setupOllamaRequest(ollamaMessages, req.Model)
		if err != nil {
			errorChan <- err
			return
		}

		client := &http.Client{}
		resp, err := client.Do(request)
		if err != nil {
			log.Printf("❌ Error connecting to Ollama: %v", err)
			errorChan <- err
			return
		}
		defer resp.Body.Close()

		log.Printf("✅ Connected to Ollama (Status: %s)", resp.Status)

		// Process streaming response
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			// Get raw response
			rawResp := scanner.Text()

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
				close(responseChan)
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

	// Stream the response
	var fullResponse string
	c.Stream(func(w io.Writer) bool {
		select {
		case token, ok := <-responseChan:
			if !ok {
				// Save and cache the complete AI response
				if _, err := createAndSaveMessage(ctx, chatID, "assistant", fullResponse); err != nil {
					log.Printf("Failed to save AI response: %v", err)
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
