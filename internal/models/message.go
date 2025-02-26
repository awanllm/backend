package models

import (
	"time"

	"github.com/google/uuid"
)

// Message represents a chat message
type Message struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	ChatID    uuid.UUID `gorm:"type:uuid"`
	Role      string    `gorm:"type:varchar(10);check:role IN ('user', 'assistant')"`
	Content   string
	Timestamp time.Time
}
