package models

import (
	"time"

	"github.com/google/uuid"
)

// Chat represents a chat room
type Chat struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Name      string
	IsPrivate bool
	UserID    uuid.UUID `gorm:"type:uuid"`
}
