# HopV4 Backend

## Features

- Real-time AI response streaming using Server-Sent Events (SSE)
- RESTful APIs for chat management and user operations
- JWT-based authentication
- PostgreSQL for persistent storage
- Redis for caching chat histories

## Prerequisites

- Go 1.21 or later
- PostgreSQL 13 or later
- Redis 6 or later

## Setup

1. Install dependencies:
```bash
go mod download
```

2. Set up PostgreSQL:
```sql
CREATE DATABASE hop_chat;
```

3. Configure environment variables according to `.env.example`.

4. Run the application:
```bash
go run .
```

The server will start on port 8080 by default.

## API Endpoints

### Authentication
- POST `/api/auth/register` - Register a new user
- POST `/api/auth/login` - Login and receive JWT token

### Chats
- GET `/api/chats` - List all chats for the authenticated user
- POST `/api/chats` - Create a new chat
- GET `/api/chats/:chatId` - Get chat details
- GET `/api/chats/:chatId/messages` - Get chat messages
- POST `/api/chats/:chatId/messages` - Send message and receive streaming AI response

## Architecture

- Uses Gin web framework for routing and middleware
- GORM as the ORM for PostgreSQL
- go-redis for Redis operations
- JWT for stateless authentication
- Server-Sent Events for real-time streaming

## Security Notes

- Passwords are hashed using bcrypt
- JWT tokens expire after 24 hours
- All chat endpoints require authentication
- Redis cache expires after 24 hours
