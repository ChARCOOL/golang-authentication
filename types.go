package main

import (
	"time"

	"github.com/lib/pq"
)

type User struct {
	ID        string      `json:"id"`
	Username  string      `json:"username"`
	Email     string      `json:"email"`
	Password  string      `json:"password"`
	CreatedAt time.Time   `json:"createdAt"`
	UpdatedAt pq.NullTime `json:"updatedAt"`
}
