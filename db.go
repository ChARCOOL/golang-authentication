package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDB(host, port, user, password, dbname string) {
	psqlConn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlConn)
	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}

	DB = db
}

func CreateUser(username, email, password string) (string, error) {
	var uuid string

	err := DB.QueryRow("SELECT uuid_generate_v4()").Scan(&uuid)
	if err != nil {
		return "", err
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	_, err = DB.Exec("INSERT INTO users (id, username, email, password) VALUES (($1), $2, $3, $4)", uuid, username, email, hashedPassword)
	if err != nil {
		return "", err
	}

	return uuid, nil
}

func GetUserByEmail(email string) (*User, error) {
	query := "SELECT id, username, email, password, createdat, updatedat FROM users WHERE Email = $1"
	row := DB.QueryRow(query, email)
	user := &User{}
	err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}
