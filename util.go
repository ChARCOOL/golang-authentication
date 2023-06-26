package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
}

func GetEnv(envName, defaultValue string) string {
	if env := os.Getenv(envName); env != "" {
		return env
	}

	return defaultValue
}

func CreateTokenWithClaims(payload *map[string]interface{}, secret string) (string, error) {
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerStr, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadStr, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	encoder := base64.RawURLEncoding

	headerEncoded := encoder.EncodeToString(headerStr)
	payloadEncoded := encoder.EncodeToString(payloadStr)

	signingInput := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))

	signature := h.Sum(nil)

	token := fmt.Sprintf("%s.%s", signingInput, encoder.EncodeToString(signature))

	return token, nil
}

func VerifyToken(token, secret string) (bool, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return false, errors.New("invalid token format")
	}

	headerEncoded := tokenParts[0]
	payloadEncoded := tokenParts[1]
	signatureEncoded := tokenParts[2]

	var header struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}

	headerDecoded, err := base64.RawURLEncoding.DecodeString(headerEncoded)
	if err != nil {
		return false, errors.New("invalid header encoding")
	}

	if err := json.Unmarshal(headerDecoded, &header); err != nil {
		return false, errors.New("failed to decode header JSON")
	}

	if header.Typ != "JWT" {
		return false, errors.New("invalid token type")
	}

	signingInput := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))

	calculated := h.Sum(nil)

	signatureDecoded, err := base64.RawURLEncoding.DecodeString(signatureEncoded)
	if err != nil {
		return false, errors.New("invalid signature encoding")
	}

	if !hmac.Equal(calculated, signatureDecoded) {
		return false, errors.New("invalid signature")
	}

	var claims Claims

	payloadDecoded, err := base64.RawURLEncoding.DecodeString(payloadEncoded)
	if err != nil {
		return false, errors.New("invalid payload encoding")
	}

	if err := json.Unmarshal(payloadDecoded, &claims); err != nil {
		return false, errors.New("failed to decode payload JSON")
	}

	currentUnixTime := time.Now().Unix()

	if claims.Iat > currentUnixTime {
		return false, errors.New("token issued in the future")
	}

	if claims.Exp <= currentUnixTime {
		return false, errors.New("token has expired")
	}

	return true, nil
}

func ParseToken(token string) (map[string]interface{}, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.New("invalid token")
	}

	payloadEncoded := tokenParts[1]

	encoder := base64.RawURLEncoding

	payloadDecoded, err := encoder.DecodeString(payloadEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}

	err = json.Unmarshal(payloadDecoded, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return payload, nil
}

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashed), nil
}

func ComparePassword(hashed, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
}
