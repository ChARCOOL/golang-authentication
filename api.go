package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		next.ServeHTTP(w, r)
	})
}

func RunServer(listenAddr string) {
	router := mux.NewRouter()

	router.Use(cors)

	router.HandleFunc("/user/register", handleRegister).Methods("POST")
	router.HandleFunc("/user/login", handleLogin).Methods("POST")
	router.HandleFunc("/user/me", handleMe).Methods("GET")

	log.Fatal(http.ListenAndServe(listenAddr, router))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	type User struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var user User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	uuid, err := CreateUser(user.Username, user.Email, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := map[string]interface{}{
		"uuid": uuid,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	type Login struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var login Login

	if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(login.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := ComparePassword(user.Password, login.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now()

	claims := map[string]interface{}{
		"email":    user.Email,
		"username": user.Username,
		"iat":      now.Unix(),
		"exp":      now.Add(time.Minute * 15).Unix(),
	}

	secretKey := GetEnv("JWT_SECRET_KEY", "SuperSecretKey")
	token, err := CreateTokenWithClaims(&claims, secretKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cookie := &http.Cookie{
		Name:     "auth-token",
		Value:    token,
		Path:     "/",
		MaxAge:   int((time.Minute * 15) / time.Second),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	resp := map[string]interface{}{
		"uuid": user.ID,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	authToken, err := r.Cookie("auth-token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ok, err := VerifyToken(authToken.Value, GetEnv("JWT_SECRET_KEY", "SuperSecretKey"))
	if err != nil || !ok {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	payload, err := ParseToken(authToken.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
