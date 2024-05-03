package main

import (
	"encoding/json"
	"fmt"
	"github.com/LeoInnovateLab/gauth"
	_ "github.com/LeoInnovateLab/gauth/register"
	"github.com/LeoInnovateLab/gauth/utils"
	"github.com/gorilla/schema"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
)

var authRequestMap = make(map[string]gauth.AuthRequest)

func main() {
	err := godotenv.Load(".env.demo")
	if err != nil {
		log.Fatalf("Error loading .env file %v", err)
	}

	port := 8080

	http.HandleFunc("GET /auth/{source}/login", login)
	http.HandleFunc("GET /auth/{source}/callback", callback)

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Printf("Failed to start server:%v", err)
		return
	}
}

func pickAuthRequest(source string) gauth.AuthRequest {
	if authRequest, ok := authRequestMap[source]; ok {
		return authRequest
	}

	var clientId, secret string

	switch source {
	case "github":
		clientId = os.Getenv("GITHUB_CLIENT_ID")
		secret = os.Getenv("GITHUB_SECRET")
		break
	case "google":
		clientId = os.Getenv("GOOGLE_CLIENT_ID")
		secret = os.Getenv("GOOGLE_SECRET")
		break
	case "facebook":
		clientId = os.Getenv("FACEBOOK_APP_ID")
		secret = os.Getenv("FACEBOOK_APP_SECRET")
		break
	}

	authRequest, err := gauth.New().
		Source(source).
		ClientId(clientId).
		ClientSecret(secret).
		RedirectUrl(fmt.Sprintf("http://localhost:8080/auth/%s/callback", source)).
		Build()

	if err != nil {
		log.Fatalf("Failed to build request:%v", err)
	}

	authRequestMap[source] = authRequest

	return authRequest
}

func login(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	authRequest := pickAuthRequest(source)
	authorizeUrl, err := authRequest.Authorize(utils.CreateState())
	if err != nil {
		log.Printf("Failed to authorize:%v", err)
		http.Error(w, "Failed to authorize", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authorizeUrl, http.StatusMovedPermanently)
}

func callback(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	authRequest := pickAuthRequest(source)

	var c gauth.AuthCallback

	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	err := decoder.Decode(&c, r.URL.Query())
	if err != nil {
		log.Printf("Failed to decode request body:%v", err)
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	response, err := authRequest.Login(c)
	var jsonByte []byte
	if err != nil {
		log.Printf("Failed to login:%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		jsonByte, _ = json.Marshal(response)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonByte)
}
