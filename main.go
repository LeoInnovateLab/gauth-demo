package main

import (
	"fmt"
	"github.com/LeoInnovateLab/gauth"
	_ "github.com/LeoInnovateLab/gauth/register"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"log"
	"os"
)

var authRequestMap = make(map[string]gauth.AuthRequest)

func main() {
	err := godotenv.Load(".env.demo")
	if err != nil {
		log.Fatalf("Error loading .env file %v", err)
	}

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/assets", "./assets")

	r.GET("/", homeHandler)
	r.GET("/auth/:source/login", loginHandler)
	r.GET("/auth/:source/callback", callbackHandler)

	r.Run(":8080")
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
