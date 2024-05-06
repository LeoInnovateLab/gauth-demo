package main

import (
	"github.com/LeoInnovateLab/gauth"
	"github.com/LeoInnovateLab/gauth/utils"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/schema"
	"log"
	"net/http"
)

func homeHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.tmpl", gin.H{})
}

func loginHandler(c *gin.Context) {
	source := c.Param("source")
	authRequest := pickAuthRequest(source)
	authorizeUrl, err := authRequest.Authorize(utils.CreateState())
	if err != nil {
		log.Printf("Failed to authorize:%v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to authorize",
		})
		return
	}

	c.Redirect(http.StatusMovedPermanently, authorizeUrl)
}

func callbackHandler(c *gin.Context) {
	source := c.Param("source")
	authRequest := pickAuthRequest(source)

	var callback gauth.AuthCallback

	decoder := schema.NewDecoder()
	decoder.IgnoreUnknownKeys(true)
	err := decoder.Decode(&callback, c.Request.URL.Query())
	if err != nil {
		log.Printf("Failed to decode request body:%v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to decode request body",
		})
		return
	}

	response, err := authRequest.Login(callback)

	if err != nil {
		log.Printf("Failed to login:%v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": response,
	})
}
