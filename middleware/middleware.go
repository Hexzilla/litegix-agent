package middleware

import (
	"github.com/gin-gonic/gin"
	"litegix-agent/auth"
	"net/http"
)

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := auth.TokenValid(c.Request)
		if err != nil  {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		c.Next()
	}
}

