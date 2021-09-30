package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	
	"litegix-agent/auth"
	handlers "litegix-agent/handler"
	"litegix-agent/middleware"
)

func init() {
	
}

func NewRedisDB(host, port, password string) *redis.Client {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password,
		DB:       0,
	})
	return redisClient
}

func loadConfiguration(file string) Config {
    configFile, err := os.Open(file)
    defer configFile.Close()
    if err != nil {
        log.Println(err.Error())
    }
    jsonParser := json.NewDecoder(configFile)

	config := handlers.Config{}
    err = jsonParser.Decode(&config)
	if err != nil {
		log.Fatal("can't decode config JSON: ", err)
	}
    return config
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	config := loadConfiguration("./config.json")
	log.Println(config.ServerID)
	
	var rd = auth.NewAuth()	//TODO
	var tk = auth.NewToken()
	var service = handlers.NewHandler(rd, tk, config)

	var router = gin.Default()

	router.POST("/login", service.Login)
	router.POST("/logout", middleware.TokenAuthMiddleware(), service.Logout)
	router.POST("/refresh", service.Refresh)
	router.POST("/system/user/create", middleware.TokenAuthMiddleware(), service.CreateSystemUser)
	router.POST("/database/create", middleware.TokenAuthMiddleware(), service.CreateDatabase)
	router.POST("/database/user/create", middleware.TokenAuthMiddleware(), service.CreateDatabaseUser)
	router.POST("/php/version", middleware.TokenAuthMiddleware(), service.ChangePhpVersion)
	router.POST("/sshkey/create", middleware.TokenAuthMiddleware(), service.AddSSHKey)
	router.POST("/deploymentkey/create", middleware.TokenAuthMiddleware(), service.AddDeploymentKey)
	router.POST("/cronjob/create", middleware.TokenAuthMiddleware(), service.CreateCronJob)
	router.POST("/supervisorjob/create", middleware.TokenAuthMiddleware(), service.CreateSuperVisor)
	router.POST("/firewall/addrule", middleware.TokenAuthMiddleware(), service.AddFirewallRule)
	router.POST("/services/view", middleware.TokenAuthMiddleware(), service.ViewServices)

	srv := &http.Server{
		Addr:    ":21000",
		Handler: router,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()
	//Wait for interrupt signal to gracefully shutdown the server with a timeout of 10 seconds
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exiting")
}
