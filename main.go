package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	httpSwagger "github.com/swaggo/http-swagger"

	_ "image-api/docs"
	"image-api/handlers"
)

// @title Pixiv Image API
// @version 1.0
// @description A REST API for fetching images and illustrations from Pixiv
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url https://github.com/chiraitori/image-api

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8000
// @BasePath /
// @schemes http https

func init() {
	// Load .env file before handlers.init() runs
	godotenv.Load()
}

func main() {
	// Re-initialize client with loaded env
	handlers.InitClient()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/illust/", handlers.GetIllust)
	mux.HandleFunc("/api/image/", handlers.ProxyImage)
	mux.HandleFunc("/image", handlers.RandomImage)
	mux.HandleFunc("/manga", handlers.RandomManga)
	mux.HandleFunc("/api/search", handlers.SearchIllusts)
	mux.HandleFunc("/api/ranking", handlers.GetRanking)
	mux.HandleFunc("/api/login", handlers.Login)
	mux.HandleFunc("/api/auth/status", handlers.AuthStatus)
	mux.HandleFunc("/api/auth/token", handlers.SetTokens)
	mux.HandleFunc("/api/auth/code", handlers.ExchangeCode)
	mux.HandleFunc("/api/auth/refresh", handlers.RefreshToken)
	mux.HandleFunc("/health", handlers.HealthCheck)

	// Kemono API proxy endpoints
	mux.HandleFunc("/api/kemono/creators", handlers.KemonoCreators)
	mux.HandleFunc("/api/kemono/proxy", handlers.KemonoProxy)
	mux.HandleFunc("/api/kemono/", handlers.KemonoPosts) // Catch-all for /api/kemono/{service}/...

	// Swagger documentation
	mux.Handle("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// Paperback extensions - serve static files from bundles folder
	fs := http.FileServer(http.Dir("paperback-extensions/bundles"))
	mux.Handle("/paperback/", http.StripPrefix("/paperback/", fs))

	log.Printf("Starting server on port %s", port)
	log.Printf("Swagger docs available at http://localhost:%s/swagger/", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
