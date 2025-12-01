package main

import (
	"log"
	"net/http"
	"os"

	"image-api/handlers"
)

func main() {
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
	mux.HandleFunc("/health", handlers.HealthCheck)

	// Paperback extensions - serve static files from bundles folder
	fs := http.FileServer(http.Dir("paperback-extensions/bundles"))
	mux.Handle("/paperback/", http.StripPrefix("/paperback/", fs))

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
