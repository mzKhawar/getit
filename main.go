package main

import (
	"context"
	"github.com/joho/godotenv"
	"log"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("unable to load env: %v", err)
	}
	ctx := context.Background()
	pgStore, err := NewPostgresStore(ctx)
	if err != nil {
		log.Fatalf("unable to connect to db: %v", err)
	}
	service := NewService(pgStore)
	if err := pgStore.Init(ctx); err != nil {
		log.Fatalf("unable to initialize db: %v", err)
	}
	apiServer := NewApiServer(":8080", service)
	apiServer.Run()
}
