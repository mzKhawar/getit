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
	service := NewService(pgStore)
	if err != nil {
		log.Fatalf("unable to connect to db: %v", err)
	}
	if err := pgStore.Init(ctx); err != nil {
		log.Fatal(err)
	}
	apiServer := NewApiServer(":8080", service)
	apiServer.Run()
}
