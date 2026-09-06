package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/cloudflarebridge"
	"github.com/Wei-Shaw/sub2api/internal/repository"
)

func runCloudflareServer() {
	runtimeConfig, err := cloudflarebridge.LoadRuntimeConfigFromEnv()
	if err != nil {
		log.Fatalf("Invalid Cloudflare runtime configuration: %v", err)
	}
	control, err := cloudflarebridge.NewHTTPControlPlane(runtimeConfig.ControlPlaneURL, nil)
	if err != nil {
		log.Fatalf("Failed to create Cloudflare control plane client: %v", err)
	}
	upstream := repository.NewHTTPUpstream(runtimeConfig.Application)
	handler, err := cloudflarebridge.NewHandler(runtimeConfig, control, upstream)
	if err != nil {
		log.Fatalf("Failed to initialize Cloudflare server: %v", err)
	}

	server := &http.Server{
		Addr:              runtimeConfig.Address,
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(runtimeConfig.Application.Server.ReadHeaderTimeout) * time.Second,
		IdleTimeout:       time.Duration(runtimeConfig.Application.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes:    runtimeConfig.Application.Server.MaxHeaderBytes,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Cloudflare server failed: %v", err)
		}
	}()
	log.Printf("Cloudflare Container server started on %s", server.Addr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Cloudflare server forced to shut down: %v", err)
	}
}
