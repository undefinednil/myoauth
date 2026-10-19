package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/undefinednil/myoauth/dal"
	"github.com/undefinednil/myoauth/handler"
	"github.com/undefinednil/myoauth/service"
	"github.com/undefinednil/myoauth/token"
	"github.com/undefinednil/myoauth/util"
)

// shutdownTimeout bounds how long an in-flight graceful shutdown may take
// before it is reported as failed.
const shutdownTimeout = 10 * time.Second

func main() {
	// graceful exit
	var cleanUpErr error
	exitedCleanly := false
	defer func() {
		if cleanUpErr != nil {
			panic(cleanUpErr)
		}
		if exitedCleanly {
			log.Println("gracefully exited")
		}
	}()

	// Configuration comes exclusively from the MYOAUTH_* environment variables
	// (typically loaded from .env); there is no config-file flag or argument.
	conf := new(util.Configuration)
	if err := conf.Init(); err != nil {
		panic(err)
	}

	logger := new(util.Logger)
	if err := logger.Init(conf); err != nil {
		panic(err)
	}
	defer func() {
		log.Println("exiting")
		if err := logger.Close(); err != nil {
			cleanUpErr = errors.Join(cleanUpErr, err)
		}
	}()

	db := new(dal.Database)
	if err := db.Init(context.Background(), conf); err != nil {
		panic(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			cleanUpErr = errors.Join(cleanUpErr, err)
		}
	}()

	authCodeStore := util.NewAuthorizationCodeStore(conf)
	tk := new(token.Token)
	if err := tk.Init(conf, logger); err != nil {
		panic(err)
	}
	denylist := util.NewDenylist()
	rateLimiter := util.NewRateLimiter(conf.RateLimitRequestsPerMinute, conf.RateLimitBurst, conf.RateLimitMaxKeys)
	service := new(service.Service)
	service.Init(conf, db)

	hd := new(handler.Handler)
	hd.Init(conf, logger, db, service, authCodeStore, tk, denylist, rateLimiter)
	if err := hd.EnsureForwardAuthClient(); err != nil {
		panic(err)
	}

	// Start serving before signal handling is registered so a signal can never
	// reach Shutdown ahead of the server itself. The serving goroutine reports
	// its outcome on serverErrChan.
	serverErrChan := make(chan error, 1)
	go func() {
		serverErrChan <- hd.ListenAndServe()
	}()

	osSignalChan := make(chan os.Signal, 2)
	signal.Notify(osSignalChan, os.Interrupt, syscall.SIGTERM)

	log.Println("started")

	select {
	case err := <-serverErrChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped with error: %v\n", err)
			os.Exit(1)
		}
	case <-osSignalChan:
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		shutdownDone := make(chan error, 1)
		go func() { shutdownDone <- shutdownServer(hd, ctx) }()
		// A second signal while draining forces an immediate exit; otherwise
		// wait for the graceful shutdown to finish.
		select {
		case err := <-shutdownDone:
			cancel()
			if err != nil {
				log.Printf("graceful shutdown failed: %v\n", err)
				os.Exit(1)
			}
		case <-osSignalChan:
			cancel()
			log.Println("second signal received, forcing exit")
			os.Exit(1)
		}
		if err := <-serverErrChan; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server stopped with error: %v\n", err)
			os.Exit(1)
		}
	}
	exitedCleanly = true
}

// shutdownServer shuts the HTTP server down, converting a panic into an error.
// The guard makes it impossible for a signal that races ahead of
// ListenAndServe's server construction to nil-dereference inside
// handler.Shutdown and crash the process from a goroutine.
func shutdownServer(hd *handler.Handler, ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("shutdown panicked: %v", r)
		}
	}()
	return hd.Shutdown(ctx)
}
