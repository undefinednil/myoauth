package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zenpk/my-oauth/dal"
	"github.com/zenpk/my-oauth/handler"
	"github.com/zenpk/my-oauth/service"
	"github.com/zenpk/my-oauth/token"
	"github.com/zenpk/my-oauth/util"
)

func main() {
	confPath := flag.String("conf", "", "path to the configuration file (default ./conf.json)")
	flag.Parse()
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

	if strings.TrimSpace(*confPath) == "" {
		*confPath = strings.TrimSpace(os.Getenv("MYOAUTH_CONF"))
	}
	if strings.TrimSpace(*confPath) == "" {
		*confPath = "./conf.json"
	}

	conf := new(util.Configuration)
	if err := conf.Init(*confPath); err != nil {
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
	if err := db.Init(conf); err != nil {
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

	// clean up
	osSignalChan := make(chan os.Signal, 2)
	signal.Notify(osSignalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-osSignalChan
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := hd.Shutdown(ctx); err != nil {
			panic(err)
		}
	}()

	log.Println("started")
	if err := hd.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
	exitedCleanly = true
}
