package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	gokitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	gokitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/gorilla/sessions"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/jnikolaeva/eshop-common/httpkit"
	postgresadapter "github.com/jnikolaeva/eshop-common/postgres"

	"github.com/jnikolaeva/authservice/internal/auth/application"
	"github.com/jnikolaeva/authservice/internal/auth/infrastructure/postgres"
	usertransport "github.com/jnikolaeva/authservice/internal/auth/infrastructure/transport"
	"github.com/jnikolaeva/authservice/internal/probes"
)

const (
	appName     = "authservice"
	defaultPort = "8080"
)

func main() {
	serverAddr := ":" + envString("APP_PORT", defaultPort)

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime: "@timestamp",
			logrus.FieldKeyMsg:  "message",
		},
	})

	errorLogger := gokitlog.NewJSONLogger(gokitlog.NewSyncWriter(os.Stderr))
	errorLogger = level.NewFilter(errorLogger, level.AllowDebug())
	errorLogger = gokitlog.With(errorLogger,
		"appName", appName,
		"@timestamp", gokitlog.DefaultTimestampUTC,
	)

	connConfig, err := postgresadapter.ParseEnvConfig(appName)
	if err != nil {
		logger.Fatal(err.Error())
	}
	connectionPool, err := postgresadapter.NewConnectionPool(connConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer connectionPool.Close()

	sessionLifetime := envAsInt("SESSION_LIFETIME", 30)
	sessionCookieName := envString("SESSION_COOKIE", "sid")

	repository := postgres.New(connectionPool)
	identityService := application.NewIdentityService(repository)
	authService := application.NewAuthService(repository)

	sessionStorage := sessions.NewFilesystemStore("", []byte("something-very-secret"))
	sessionStorage.MaxAge(sessionLifetime)
	sessionStorage.Options.HttpOnly = true

	metrics := httpkit.NewMetricsHolder(gokitprometheus.NewCounterFrom(prometheus.CounterOpts{
		Namespace: "auth",
		Name:      "request_count",
		Help:      "Number of requests received.",
	}, []string{"method", "endpoint", "status_code"}),
		gokitprometheus.NewHistogramFrom(prometheus.HistogramOpts{
			Namespace: "auth",
			Name:      "request_latency_seconds",
			Help:      "Total duration of request in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "endpoint"}))

	apiServer := usertransport.NewHttpServer(errorLogger, identityService, authService, sessionStorage, sessionCookieName, metrics)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", apiServer.MakeHandler("/api/v1/auth"))
	mux.Handle("/ready", probes.MakeReadyHandler())
	mux.Handle("/live", probes.MakeLiveHandler())
	mux.Handle("/metrics", promhttp.Handler())

	srv := startServer(serverAddr, mux, logger)

	waitForShutdown(srv)
	logger.Info("shutting down")
}

func startServer(serverAddr string, handler http.Handler, logger *logrus.Logger) *http.Server {
	srv := &http.Server{Addr: serverAddr, Handler: handler}

	go func() {
		logger.WithFields(logrus.Fields{"url": serverAddr}).Info("starting the server")
		logger.Fatal(srv.ListenAndServe())
	}()

	return srv
}

func waitForShutdown(srv *http.Server) {
	killSignalChan := make(chan os.Signal, 1)
	signal.Notify(killSignalChan, os.Kill, os.Interrupt, syscall.SIGTERM)

	<-killSignalChan
	_ = srv.Shutdown(context.Background())
}

func envString(env, fallback string) string {
	e := os.Getenv(env)
	if e == "" {
		return fallback
	}
	return e
}

func envAsInt(env string, fallback int) int {
	v := envString(env, "")
	if value, err := strconv.Atoi(v); err == nil {
		return value
	}
	return fallback
}
