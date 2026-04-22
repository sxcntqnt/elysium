// cmd/server/main.go is the composition root for the auth service.
//
// Boot sequence:
//  1. Read Vault bootstrap credentials from environment — these are the only
//     values that cannot come from Vault (they unlock Vault).
//  2. Authenticate to Vault via AppRole; start background token renewal.
//  3. Pull all secrets and config from Vault KV v2.
//  4. Wire the Signer: TransitSigner when AUTH_USE_TRANSIT=true (production),
//     HMACSigner otherwise (dev / environments without the Transit engine).
//  5. Build repository, token manager, service, middleware, HTTP/gRPC handlers.
//  6. Start servers; block on OS signal.
//  7. Graceful shutdown in reverse dependency order.
//     Vault client is shut down last — all Vault API calls (Transit
//     sign/verify, future KV re-reads) must complete before renewal stops.
//
// Keygraph migration (when ready):
//   Replace: repo, conn, err := dgraph.New(cfg.Database.DgraphTarget)
//   With:    repo, conn, err := keygraph.New(cfg.Database.KeygraphTarget)
//   Nothing else changes — the service layer depends on repository.UserRepository.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sxcntqnt/auth-service/internal/config"
	grpchandler "sxcntqnt/auth-service/internal/handler/grpc"
	"sxcntqnt/auth-service/internal/handler/grpc/pb"
	httphandler "sxcntqnt/auth-service/internal/handler/http"
	"sxcntqnt/auth-service/internal/middleware"
	"sxcntqnt/auth-service/internal/repository/dgraph"
	"sxcntqnt/auth-service/internal/service"
	"sxcntqnt/auth-service/internal/token"
	"sxcntqnt/auth-service/internal/vault"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Bootstrap logger — used before Vault is available.
	// Replaced with the configured-level logger once config is loaded.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal startup error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// ── 1. Read Vault bootstrap credentials from the environment ─────────────
	vaultCfg := config.VaultConfigFromEnv()
	if vaultCfg.RoleID == "" || vaultCfg.SecretID == "" {
		return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID must be set")
	}

	// ── 2. Authenticate to Vault; start background token renewal ─────────────
	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer startCancel()

	vaultClient, err := vault.New(startCtx, vault.Config{
		Address:   vaultCfg.Address,
		RoleID:    vaultCfg.RoleID,
		SecretID:  vaultCfg.SecretID,
		Namespace: vaultCfg.Namespace,
	}, logger)
	if err != nil {
		return fmt.Errorf("authenticate to vault: %w", err)
	}
	// Vault token renewal goroutine is now running.
	// vaultClient.Shutdown() is called last in the shutdown sequence.

	// ── 3. Pull secrets and full config from Vault KV v2 ─────────────────────
	sm := vault.NewSecretManager(vaultClient, vaultCfg.KVMount, vaultCfg.KVPrefix)
	cfg, err := config.Load(startCtx, sm)
	if err != nil {
		vaultClient.Shutdown()
		return fmt.Errorf("load config from vault: %w", err)
	}

	// Re-build the logger now that we know the configured log level.
	logger = newLogger(cfg.Server.LogLevel)
	slog.SetDefault(logger)

	logger.Info("starting auth-service",
		slog.String("env", cfg.Server.Env),
		slog.String("http_addr", cfg.Server.HTTPAddr),
		slog.String("grpc_addr", cfg.Server.GRPCAddr),
		slog.Bool("transit_signing", cfg.Auth.UseTransit),
	)

	// ── 4. Wire the Signer ────────────────────────────────────────────────────
	//
	// vault.Signer is the only interface the token manager has on the vault
	// package. Swapping Transit for HMAC (or a future Keygraph signer) is a
	// single-line change here — no other layer is aware of the difference.
	var signer vault.Signer

	if cfg.Auth.UseTransit {
		signer = vault.NewTransitSigner(
			vaultClient,
			cfg.Auth.TransitMount,
			cfg.Auth.TransitKeyName,
			cfg.Auth.Issuer,
			cfg.Auth.AccessTokenTTL,
			cfg.Auth.RefreshTokenTTL,
		)
		logger.Info("vault transit signer active",
			slog.String("mount", cfg.Auth.TransitMount),
			slog.String("key", cfg.Auth.TransitKeyName),
		)
	} else {
		signer, err = vault.NewHMACSigner(
			cfg.Auth.SigningKey,
			cfg.Auth.Issuer,
			cfg.Auth.AccessTokenTTL,
			cfg.Auth.RefreshTokenTTL,
		)
		if err != nil {
			vaultClient.Shutdown()
			return fmt.Errorf("create hmac signer: %w", err)
		}
		logger.Info("hmac signer active (KV v2 key)")
	}

	// ── 5. Build the service graph ────────────────────────────────────────────

	// Repository — swap dgraph.New for keygraph.New here when migrating stores.
	repo, dgraphConn, err := dgraph.New(cfg.Database.DgraphTarget)
	if err != nil {
		vaultClient.Shutdown()
		return fmt.Errorf("connect to dgraph: %w", err)
	}
	defer dgraphConn.Close()

	if cfg.Database.DgraphApplySchema {
		schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := repo.ApplySchema(schemaCtx); err != nil {
			schemaCancel()
			vaultClient.Shutdown()
			return fmt.Errorf("apply dgraph schema: %w", err)
		}
		if err := repo.ApplyServiceAccountSchema(schemaCtx); err != nil {
			schemaCancel()
			vaultClient.Shutdown()
			return fmt.Errorf("apply dgraph service account schema: %w", err)
		}
		schemaCancel()
		logger.Info("dgraph schemas applied")
	}

	// Token manager receives the Signer — no key material stored here.
	tokenMgr := token.New(signer, cfg.Auth.Issuer, cfg.Auth.AccessTokenTTL)

	// Human user service.
	svc := service.New(repo, tokenMgr, cfg.Auth.BcryptCost, logger)

	// Service account repo wraps the same Dgraph connection without method collisions.
	saRepo := dgraph.NewServiceAccountRepo(repo)

	// Service account auth — shares token manager and bcrypt cost with the user service.
	svcAuth := service.NewServiceAuth(saRepo, tokenMgr, cfg.Auth.BcryptCost, logger)

	// ── 6. HTTP server ────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	httpH := httphandler.New(svc, svcAuth, repo, logger)
	httpH.RegisterRoutes(mux, middleware.Authenticate(svc))

	globalChain := middleware.Chain(
		middleware.SecurityHeaders(),
		middleware.RateLimiter(cfg.Server.RateLimitRPS, cfg.Server.RateLimitBurst),
		middleware.RequestLogger(logger),
	)

	httpServer := &http.Server{
		Addr:              cfg.Server.HTTPAddr,
		Handler:           globalChain(mux),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    1 << 13, // 8 KB
	}

	// ── 7. gRPC server ────────────────────────────────────────────────────────
	grpcH := grpchandler.New(svc, logger)

	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcLoggingInterceptor(logger),
			grpcRecoveryInterceptor(logger),
		),
		grpc.MaxRecvMsgSize(1<<20), // 1 MB
	)
	pb.RegisterAuthServiceServer(grpcSrv, grpcH)

	if cfg.Server.Env == "development" {
		reflection.Register(grpcSrv)
		logger.Info("grpc reflection enabled (development only)")
	}

	grpcLis, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		vaultClient.Shutdown()
		return fmt.Errorf("listen grpc: %w", err)
	}

	// ── 8. Start servers ──────────────────────────────────────────────────────
	// Buffered channel — the OS signal sender never blocks.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// serverErr collects fatal startup or runtime errors from both servers.
	serverErr := make(chan error, 2)

	// Each goroutine has a clear owner (main), a known exit (serverErr or
	// server close), and does not leak on shutdown.
	go func() {
		logger.Info("http server listening", slog.String("addr", cfg.Server.HTTPAddr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("http server: %w", err)
		}
	}()

	go func() {
		logger.Info("grpc server listening", slog.String("addr", cfg.Server.GRPCAddr))
		if err := grpcSrv.Serve(grpcLis); err != nil {
			serverErr <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	// Block until a signal arrives or a server fails.
	select {
	case err := <-serverErr:
		// A server failed at startup. Shut down everything.
		shutdownAll(context.Background(), httpServer, grpcSrv, vaultClient, cfg.Server.ShutdownTimeout, logger)
		return err
	case sig := <-quit:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	}

	// ── 9. Graceful shutdown — reverse dependency order ───────────────────────
	shutdownAll(context.Background(), httpServer, grpcSrv, vaultClient, cfg.Server.ShutdownTimeout, logger)
	logger.Info("auth service stopped cleanly")
	return nil
}

// shutdownAll stops servers and the Vault client in the correct order.
// HTTP and gRPC stop first (stop accepting new requests that might need Vault),
// then the Vault client stops last (all Vault calls must complete first).
func shutdownAll(
	parent context.Context,
	httpServer *http.Server,
	grpcSrv *grpc.Server,
	vaultClient *vault.Client,
	timeout time.Duration,
	logger *slog.Logger,
) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// Stop accepting new gRPC RPCs; wait for in-flight ones to complete.
	grpcDone := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(grpcDone)
	}()

	// Stop accepting new HTTP requests; wait for in-flight ones to complete.
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("http shutdown error", slog.String("error", err.Error()))
	}

	select {
	case <-grpcDone:
		logger.Info("grpc server stopped gracefully")
	case <-ctx.Done():
		logger.Warn("grpc graceful stop timed out; forcing stop")
		grpcSrv.Stop()
	}

	// Vault client last — renewal goroutine must outlive all API callers.
	vaultClient.Shutdown()
}

// ── gRPC interceptors ─────────────────────────────────────────────────────────

func grpcLoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		logger.InfoContext(ctx, "grpc call",
			slog.String("method", info.FullMethod),
			slog.Duration("duration", time.Since(start)),
			slog.Bool("error", err != nil),
		)
		return resp, err
	}
}

// grpcRecoveryInterceptor catches panics in RPC handlers and converts them
// to codes.Internal so a single handler panic doesn't crash the process.
func grpcRecoveryInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.ErrorContext(ctx, "grpc handler panic",
					slog.String("method", info.FullMethod),
					slog.Any("panic", r),
				)
				err = grpc.ErrServerStopped // surfaces as codes.Internal to the client
			}
		}()
		return handler(ctx, req)
	}
}

// newLogger builds a structured JSON logger at the requested level.
// Unknown levels fall back to Info.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
