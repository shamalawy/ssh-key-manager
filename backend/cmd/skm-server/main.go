// Command skm-server runs the SKM API, the job scheduler, and the embedded
// single-page application from one binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hamalawy/ssh-key-manager/backend/internal/api"
	"github.com/hamalawy/ssh-key-manager/backend/internal/audit"
	"github.com/hamalawy/ssh-key-manager/backend/internal/config"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors/execc"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors/git"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors/linux"
	"github.com/hamalawy/ssh-key-manager/backend/internal/connectors/netdev"
	"github.com/hamalawy/ssh-key-manager/backend/internal/consumers"
	"github.com/hamalawy/ssh-key-manager/backend/internal/db"
	"github.com/hamalawy/ssh-key-manager/backend/internal/events"
	"github.com/hamalawy/ssh-key-manager/backend/internal/jobs"
	"github.com/hamalawy/ssh-key-manager/backend/internal/service"
	"github.com/hamalawy/ssh-key-manager/backend/internal/store"
	"github.com/hamalawy/ssh-key-manager/backend/internal/vault"
	"github.com/hamalawy/ssh-key-manager/backend/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg)
	slog.SetDefault(log)

	log.Info("starting skm-server",
		"listen", cfg.ListenAddr,
		"dev_mode", cfg.DevMode,
		"scheduler", cfg.SchedulerEnabled)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Connect(ctx, db.Options{
		URL:          cfg.DatabaseURL,
		MaxConns:     cfg.DBMaxConns,
		MinConns:     cfg.DBMinConns,
		ConnLifetime: cfg.DBConnLifetime,
	})
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("connected to the database")

	if cfg.MigrateOnStart {
		if err := db.Migrate(ctx, pool, log); err != nil {
			return err
		}
	}

	// The vault starts sealed unless a master key was supplied. Sealed is a
	// usable state: the server serves, reports its status, and refuses key
	// operations until it is unsealed.
	v := vault.New()
	if len(cfg.MasterKey) > 0 {
		if err := v.Unseal(1, cfg.MasterKey); err != nil {
			return fmt.Errorf("unsealing vault: %w", err)
		}
		vault.Zero(cfg.MasterKey)
		log.Info("vault unsealed", "kek_version", v.CurrentVersion())
	} else {
		log.Warn("no master key supplied; the vault is sealed and key operations will be refused " +
			"(set SKM_MASTER_KEY or SKM_MASTER_KEY_FILE)")
	}

	registry := connectors.NewRegistry()
	registry.Register(linux.New())
	registry.Register(netdev.New())
	registry.Register(git.New())
	registry.Register(execc.New(cfg.ExecConnectorDirs))
	log.Info("registered connectors", "kinds", registry.Kinds())
	if len(cfg.ExecConnectorDirs) == 0 {
		log.Info("the exec connector is registered but disabled",
			"note", "set SKM_EXEC_DIRS to allow running operator-supplied connector scripts")
	}

	auditLog := audit.New(pool)
	keyStore := store.NewKeys(pool)
	userStore := store.NewUsers(pool)
	targetStore := store.NewTargets(pool)
	assignmentStore := store.NewAssignments(pool)
	snapshotStore := store.NewSnapshots(pool)
	changesetStore := store.NewChangesets(pool)
	credentialStore := store.NewCredentials(pool)
	jobStore := store.NewJobs(pool)
	rotationStore := store.NewRotations(pool)
	consumerStore := store.NewConsumers(pool)
	webhookStore := store.NewWebhooks(pool)
	backupStore := store.NewBackups(pool)
	discoveryStore := store.NewDiscovery(pool)
	tokenStore := store.NewTokens(pool)

	if err := userStore.EnsureSystemRoles(ctx, store.DefaultTenantID); err != nil {
		return err
	}

	// The event bus fans out to the browser over SSE; the dispatcher turns the
	// same events into signed webhook deliveries.
	bus := events.NewBus(log)
	dispatcher := events.NewDispatcher(webhookStore, v, log)
	publisher := events.NewPublisher(bus, log, dispatcher)

	keySvc := service.NewKeyService(keyStore, v, auditLog)
	authSvc := service.NewAuthService(pool, userStore, auditLog, cfg.SessionTTL)
	authSvc.SetTokens(tokenStore)
	userSvc := service.NewUserService(userStore, tokenStore, auditLog)
	deploySvc := service.NewDeployService(service.DeployServiceDeps{
		Targets: targetStore, Keys: keyStore, Assignments: assignmentStore,
		Snapshots: snapshotStore, Changesets: changesetStore, Credentials: credentialStore,
		Registry: registry, Vault: v, KeyService: keySvc, Audit: auditLog, Logger: log,
	})
	consumerSvc := service.NewConsumerService(consumerStore, keyStore, keySvc,
		consumers.NewRegistry(), auditLog, log).
		WithRemoteDelivery(targetStore, credentialStore, v)
	rotationSvc := service.NewRotationService(service.RotationDeps{
		Rotations: rotationStore, Keys: keyStore, Targets: targetStore,
		Assignments: assignmentStore, Changesets: changesetStore, Consumers: consumerStore,
		Users: userStore, Jobs: jobStore, KeyService: keySvc, Deploy: deploySvc,
		ConsumerSvc: consumerSvc, Audit: auditLog, Publisher: publisher, Logger: log,
	})
	reconcileSvc := service.NewReconcileService(targetStore, keyStore, assignmentStore,
		discoveryStore, deploySvc, keySvc, auditLog, publisher, log)
	backupSvc := service.NewBackupService(service.BackupDeps{
		Backups: backupStore, Keys: keyStore, Targets: targetStore,
		Assignments: assignmentStore, Consumers: consumerStore, Rotations: rotationStore,
		KeyService: keySvc, Vault: v, Audit: auditLog, Publisher: publisher,
		Logger: log, Directory: cfg.BackupDir,
	})

	// Attached after construction: the publisher's webhook sink needs the
	// vault, which these services already depend on.
	keySvc.SetPublisher(publisher)
	deploySvc.SetPublisher(publisher)
	// Deleting a key shreds its private half, so the service needs to see
	// where the key is still deployed in order to refuse.
	keySvc.SetAssignments(assignmentStore)

	worker := service.NewWorker(service.WorkerDeps{
		Jobs: jobStore, Rotations: rotationStore, Keys: keyStore, Targets: targetStore,
		Users: userStore, Rotation: rotationSvc, Deploy: deploySvc, Reconcile: reconcileSvc,
		Backup: backupSvc, Consumers: consumerSvc, Auth: authSvc,
		Dispatcher: dispatcher, Publisher: publisher, Audit: auditLog, Logger: log,
		JobRetention: cfg.JobRetention, ExpiryWarning: cfg.ExpiryWarning,
		ReconcileEvery: cfg.ReconcileInterval,
	})

	if user, err := authSvc.Bootstrap(ctx, store.DefaultTenantID, cfg.BootstrapUser, cfg.BootstrapPass); err != nil {
		return fmt.Errorf("bootstrapping the first administrator: %w", err)
	} else if user != nil {
		log.Info("created the initial administrator", "username", user.Username,
			"note", "this account must change its password on first sign-in")
	}

	// Workers run in every instance; only the leader runs the scheduler, so
	// scaling out multiplies throughput without multiplying scheduled work.
	runner := jobs.NewRunner(jobStore, jobs.Options{
		Workers:      cfg.WorkerConcurrency,
		PollInterval: cfg.JobPollInterval,
		JobTimeout:   30 * time.Minute,
		LeaseTTL:     5 * time.Minute,
		BaseBackoff:  10 * time.Second,
		MaxBackoff:   30 * time.Minute,
	}, log)
	worker.RegisterHandlers(runner)
	runner.Start(ctx)
	defer runner.Stop()

	var scheduler *jobs.Scheduler
	if cfg.SchedulerEnabled {
		scheduler = jobs.NewScheduler(pool, 15*time.Second, log)
		worker.RegisterTasks(scheduler)
		go scheduler.Run(ctx)
	} else {
		log.Warn("the scheduler is disabled; rotation policies and drift sweeps will not run " +
			"(set SKM_SCHEDULER_ENABLED=true to enable them)")
	}

	srv := &api.Server{
		Auth: authSvc, Keys: keySvc, Deploy: deploySvc, Rotation: rotationSvc,
		Reconcile: reconcileSvc, Backup: backupSvc, Consumers: consumerSvc, Worker: worker,
		UserAdmin: userSvc, Tokens: tokenStore,
		Targets: targetStore, Assignments: assignmentStore, Credentials: credentialStore,
		Snapshots: snapshotStore, Users: userStore, Rotations: rotationStore,
		Jobs: jobStore, Webhooks: webhookStore, Backups: backupStore,
		Discovery: discoveryStore, Audit: auditLog, Vault: v, Registry: registry,
		Events: publisher, Scheduler: scheduler, Log: log, Issuer: "SKM",
	}

	if handler, err := staticHandler(log); err != nil {
		log.Warn("the web interface is not embedded in this build", "reason", err)
	} else {
		srv.StaticFS = handler
		log.Info("serving the embedded web interface")
	}

	httpSrv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.Handler(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "tls", cfg.TLSCertFile != "")

		var err error
		if cfg.TLSCertFile != "" {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	// Drain in-flight requests before exiting, so a deployment in progress is
	// not cut off mid-write.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}

	// Sealing on the way out clears key material from memory.
	v.Seal()
	log.Info("stopped")
	return nil
}

// staticHandler serves the embedded SPA build, when one was compiled in.
func staticHandler(log *slog.Logger) (http.Handler, error) {
	dist, err := web.Dist()
	if err != nil {
		return nil, err
	}
	return spaFileServer(dist), nil
}

// spaFileServer serves static files, falling back to index.html so client-side
// routes survive a reload.
func spaFileServer(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}

		if _, err := fs.Stat(dist, path[1:]); err != nil {
			// Not a real file: hand the request to the SPA's router.
			index, err := fs.ReadFile(dist, "index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(index)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}

	if cfg.LogFormat == "text" || cfg.DevMode {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
