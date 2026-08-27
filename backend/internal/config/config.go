// Package config loads runtime configuration from environment variables.
//
// Every secret-bearing setting supports a "_FILE" companion variable holding a
// path to read the value from, so secrets can be delivered as Docker/Kubernetes
// secrets instead of appearing in the process environment.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Server
	ListenAddr   string
	PublicURL    string
	TLSCertFile  string
	TLSKeyFile   string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Database
	DatabaseURL    string
	DBMaxConns     int32
	DBMinConns     int32
	DBConnLifetime time.Duration
	MigrateOnStart bool

	// Vault
	MasterKey    []byte // raw 32 bytes; empty means the server boots sealed
	KeyRetention time.Duration
	SealOnStart  bool

	// Auth
	SessionTTL    time.Duration
	RefreshTTL    time.Duration
	JWTSecret     []byte
	BootstrapUser string
	BootstrapPass string
	Argon2Time    uint32
	Argon2Memory  uint32
	Argon2Threads uint8

	// Workers / scheduler
	WorkerConcurrency int
	SchedulerEnabled  bool

	// BackupDir is where encrypted vault exports are written.
	BackupDir string
	// ExecConnectorDirs allow-lists the directories the exec connector may run
	// scripts from. Empty disables the connector, which is the right default:
	// those scripts run with the server's privileges.
	ExecConnectorDirs []string
	// ReconcileInterval paces the fleet-wide drift sweep.
	ReconcileInterval time.Duration
	// ExpiryWarning is how far ahead an approaching key expiry is announced.
	ExpiryWarning time.Duration
	// JobRetention bounds how long finished jobs are kept for inspection.
	JobRetention    time.Duration
	JobPollInterval time.Duration

	// Observability
	LogLevel  slog.Level
	LogFormat string // "json" or "text"

	// Behaviour
	DefaultSoakPeriod time.Duration
	DevMode           bool
}

// Load resolves configuration from the environment, applying defaults and
// validating anything that would fail later at an inconvenient moment.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:        env("SKM_LISTEN_ADDR", ":8080"),
		PublicURL:         env("SKM_PUBLIC_URL", "http://localhost:8080"),
		TLSCertFile:       env("SKM_TLS_CERT_FILE", ""),
		TLSKeyFile:        env("SKM_TLS_KEY_FILE", ""),
		ReadTimeout:       envDuration("SKM_READ_TIMEOUT", 30*time.Second),
		WriteTimeout:      envDuration("SKM_WRITE_TIMEOUT", 60*time.Second),
		IdleTimeout:       envDuration("SKM_IDLE_TIMEOUT", 120*time.Second),
		DBMaxConns:        int32(envInt("SKM_DB_MAX_CONNS", 20)),
		DBMinConns:        int32(envInt("SKM_DB_MIN_CONNS", 2)),
		DBConnLifetime:    envDuration("SKM_DB_CONN_LIFETIME", time.Hour),
		MigrateOnStart:    envBool("SKM_MIGRATE_ON_START", true),
		KeyRetention:      envDuration("SKM_KEY_RETENTION", 90*24*time.Hour),
		SealOnStart:       envBool("SKM_SEAL_ON_START", false),
		SessionTTL:        envDuration("SKM_SESSION_TTL", 12*time.Hour),
		RefreshTTL:        envDuration("SKM_REFRESH_TTL", 30*24*time.Hour),
		BootstrapUser:     env("SKM_BOOTSTRAP_USER", ""),
		Argon2Time:        uint32(envInt("SKM_ARGON2_TIME", 3)),
		Argon2Memory:      uint32(envInt("SKM_ARGON2_MEMORY_KIB", 64*1024)),
		Argon2Threads:     uint8(envInt("SKM_ARGON2_THREADS", 4)),
		WorkerConcurrency: envInt("SKM_WORKER_CONCURRENCY", 10),
		SchedulerEnabled:  envBool("SKM_SCHEDULER_ENABLED", true),
		JobPollInterval:   envDuration("SKM_JOB_POLL_INTERVAL", 2*time.Second),
		LogFormat:         env("SKM_LOG_FORMAT", "json"),
		DefaultSoakPeriod: envDuration("SKM_DEFAULT_SOAK_PERIOD", 24*time.Hour),
		DevMode:           envBool("SKM_DEV_MODE", false),
		BackupDir:         env("SKM_BACKUP_DIR", "/var/lib/skm/backups"),
		ExecConnectorDirs: envList("SKM_EXEC_DIRS"),
		ReconcileInterval: envDuration("SKM_RECONCILE_INTERVAL", time.Hour),
		ExpiryWarning:     envDuration("SKM_EXPIRY_WARNING", 14*24*time.Hour),
		JobRetention:      envDuration("SKM_JOB_RETENTION", 14*24*time.Hour),
	}

	var err error

	if c.DatabaseURL, err = secret("SKM_DATABASE_URL", ""); err != nil {
		return nil, err
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: SKM_DATABASE_URL (or SKM_DATABASE_URL_FILE) is required")
	}

	rawMaster, err := secret("SKM_MASTER_KEY", "")
	if err != nil {
		return nil, err
	}
	if rawMaster != "" {
		c.MasterKey, err = decodeMasterKey(rawMaster)
		if err != nil {
			return nil, err
		}
	}

	rawJWT, err := secret("SKM_JWT_SECRET", "")
	if err != nil {
		return nil, err
	}
	c.JWTSecret = []byte(rawJWT)

	if c.BootstrapPass, err = secret("SKM_BOOTSTRAP_PASSWORD", ""); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("SKM_LOG_LEVEL", "info")); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func (c *Config) validate() error {
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return fmt.Errorf("config: SKM_TLS_CERT_FILE and SKM_TLS_KEY_FILE must be set together")
	}
	if c.DBMinConns > c.DBMaxConns {
		return fmt.Errorf("config: SKM_DB_MIN_CONNS (%d) exceeds SKM_DB_MAX_CONNS (%d)", c.DBMinConns, c.DBMaxConns)
	}
	if c.WorkerConcurrency < 1 {
		return fmt.Errorf("config: SKM_WORKER_CONCURRENCY must be at least 1")
	}
	if c.Argon2Threads < 1 {
		return fmt.Errorf("config: SKM_ARGON2_THREADS must be at least 1")
	}
	if c.Argon2Memory < 8*1024 {
		return fmt.Errorf("config: SKM_ARGON2_MEMORY_KIB must be at least 8192")
	}
	if (c.BootstrapUser == "") != (c.BootstrapPass == "") {
		return fmt.Errorf("config: SKM_BOOTSTRAP_USER and SKM_BOOTSTRAP_PASSWORD must be set together")
	}
	return nil
}

// Sealed reports whether the vault lacks a master key and must be unsealed
// through the API before key material can be read or written.
func (c *Config) Sealed() bool { return len(c.MasterKey) == 0 || c.SealOnStart }

// secret resolves NAME, preferring the contents of the file named by NAME_FILE.
// Trailing newlines are trimmed, which is what every secret-mounting system
// leaves behind.
func secret(name, def string) (string, error) {
	if path := os.Getenv(name + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("config: reading %s_FILE (%s): %w", name, path, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return env(name, def), nil
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(name string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("config: unknown SKM_LOG_LEVEL %q", s)
	}
}

// envList reads a colon-separated list, the same shape as PATH, so an operator
// configuring directories does not have to learn a second convention.
func envList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(raw, ":") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
