// Package app wires the storage layer and services together. The CLI and
// the HTTP server both build on App so they share one implementation.
package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/enigma-137/ven/internal/environments"
	"github.com/enigma-137/ven/internal/projects"
	"github.com/enigma-137/ven/internal/storage"
	"github.com/enigma-137/ven/internal/variables"
	"github.com/enigma-137/ven/internal/vault"
)

// Version is set at build time with -ldflags "-X github.com/enigma-137/ven/internal/app.Version=...".
var Version = "0.1.0-dev"

// EnvVaultPath overrides the vault database location.
const EnvVaultPath = "VEN_VAULT"

// App bundles the services for one vault.
type App struct {
	DB           *storage.DB
	Vault        *vault.Service
	Projects     *projects.Service
	Environments *environments.Service
	Variables    *variables.Service
}

// Open opens the vault database at path and builds the services.
func Open(path string, opts ...vault.Option) (*App, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	p := projects.NewService(db)
	return &App{
		DB:           db,
		Vault:        vault.NewService(db, opts...),
		Projects:     p,
		Environments: environments.NewService(db, p),
		Variables:    variables.NewService(db),
	}, nil
}

// Close closes the database.
func (a *App) Close() error { return a.DB.Close() }

// DefaultDataDir returns the per-user application data directory:
//
//	Windows: %AppData%\VEN
//	macOS:   ~/Library/Application Support/VEN
//	Linux:   $XDG_DATA_HOME/ven or ~/.local/share/ven
func DefaultDataDir() (string, error) {
	switch runtime.GOOS {
	case "windows", "darwin", "ios":
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "VEN"), nil
	default:
		if x := os.Getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
			return filepath.Join(x, "ven"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "ven"), nil
	}
}

// ResolveVaultPath picks the vault path: explicit flag, then $VEN_VAULT,
// then the default data directory.
func ResolveVaultPath(flag string) (string, error) {
	if flag != "" {
		return filepath.Abs(flag)
	}
	if env := os.Getenv(EnvVaultPath); env != "" {
		return filepath.Abs(env)
	}
	dir, err := DefaultDataDir()
	if err != nil {
		return "", errors.New("cannot determine the user data directory; pass --vault")
	}
	return filepath.Join(dir, "vault.db"), nil
}

// Dashboard auto-lock setting.
const (
	settingAutoLock        = "dashboard.auto_lock_minutes"
	DefaultAutoLockMinutes = 15
	MinAutoLockMinutes     = 1
	MaxAutoLockMinutes     = 240
)

// AutoLockMinutes returns the dashboard inactivity timeout.
func (a *App) AutoLockMinutes(ctx context.Context) int {
	v, err := storage.GetSetting(ctx, a.DB, settingAutoLock)
	if err != nil {
		return DefaultAutoLockMinutes
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < MinAutoLockMinutes || n > MaxAutoLockMinutes {
		return DefaultAutoLockMinutes
	}
	return n
}

// SetAutoLockMinutes stores the dashboard inactivity timeout.
func (a *App) SetAutoLockMinutes(ctx context.Context, n int) error {
	if n < MinAutoLockMinutes || n > MaxAutoLockMinutes {
		return errors.New("auto-lock interval must be between 1 and 240 minutes")
	}
	return storage.SetSetting(ctx, a.DB, settingAutoLock, strconv.Itoa(n))
}
