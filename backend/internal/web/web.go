// Package web embeds the built single-page application into the server binary.
//
// The directory is committed with a placeholder so the package always compiles;
// `make build` overwrites it with the real Angular build before compiling, and
// Dist reports a clear error when only the placeholder is present.
package web

import (
	"embed"
	"errors"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// ErrNotBuilt means the frontend has not been compiled into this binary.
var ErrNotBuilt = errors.New("web: no frontend build is embedded (run `make frontend` before `make build`)")

// Dist returns the embedded build rooted at its top level.
func Dist() (fs.FS, error) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, ErrNotBuilt
	}
	return sub, nil
}
