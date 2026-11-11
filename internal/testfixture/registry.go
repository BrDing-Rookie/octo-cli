// Package testfixture supplies synthetic OpenAPI specs to tests.
package testfixture

import (
	"embed"
	"io/fs"

	"github.com/Mininglamp-OSS/octo-cli/internal/registry"
)

//go:embed specs/*.json
var specs embed.FS

// Registry loads synthetic operations without changing the embedded production registry.
func Registry() *registry.Registry {
	source, err := fs.Sub(specs, "specs")
	if err != nil {
		panic(err)
	}
	reg, err := registry.Load(source)
	if err != nil {
		panic(err)
	}
	return reg
}
