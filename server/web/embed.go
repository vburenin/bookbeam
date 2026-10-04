// Package web holds the embedded single-page app served by BookBeam.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:public
var embedded embed.FS

// Public returns the static web root (index.html, sw.js, assets/...).
func Public() fs.FS {
	sub, err := fs.Sub(embedded, "public")
	if err != nil {
		panic(err)
	}
	return sub
}
