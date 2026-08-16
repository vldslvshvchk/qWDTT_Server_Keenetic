//go:build !linux

package qwdtt

import (
	"fmt"
	"os"
)

func createRawTUN(name string) (*os.File, error) {
	return nil, fmt.Errorf("raw TUN is supported only on Linux (requested %s)", name)
}
