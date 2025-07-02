package local

import (
	"io"
	"os"
	"path/filepath"
)

func MasterKeyFromPath(path string) (io.Reader, error) {
	masterKeyFile, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = masterKeyFile.Close()
		if err != nil {
			logger.Warnf("failed to close master key file: %v", err)
		}
	}()
}
