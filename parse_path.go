package jwttokenhandler

import (
	"path/filepath"
	"runtime"
)

// Get an absolute path name from the caller stack when repository is getting from a remote project
// otherwise if use os.ReadFile that will returns path from a remote project that is false.
func AbsPath(fileName string) string {
	_, f, _, _ := runtime.Caller(0)
	basePath := filepath.Dir(f)
	return filepath.Join(basePath, fileName)
}
