//go:build windows

package daemonctl

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os/user"
	"strings"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// controlEndpoint is the per-user named pipe. Named pipes share one machine-wide
// namespace, so the current user is folded into the name to keep two users'
// daemons apart.
func controlEndpoint() (string, error) {
	name := "default"
	if u, err := user.Current(); err == nil && u.Username != "" {
		// "DOMAIN\\user" -> "user"; keep it a valid pipe path segment.
		un := u.Username
		if i := strings.LastIndexAny(un, `\/`); i >= 0 {
			un = un[i+1:]
		}
		name = sanitizePipeSegment(un)
	}
	return `\\.\pipe\share2us-daemon-` + name, nil
}

func sanitizePipeSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

// bindControl enforces single-instance with a named mutex (creating a pipe with
// the same name would just open another instance, not fail), then serves on the
// named pipe. release closes the mutex handle on Close.
func bindControl(pipe string) (net.Listener, func(), error) {
	h, err := acquireMutex(pipe)
	if err != nil {
		return nil, nil, err // ErrAlreadyRunning or a real failure
	}
	ln, err := winio.ListenPipe(pipe, &winio.PipeConfig{})
	if err != nil {
		windows.CloseHandle(h)
		return nil, nil, err
	}
	return ln, func() { windows.CloseHandle(h) }, nil
}

func dialControl(pipe string, timeout time.Duration) (net.Conn, error) {
	t := timeout
	return winio.DialPipe(pipe, &t)
}

// acquireMutex creates a per-user named mutex. If it already exists, another
// daemon is running (ErrAlreadyRunning). The mutex lives in the session-local
// namespace so it is scoped to this user's session, matching the pipe scope.
func acquireMutex(pipe string) (windows.Handle, error) {
	sum := sha256.Sum256([]byte(pipe))
	name := `Local\share2us-daemon-` + hex.EncodeToString(sum[:8])
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		// CreateMutex returns a valid handle AND ERROR_ALREADY_EXISTS when the
		// mutex is already held; that handle must be closed.
		if err == windows.ERROR_ALREADY_EXISTS {
			if h != 0 {
				windows.CloseHandle(h)
			}
			return 0, ErrAlreadyRunning
		}
		return 0, err
	}
	return h, nil
}
