package lanshare

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultPort is the first port a receiver tries when none is pinned.
	DefaultPort = 4300
	// portRangeEnd is the last port in the auto-bind range (inclusive).
	portRangeEnd = 4600
	// maxTransferBytes is an absolute ceiling on a single transfer, independent
	// of the size the sender declares. A hostile peer cannot fill the receiver's
	// disk by declaring a tiny size and streaming forever (the stream is held to
	// the declared size, see receiveToFile) nor by declaring an absurd one.
	maxTransferBytes int64 = 1 << 40 // 1 TiB
)

// Auth modes reported in ListenInfo.Mode.
const (
	ModePassword = "password"
	ModeAllowIP  = "allow-ip"
	ModeOpen     = "open"
)

// ReceiveOptions configures a single inbound transfer.
type ReceiveOptions struct {
	// Bind is the interface address to listen on ("" = all interfaces).
	Bind string
	// Port pins the listen port. 0 = auto-scan DefaultPort..portRangeEnd. A
	// pinned port that is unavailable is a hard error (no fallback).
	Port int
	// Password sets an explicit receive password (PAKE). Empty + !NoPassword +
	// no AllowIPs => a passphrase is auto-generated.
	Password string
	// NoPassword opens the receiver with no password (caller should warn).
	NoPassword bool
	// AllowIPs restricts accepted source IPs. With AllowIPs and no password, the
	// mode is allow-ip (network-identity auth).
	AllowIPs []string
	// TrustedIPs are source IPs whose inbound transfers are auto-accepted even
	// when a password is set for everyone else (trust-by-IP; caller warns).
	TrustedIPs []string
	// DestDir is where files land (default ~/s2u, created if missing).
	DestDir string
	// Overwrite permits replacing an existing destination file.
	Overwrite bool
	// HandshakeTimeout bounds per-connection setup (default 30s).
	HandshakeTimeout time.Duration
	// OnListen fires once the listener is up, before accepting.
	OnListen func(ListenInfo)
	// OnProgress fires as bytes arrive.
	OnProgress func(received, total int64)
}

// ListenInfo describes a live receiver.
type ListenInfo struct {
	BindAddr    string
	Port        int
	Fingerprint string // self-signed cert SHA-256 (for QR / pairing)
	Passphrase  string // effective password in password mode; "" otherwise
	Mode        string // ModePassword | ModeAllowIP | ModeOpen
}

// ReceiveResult reports a completed transfer.
type ReceiveResult struct {
	Name   string
	Path   string
	Bytes  int64
	SHA256 string
	PeerIP string
}

// Receive opens a listener, accepts connections until one completes a full
// authenticated transfer, writes the file atomically into DestDir, and returns.
// Connections that fail allow-ip, TLS, auth, or local checks are closed and the
// listener keeps waiting (so junk/probe connections cannot abort a receive).
func Receive(ctx context.Context, opts ReceiveOptions) (ReceiveResult, error) {
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	destDir, err := resolveDestDir(opts.DestDir)
	if err != nil {
		return ReceiveResult{}, err
	}
	opts.DestDir = destDir

	// Effective auth mode.
	password := opts.Password
	if password == "" && !opts.NoPassword && len(opts.AllowIPs) == 0 {
		gen, gerr := GeneratePassphrase(DefaultPassphraseWords)
		if gerr != nil {
			return ReceiveResult{}, gerr
		}
		password = gen
	}
	mode := ModeOpen
	switch {
	case password != "":
		mode = ModePassword
	case len(opts.AllowIPs) > 0:
		mode = ModeAllowIP
	}

	allow, err := parseAllowIPs(opts.AllowIPs)
	if err != nil {
		return ReceiveResult{}, err
	}
	trusted, err := parseAllowIPs(opts.TrustedIPs)
	if err != nil {
		return ReceiveResult{}, err
	}

	cert, fingerprint, err := generateEphemeralCert()
	if err != nil {
		return ReceiveResult{}, err
	}

	ln, port, err := listen(opts.Bind, opts.Port)
	if err != nil {
		return ReceiveResult{}, err
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLSConfig(cert))

	if opts.OnListen != nil {
		opts.OnListen(ListenInfo{
			BindAddr:    opts.Bind,
			Port:        port,
			Fingerprint: fingerprint,
			Passphrase:  password,
			Mode:        mode,
		})
	}

	// Close the listener when the context is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	throttle := newIPThrottle(10, 5*time.Second)
	for {
		conn, aerr := tlsLn.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return ReceiveResult{}, ctx.Err()
			}
			return ReceiveResult{}, fmt.Errorf("lanshare: accept: %w", aerr)
		}
		// Cheap per-IP flood guard before any TLS/crypto work.
		if !throttle.allow(remoteIP(conn)) {
			_ = conn.Close()
			continue
		}
		res, done, herr := handleConn(ctx, conn, opts, password, allow, trusted)
		if done {
			return res, herr
		}
		// Non-fatal (bad peer): keep listening.
	}
}

// ipThrottle bounds connection attempts per source IP over a sliding window, so
// a single flooding peer cannot pin the open receive port doing crypto work.
type ipThrottle struct {
	mu     sync.Mutex
	seen   map[string][]time.Time
	max    int
	window time.Duration
}

func newIPThrottle(max int, window time.Duration) *ipThrottle {
	return &ipThrottle{seen: make(map[string][]time.Time), max: max, window: window}
}

func (t *ipThrottle) allow(ip string) bool {
	if ip == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	// Opportunistically prune the whole map to bound memory.
	if len(t.seen) > 1024 {
		for k, ts := range t.seen {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > t.window {
				delete(t.seen, k)
			}
		}
	}
	kept := t.seen[ip][:0]
	for _, ts := range t.seen[ip] {
		if now.Sub(ts) < t.window {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= t.max {
		t.seen[ip] = kept
		return false
	}
	t.seen[ip] = append(kept, now)
	return true
}

// handleConn processes a single inbound connection. done=true means this
// connection produced a terminal result (success, or a hard local error like an
// overwrite refusal) and Receive should return; done=false means the peer was
// rejected and the listener should keep waiting.
func handleConn(ctx context.Context, conn net.Conn, opts ReceiveOptions, password string, allow, trusted []net.IP) (ReceiveResult, bool, error) {
	closeConn := true
	defer func() {
		if closeConn {
			_ = conn.Close()
		}
	}()

	peerIP := remoteIP(conn)
	if len(allow) > 0 && !ipAllowed(peerIP, allow) {
		return ReceiveResult{}, false, nil // silently drop disallowed sources
	}
	trustedPeer := len(trusted) > 0 && ipAllowed(peerIP, trusted)

	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return ReceiveResult{}, false, nil
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return ReceiveResult{}, false, nil
	}

	var h hello
	if err := readControl(conn, msgHello, &h); err != nil {
		return ReceiveResult{}, false, nil
	}
	if h.Version != protocolVersion {
		sendError(conn, "unsupported protocol version")
		return ReceiveResult{}, false, nil
	}
	if h.Size < 0 || h.Size > maxTransferBytes {
		sendError(conn, "declared transfer size is out of range")
		return ReceiveResult{}, false, nil
	}

	// Authenticate. The PAKE runs iff the SENDER offered a password (keeps both
	// sides in lockstep). Authorization: a password sender must pass the PAKE; a
	// no-password sender is accepted only when the receiver has no password OR the
	// peer IP is trusted.
	if h.HasPassword {
		if password == "" {
			sendError(conn, "this receiver is not expecting a password")
			return ReceiveResult{}, false, nil
		}
		ekm, err := exportKeyingMaterial(tlsConn)
		if err != nil {
			sendError(conn, "channel binding failed")
			return ReceiveResult{}, false, nil
		}
		if err := pakeReceiver(conn, ekm, []byte(password)); err != nil {
			sendError(conn, "authentication failed")
			return ReceiveResult{}, false, nil // wrong password: keep waiting
		}
	} else if password != "" && !trustedPeer {
		sendError(conn, "this receiver requires a password (--password)")
		return ReceiveResult{}, false, nil
	}

	// Resolve + guard the destination path.
	outPath, err := destPath(opts.DestDir, h.Name)
	if err != nil {
		sendError(conn, err.Error())
		return ReceiveResult{}, false, nil
	}
	if _, statErr := os.Stat(outPath); statErr == nil && !opts.Overwrite {
		reason := fmt.Sprintf("%q already exists; re-run the receiver with --overwrite", filepath.Base(outPath))
		_ = writeJSON(conn, msgAccept, accept{OK: false, Reason: reason})
		return ReceiveResult{}, true, errors.New("lanshare: " + reason)
	}

	if err := writeJSON(conn, msgAccept, accept{OK: true}); err != nil {
		return ReceiveResult{}, false, nil
	}

	// Receive the stream into a temp file in the destination dir, then rename.
	_ = conn.SetDeadline(time.Time{})
	written, sum, rerr := receiveToFile(ctx, conn, outPath, h.Size, opts.Overwrite, opts.OnProgress)
	if rerr != nil {
		sendError(conn, "write failed")
		return ReceiveResult{}, true, rerr
	}
	_ = writeJSON(conn, msgDone, done{OK: true, Bytes: written, SHA256: sum})

	return ReceiveResult{
		Name:   filepath.Base(outPath),
		Path:   outPath,
		Bytes:  written,
		SHA256: sum,
		PeerIP: peerIP,
	}, true, nil
}

// receiveToFile reads msgData frames until msgEOF, hashing, writing atomically.
func receiveToFile(ctx context.Context, conn net.Conn, outPath string, total int64, overwrite bool, onProgress func(received, total int64)) (int64, string, error) {
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, ".s2u-partial-*")
	if err != nil {
		return 0, "", fmt.Errorf("lanshare: temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return 0, "", err
	}

	digest := sha256.New()
	var received int64
	for {
		select {
		case <-ctx.Done():
			return 0, "", ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		typ, payload, ferr := readFrame(conn, maxDataFrame)
		if ferr != nil {
			return 0, "", fmt.Errorf("lanshare: read stream: %w", ferr)
		}
		switch typ {
		case msgData:
			// Hold the stream to the size the sender declared, so a peer cannot
			// declare a tiny size and stream forever to fill the disk.
			received += int64(len(payload))
			if received > total {
				return 0, "", fmt.Errorf("lanshare: sender exceeded declared size (%d > %d bytes)", received, total)
			}
			if _, werr := tmp.Write(payload); werr != nil {
				return 0, "", werr
			}
			_, _ = digest.Write(payload)
			if onProgress != nil {
				onProgress(received, total)
			}
		case msgEOF:
			if received != total {
				return 0, "", fmt.Errorf("lanshare: incomplete transfer: got %d of %d bytes", received, total)
			}
			if err := tmp.Sync(); err != nil {
				return 0, "", err
			}
			if err := tmp.Close(); err != nil {
				return 0, "", err
			}
			if err := placeFile(tmpName, outPath, overwrite); err != nil {
				return 0, "", err
			}
			cleanup = false
			return received, hex.EncodeToString(digest.Sum(nil)), nil
		default:
			return 0, "", fmt.Errorf("lanshare: unexpected frame type %d during transfer", typ)
		}
	}
}

// placeFile moves the staged temp file to outPath. Without overwrite it uses a
// hard link, which fails atomically if outPath already exists — closing the race
// between handleConn's earlier existence check and here, so a file that appears
// mid-transfer can no longer be silently clobbered. With overwrite it renames
// (replacing the name; os.Rename does not write through a symlink at the target).
func placeFile(tmpName, outPath string, overwrite bool) error {
	if overwrite {
		if err := os.Rename(tmpName, outPath); err != nil {
			return fmt.Errorf("lanshare: finalize %s: %w", outPath, err)
		}
		return nil
	}
	if err := os.Link(tmpName, outPath); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("lanshare: %q already exists; re-run the receiver with --overwrite", filepath.Base(outPath))
		}
		return fmt.Errorf("lanshare: finalize %s: %w", outPath, err)
	}
	_ = os.Remove(tmpName)
	return nil
}

// listen binds either the pinned port (hard error if taken) or the first free
// port in [DefaultPort, portRangeEnd].
func listen(bind string, port int) (net.Listener, int, error) {
	if port != 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
		if err != nil {
			return nil, 0, fmt.Errorf("lanshare: port %d unavailable: %w", port, err)
		}
		return ln, boundPort(ln), nil
	}
	var lastErr error
	for p := DefaultPort; p <= portRangeEnd; p++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(p)))
		if err == nil {
			return ln, boundPort(ln), nil
		}
		lastErr = err
	}
	return nil, 0, fmt.Errorf("lanshare: no free port in %d-%d: %w", DefaultPort, portRangeEnd, lastErr)
}

func boundPort(ln net.Listener) int {
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

// resolveDestDir returns the download dir (default ~/s2u), creating it 0700.
func resolveDestDir(dir string) (string, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("lanshare: resolve home: %w", err)
		}
		dir = filepath.Join(home, "s2u")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("lanshare: create %s: %w", dir, err)
	}
	return dir, nil
}

// destPath joins a sanitized base name onto the destination dir, refusing names
// that would escape it.
func destPath(dir, name string) (string, error) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) {
		return "", errors.New("received an invalid file name")
	}
	out := filepath.Join(dir, base)
	if filepath.Dir(out) != filepath.Clean(dir) {
		return "", errors.New("received file name escapes the destination directory")
	}
	return out, nil
}

func parseAllowIPs(list []string) ([]net.IP, error) {
	var out []net.IP
	for _, raw := range list {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("lanshare: invalid --allow-ip value %q", raw)
		}
		out = append(out, ip)
	}
	return out, nil
}

func ipAllowed(ipStr string, allow []net.IP) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, a := range allow {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}
