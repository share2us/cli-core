package lanshare

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Access modes for a broadcast (who may pull the offered file).
const (
	AccessAll      = "all"      // anyone nearby can download
	AccessTrusted  = "trusted"  // only devices IsTrusted reports true for
	AccessApprove  = "approve"  // the broadcaster approves each download (OnRequest)
)

// BroadcastOptions configures serving one file for download ("pull"). The
// broadcaster advertises the file over mDNS and streams it to each downloader,
// gated by Access. Identity authenticates the broadcaster so downloaders can
// trust the source (and get the verify code); for trusted/approve access the
// downloader must authenticate too.
type BroadcastOptions struct {
	Path     string // file to serve
	Name     string // advertised name (defaults to filepath.Base(Path))
	Bind     string // listen interface ("" = all)
	Port     int    // 0 = auto-scan
	Instance string // mDNS instance (device) name

	Identity ed25519.PrivateKey // broadcaster identity (advertised + proven)
	Access   string             // AccessAll | AccessTrusted | AccessApprove

	// IsTrusted reports whether a downloader fingerprint is trusted (AccessTrusted).
	IsTrusted func(fingerprint string) bool
	// OnRequest approves a specific download (AccessApprove). RequestInfo carries
	// the downloader's verified key + name + the file name/size.
	OnRequest func(RequestInfo) bool
	// OnListen fires once the listener is up with the sender-facing details.
	OnListen func(ListenInfo)
	// OnConn reports per-connection progress/lifecycle for the live stats UI.
	OnConn func(ConnEvent)

	HandshakeTimeout time.Duration
}

// ConnEvent is a broadcast connection lifecycle/progress update.
type ConnEvent struct {
	PeerIP    string
	PeerKey   []byte // verified downloader identity ("" if anonymous)
	PeerName  string
	Sent      int64
	Total     int64
	Done      bool   // transfer completed
	Err       string // non-empty if the connection failed
}

// Broadcast opens a listener, advertises the file, and serves it to downloaders
// until ctx is cancelled. It reuses the same TLS + framing + identity plumbing as
// Send/Receive, in the pull direction.
func Broadcast(ctx context.Context, opts BroadcastOptions) error {
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	if opts.Name == "" {
		opts.Name = filepath.Base(opts.Path)
	}
	if opts.Access == "" {
		opts.Access = AccessApprove
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("lanshare: broadcast source is a directory (zip it first)")
	}
	size := info.Size()
	fullSHA, err := fileSHA(opts.Path)
	if err != nil {
		return err
	}

	cert, fingerprint, err := generateEphemeralCert()
	if err != nil {
		return err
	}
	ln, port, err := listen(opts.Bind, opts.Port)
	if err != nil {
		return err
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLSConfig(cert))

	li := ListenInfo{BindAddr: opts.Bind, Port: port, Fingerprint: fingerprint, Mode: ModeOpen}
	if opts.OnListen != nil {
		opts.OnListen(li)
	}

	go func() { <-ctx.Done(); _ = ln.Close() }()

	throttle := newIPThrottle(10, 5*time.Second)
	inflight := newInflightCap(2)
	sem := make(chan struct{}, 8)
	for {
		conn, aerr := tlsLn.Accept()
		if aerr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("lanshare: accept: %w", aerr)
		}
		ip := remoteIP(conn)
		if !throttle.allow(ip) || !inflight.acquire(ip) {
			_ = conn.Close()
			continue
		}
		sem <- struct{}{}
		go func(conn net.Conn, ip string) {
			defer func() { inflight.release(ip); <-sem }()
			handleDownload(ctx, conn, opts, size, fullSHA)
		}(conn, ip)
	}
}

// handleDownload serves the broadcast file to one downloader.
func handleDownload(ctx context.Context, conn net.Conn, opts BroadcastOptions, size int64, fullSHA string) {
	defer conn.Close()
	peerIP := remoteIP(conn)
	emit := func(ev ConnEvent) {
		if opts.OnConn != nil {
			ev.PeerIP, ev.Total = peerIP, size
			opts.OnConn(ev)
		}
	}

	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	ekm, err := exportKeyingMaterial(tlsConn)
	if err != nil {
		sendError(conn, "channel binding failed")
		return
	}

	var req downloadReq
	if err := readControl(conn, msgDownloadReq, &req); err != nil {
		return
	}

	// Verify the downloader's optional identity (bound to this TLS session).
	var peerKey []byte
	if len(req.IdentityPub) > 0 || len(req.IdentitySig) > 0 {
		if len(req.IdentityPub) != ed25519.PublicKeySize || len(req.IdentitySig) != ed25519.SignatureSize {
			sendError(conn, "malformed downloader identity")
			return
		}
		if !ed25519.Verify(ed25519.PublicKey(req.IdentityPub), identityMessage(ekm), req.IdentitySig) {
			sendError(conn, "downloader identity verification failed")
			return
		}
		peerKey = req.IdentityPub
	}
	fp := IdentityFingerprint(peerKey)

	// Access control.
	switch opts.Access {
	case AccessTrusted:
		if fp == "" || opts.IsTrusted == nil || !opts.IsTrusted(fp) {
			_ = writeJSON(conn, msgAccept, accept{OK: false, Reason: "this broadcast is limited to trusted devices"})
			return
		}
	case AccessApprove:
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
		if opts.OnRequest == nil || !opts.OnRequest(RequestInfo{PeerIP: peerIP, Name: opts.Name, Size: size, SenderKey: peerKey, SenderName: req.DownloaderName}) {
			_ = writeJSON(conn, msgAccept, accept{OK: false, Reason: "declined by the broadcaster"})
			return
		}
	}

	if req.Offset < 0 || req.Offset > size {
		sendError(conn, "invalid resume offset")
		return
	}

	f, err := os.Open(opts.Path)
	if err != nil {
		sendError(conn, "source unavailable")
		return
	}
	defer f.Close()
	if req.Offset > 0 {
		if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
			sendError(conn, "seek failed")
			return
		}
	}
	acc := accept{OK: true, Size: size}
	if len(opts.Identity) == ed25519.PrivateKeySize {
		if pub, ok := opts.Identity.Public().(ed25519.PublicKey); ok {
			acc.IdentityPub = pub
			acc.IdentitySig = ed25519.Sign(opts.Identity, identityMessage(ekm)) // prove the broadcaster's identity
		}
	}
	if err := writeJSON(conn, msgAccept, acc); err != nil {
		return
	}

	_ = conn.SetDeadline(time.Time{})
	emit(ConnEvent{PeerKey: peerKey, PeerName: req.DownloaderName, Sent: req.Offset})
	throwaway := sha256.New() // streamBody wants a digest; the real SHA is fullSHA
	if err := streamBody(ctx, tlsConn, f, size, throwaway, func(sent, total int64) {
		emit(ConnEvent{PeerKey: peerKey, PeerName: req.DownloaderName, Sent: req.Offset + sent})
	}); err != nil {
		emit(ConnEvent{PeerKey: peerKey, PeerName: req.DownloaderName, Err: err.Error()})
		return
	}
	_ = writeJSON(conn, msgDone, done{OK: true, Bytes: size, SHA256: fullSHA})
	emit(ConnEvent{PeerKey: peerKey, PeerName: req.DownloaderName, Sent: size, Done: true})
}

// DownloadOptions configures pulling a broadcast file. Name/Size come from the
// advertisement; PinFingerprint (the broadcaster's cert fingerprint from the
// advert) authenticates the source and is REQUIRED. Identity authenticates the
// downloader (needed for trusted/approve broadcasts). Interrupted downloads
// resume automatically from a kept partial keyed by (PinFingerprint|Name|Size).
type DownloadOptions struct {
	Dest           string
	PinFingerprint string
	Name           string
	Size           int64
	DestDir        string
	Identity       ed25519.PrivateKey
	DownloaderName string
	Overwrite      bool
	DialTimeout    time.Duration
	HandshakeTimeout time.Duration
	OnProgress     func(received, total int64)
}

// Download pulls the broadcast file at opts.Dest into DestDir, resuming from any
// kept partial. It verifies the whole-file SHA the broadcaster reports.
func Download(ctx context.Context, opts DownloadOptions) (ReceiveResult, error) {
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	if opts.Name == "" {
		return ReceiveResult{}, errors.New("lanshare: download needs the advertised file name")
	}
	destDir, err := resolveDestDir(opts.DestDir)
	if err != nil {
		return ReceiveResult{}, err
	}
	outPath, err := destPath(destDir, opts.Name)
	if err != nil {
		return ReceiveResult{}, err
	}
	if _, statErr := os.Stat(outPath); statErr == nil && !opts.Overwrite {
		return ReceiveResult{}, fmt.Errorf("lanshare: %q already exists", filepath.Base(outPath))
	}

	partialPath := filepath.Join(destDir, partialName(opts.PinFingerprint, opts.Name, opts.Size))
	offset := resumeOffset(partialPath, opts.Size)

	addr, err := normalizeDest(opts.Dest)
	if err != nil {
		return ReceiveResult{}, err
	}
	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ReceiveResult{}, fmt.Errorf("lanshare: connect %s: %w", addr, err)
	}
	conn := tls.Client(raw, clientTLSConfig(opts.PinFingerprint))
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return ReceiveResult{}, fmt.Errorf("lanshare: TLS handshake: %w", err)
	}

	req := downloadReq{Version: protocolVersion, Offset: offset, DownloaderName: opts.DownloaderName}
	if len(opts.Identity) > 0 {
		ekm, err := exportKeyingMaterial(conn)
		if err != nil {
			return ReceiveResult{}, err
		}
		if pub, ok := opts.Identity.Public().(ed25519.PublicKey); ok {
			req.IdentityPub = pub
			req.IdentitySig = ed25519.Sign(opts.Identity, identityMessage(ekm))
		}
	}
	if err := writeJSON(conn, msgDownloadReq, req); err != nil {
		return ReceiveResult{}, err
	}
	var acc accept
	if err := readControl(conn, msgAccept, &acc); err != nil {
		return ReceiveResult{}, err
	}
	if !acc.OK {
		reason := acc.Reason
		if reason == "" {
			reason = "broadcaster declined"
		}
		return ReceiveResult{}, fmt.Errorf("lanshare: %s", reason)
	}
	// Verify the broadcaster's identity proof (bound to this TLS session), so the
	// caller can recognise / trust the source by key.
	var broadcasterKey []byte
	if len(acc.IdentityPub) > 0 || len(acc.IdentitySig) > 0 {
		if len(acc.IdentityPub) != ed25519.PublicKeySize || len(acc.IdentitySig) != ed25519.SignatureSize {
			return ReceiveResult{}, errors.New("lanshare: malformed broadcaster identity")
		}
		ekm, err := exportKeyingMaterial(conn)
		if err != nil {
			return ReceiveResult{}, err
		}
		if !ed25519.Verify(ed25519.PublicKey(acc.IdentityPub), identityMessage(ekm), acc.IdentitySig) {
			return ReceiveResult{}, errors.New("lanshare: broadcaster identity verification failed")
		}
		broadcasterKey = acc.IdentityPub
	}
	total := opts.Size
	if acc.Size > 0 {
		total = acc.Size
	}

	_ = conn.SetDeadline(time.Time{})
	got, localSHA, rerr := receiveResumable(ctx, conn, partialPath, offset, total, opts.OnProgress)
	if rerr != nil {
		return ReceiveResult{}, rerr // partial kept for a later resume
	}
	var res done
	if err := readControl(conn, msgDone, &res); err != nil {
		return ReceiveResult{}, err
	}
	if res.SHA256 != "" && res.SHA256 != localSHA {
		_ = os.Remove(partialPath) // corrupt/mismatched: discard so the retry is clean
		return ReceiveResult{}, errors.New("lanshare: integrity check failed (sha256 mismatch)")
	}
	if err := placeFile(partialPath, outPath, opts.Overwrite); err != nil {
		return ReceiveResult{}, err
	}
	return ReceiveResult{Name: filepath.Base(outPath), Path: outPath, Bytes: got, SHA256: localSHA, PeerIP: remoteIP(conn), SenderKey: broadcasterKey}, nil
}

// receiveResumable streams msgData into the partial (appending from offset) until
// msgEOF, hashing the WHOLE file (re-hashing the existing partial first) so the
// broadcaster's whole-file SHA can be verified. On network error the partial is
// KEPT (for a later resume); on a protocol/size error it is discarded.
func receiveResumable(ctx context.Context, conn net.Conn, partialPath string, offset, total int64, onProgress func(int64, int64)) (int64, string, error) {
	digest := sha256.New()
	var f *os.File
	var err error
	if offset > 0 {
		f, err = os.OpenFile(partialPath, os.O_RDWR, 0o600)
		if err != nil {
			return 0, "", err
		}
		if _, err := io.CopyN(digest, f, offset); err != nil {
			f.Close()
			return 0, "", fmt.Errorf("lanshare: re-hash partial: %w", err)
		}
		if err := f.Truncate(offset); err != nil {
			f.Close()
			return 0, "", err
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			return 0, "", err
		}
	} else {
		f, err = os.OpenFile(partialPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, "", err
		}
	}
	received := offset
	closed := false
	discard := func() { // hard failure: drop the partial
		if !closed {
			f.Close()
		}
		_ = os.Remove(partialPath)
	}
	for {
		select {
		case <-ctx.Done():
			f.Close()
			return 0, "", ctx.Err() // keep partial
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		typ, payload, ferr := readFrame(conn, maxDataFrame)
		if ferr != nil {
			f.Close()
			return 0, "", fmt.Errorf("lanshare: read stream: %w", ferr) // keep partial
		}
		switch typ {
		case msgData:
			received += int64(len(payload))
			if received > total {
				discard()
				return 0, "", fmt.Errorf("lanshare: broadcaster exceeded declared size (%d > %d)", received, total)
			}
			if _, werr := f.Write(payload); werr != nil {
				f.Close()
				return 0, "", werr // keep partial
			}
			_, _ = digest.Write(payload)
			if onProgress != nil {
				onProgress(received, total)
			}
		case msgEOF:
			if received != total {
				f.Close()
				return 0, "", fmt.Errorf("lanshare: incomplete transfer: %d of %d bytes", received, total) // keep partial
			}
			if err := f.Sync(); err != nil {
				f.Close()
				return 0, "", err
			}
			if err := f.Close(); err != nil {
				return 0, "", err
			}
			closed = true
			return received, hex.EncodeToString(digest.Sum(nil)), nil
		default:
			discard()
			return 0, "", fmt.Errorf("lanshare: unexpected frame type %d during download", typ)
		}
	}
}

// fileSHA returns the lowercase-hex SHA-256 of a file.
func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// partialName is the deterministic name for a download's resume partial, keyed by
// the broadcaster fingerprint + file name + size, so a reconnect to the same
// offering resumes.
func partialName(fingerprint, name string, size int64) string {
	sum := sha256.Sum256([]byte(fingerprint + "\x00" + name + "\x00" + strconv.FormatInt(size, 10)))
	return ".s2u-partial-" + hex.EncodeToString(sum[:12])
}

// resumeOffset returns the byte count to resume from: the size of an existing
// partial when it is a strict prefix (0 < size < total), else 0 (fresh).
func resumeOffset(partialPath string, total int64) int64 {
	fi, err := os.Stat(partialPath)
	if err != nil || fi.IsDir() {
		return 0
	}
	if fi.Size() > 0 && fi.Size() < total {
		return fi.Size()
	}
	return 0
}

// SweepStalePartials removes .s2u-partial-* files in dir older than maxAge, so
// abandoned resumes do not accumulate. Best-effort.
func SweepStalePartials(dir string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < len(".s2u-partial-") || e.Name()[:len(".s2u-partial-")] != ".s2u-partial-" {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
