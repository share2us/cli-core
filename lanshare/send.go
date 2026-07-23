package lanshare

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"time"
)

// SendOptions configures a direct LAN/overlay send. The caller resolves the
// source (zipping a folder to a temp file first) and supplies its name + size.
type SendOptions struct {
	// Dest is host or host:port. When no port is given, DefaultPort is used.
	Dest string
	// Password, when non-empty, drives the PAKE. Leave empty for an allow-ip /
	// open receiver.
	Password string
	// PinFingerprint pins the receiver's self-signed cert SHA-256 fingerprint
	// (from a QR / pairing string / trusted-device entry). Empty = unpinned.
	PinFingerprint string
	// DialTimeout / HandshakeTimeout bound connection setup.
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// OnProgress, if set, is called as bytes are sent.
	OnProgress func(sent, total int64)
	// Identity, if set, authenticates the sender: it signs the TLS channel
	// binding with this Ed25519 key and sends the public key, so the receiver can
	// recognise / trust this device by its key fingerprint. SenderName is a
	// display label shown in the receiver's approval prompt / trusted-devices list.
	Identity   ed25519.PrivateKey
	SenderName string
}

// Send streams name/size/body to a receiver at opts.Dest. IsDir marks that body
// is a zip of a directory (the receiver may extract it). It returns the peer's
// reported SHA-256 on success.
func Send(ctx context.Context, name string, size int64, isDir bool, body io.Reader, opts SendOptions) (string, error) {
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.HandshakeTimeout == 0 {
		opts.HandshakeTimeout = 30 * time.Second
	}
	addr, err := normalizeDest(opts.Dest)
	if err != nil {
		return "", err
	}

	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("lanshare: connect %s: %w", addr, err)
	}
	conn := tls.Client(rawConn, clientTLSConfig(opts.PinFingerprint))
	defer conn.Close()

	// Bound the whole handshake; cleared before the (possibly long) transfer.
	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("lanshare: TLS handshake: %w", err)
	}

	h := hello{
		Version:     protocolVersion,
		Name:        name,
		Size:        size,
		IsDir:       isDir,
		HasPassword: opts.Password != "",
		SenderName:  opts.SenderName,
	}
	// Optional sender identity: sign the TLS channel binding so the receiver can
	// verify this device holds the key (and recognise it later).
	if len(opts.Identity) > 0 {
		ekm, err := exportKeyingMaterial(conn)
		if err != nil {
			return "", err
		}
		if pub, ok := opts.Identity.Public().(ed25519.PublicKey); ok {
			h.IdentityPub = pub
			h.IdentitySig = ed25519.Sign(opts.Identity, identityMessage(ekm))
		}
	}
	if err := writeJSON(conn, msgHello, h); err != nil {
		return "", err
	}

	if opts.Password != "" {
		ekm, err := exportKeyingMaterial(conn)
		if err != nil {
			return "", err
		}
		if err := pakeSender(conn, ekm, []byte(opts.Password)); err != nil {
			return "", err
		}
	}

	var acc accept
	if err := readControl(conn, msgAccept, &acc); err != nil {
		return "", err
	}
	if !acc.OK {
		reason := acc.Reason
		if reason == "" {
			reason = "receiver declined"
		}
		return "", fmt.Errorf("lanshare: %s", reason)
	}

	// Transfer: clear the handshake deadline, apply a rolling idle deadline.
	_ = conn.SetDeadline(time.Time{})
	digest := sha256.New()
	if err := streamBody(ctx, conn, body, size, digest, opts.OnProgress); err != nil {
		return "", err
	}

	var res done
	if err := readControl(conn, msgDone, &res); err != nil {
		return "", err
	}
	if !res.OK {
		reason := res.Reason
		if reason == "" {
			reason = "receiver reported failure"
		}
		return "", fmt.Errorf("lanshare: %s", reason)
	}
	localSum := hex.EncodeToString(digest.Sum(nil))
	if res.SHA256 != "" && res.SHA256 != localSum {
		return "", errors.New("lanshare: integrity check failed (sha256 mismatch)")
	}
	return localSum, nil
}

// streamBody writes body as msgData frames, hashing as it goes, then msgEOF.
func streamBody(ctx context.Context, conn *tls.Conn, body io.Reader, total int64, digest hash.Hash, onProgress func(sent, total int64)) error {
	buf := make([]byte, chunkBytes)
	var sent int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		n, readErr := body.Read(buf)
		if n > 0 {
			if err := writeFrame(conn, msgData, buf[:n]); err != nil {
				return err
			}
			_, _ = digest.Write(buf[:n])
			sent += int64(n)
			if onProgress != nil {
				onProgress(sent, total)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("lanshare: read source: %w", readErr)
		}
	}
	return writeFrame(conn, msgEOF, nil)
}

// normalizeDest appends DefaultPort when opts.Dest has no port and validates it.
func normalizeDest(dest string) (string, error) {
	if dest == "" {
		return "", errors.New("lanshare: empty destination")
	}
	if _, _, err := net.SplitHostPort(dest); err == nil {
		return dest, nil
	}
	// No port present (or an IPv6 literal without brackets): attach default.
	host := dest
	return net.JoinHostPort(host, strconv.Itoa(DefaultPort)), nil
}
