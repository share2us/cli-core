package clicore

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// A task reply in a Secure ShareNet project is sealed by the target before it leaves the
// device, so the server stores (and the channel shows) ciphertext only (ADR-053):
//
//	s2u-sealed-reply/v1:<sharenet id>:<epoch>:<base64 AES-GCM>
const sealedReplyPrefix = "s2u-sealed-reply/v1:"

// IsSealedReply reports whether a task result is a sealed Secure reply.
func IsSealedReply(result string) bool { return strings.HasPrefix(result, sealedReplyPrefix) }

// ParseSealedReply splits a sealed reply into its sharenet, epoch and ciphertext.
func ParseSealedReply(result string) (sharenetID string, epoch int, ct []byte, err error) {
	rest, ok := strings.CutPrefix(result, sealedReplyPrefix)
	if !ok {
		return "", 0, nil, errors.New("not a sealed reply")
	}
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 {
		return "", 0, nil, errors.New("malformed sealed reply")
	}
	if epoch, err = strconv.Atoi(parts[1]); err != nil || epoch < 1 {
		return "", 0, nil, errors.New("malformed sealed reply epoch")
	}
	if ct, err = base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return "", 0, nil, errors.New("malformed sealed reply body")
	}
	return parts[0], epoch, ct, nil
}

// SealTaskReply seals a reply to requestID under the sharenet's current key.
func (s *SecureNet) SealTaskReply(ctx context.Context, sharenetID, requestID, reply string) (string, error) {
	st, err := s.Keys.Client.SecureState(ctx, sharenetID)
	if err != nil {
		return "", err
	}
	if !st.Secure {
		return "", ErrNotSecureSharenet
	}
	if st.CurrentEpoch == 0 {
		return "", ErrNoEpochKeyHere
	}
	keys, err := s.EpochKeys(ctx, sharenetID, st)
	if err != nil {
		return "", err
	}
	ek, ok := keys[st.CurrentEpoch]
	if !ok {
		return "", ErrNoEpochKeyHere
	}
	ct, err := SealSym(ek, []byte(reply), TaskReplyAAD(sharenetID, st.CurrentEpoch, requestID))
	if err != nil {
		return "", err
	}
	return sealedReplyPrefix + sharenetID + ":" + strconv.Itoa(st.CurrentEpoch) + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

// OpenTaskReply returns the plain reply for requestID; a result that isn't sealed is
// returned as is.
func (s *SecureNet) OpenTaskReply(ctx context.Context, requestID, result string) (string, error) {
	if !IsSealedReply(result) {
		return result, nil
	}
	net, epoch, ct, err := ParseSealedReply(result)
	if err != nil {
		return "", err
	}
	st, err := s.Keys.Client.SecureState(ctx, net)
	if err != nil {
		return "", err
	}
	keys, err := s.EpochKeys(ctx, net, st)
	if err != nil {
		return "", err
	}
	ek, ok := keys[epoch]
	if !ok {
		return "", ErrNoEpochKeyHere
	}
	pt, err := OpenSym(ek, ct, TaskReplyAAD(net, epoch, requestID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
