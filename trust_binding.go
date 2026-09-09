// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

package clicore

import (
	"errors"
	"time"

	"github.com/share2us/cli-core/lanid"
)

// The trusted-device cache is honoured only for the account that is logged in
// on this machine (§AJ #10). lanid cannot import the credential store (cycle),
// so the binding is wired here, and every program that uses lanid (CLI, GUI)
// links this package.
func init() {
	lanid.CurrentAccountID = func() string {
		c, err := LoadCredential()
		if err != nil {
			return ""
		}
		return c.AccountID
	}
}

// SaveTrustList verifies and caches a fetched list so lanid.Lookup can use it.
// The list was just obtained over the authenticated session, so its account is
// authoritative: a login saved before credentials carried an account id learns
// it here; a list for a DIFFERENT account than the one already bound is an
// error, never a silent rebind.
func SaveTrustList(list LanTrustList) error {
	if err := lanid.SaveSignedTrust(list.Signed, list.PublicKey); err != nil {
		return err
	}
	payload, err := lanid.VerifyTrustList(list.Signed, list.PublicKey, time.Now())
	if err != nil {
		return err
	}
	cred, err := LoadCredential()
	if err != nil {
		return nil // nothing to bind to; the cache is then simply not honoured
	}
	switch {
	case cred.AccountID == payload.AccountID:
		return nil
	case cred.AccountID == "":
		cred.AccountID = payload.AccountID
		return SaveCredential(cred)
	default:
		_ = lanid.ResetTrust()
		return errors.New("the trusted-device list is for a different account than this login; log in again")
	}
}
