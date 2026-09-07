// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Hassan Khurram

// Package daemonctl is the local control channel for the optional background
// service (ADR-035). It lives in cli-core so both the daemon (which serves it)
// and the GUI (which probes "does a daemon already own receiving?") share one
// implementation. The transport is a per-user unix socket on Linux/macOS (a
// named pipe on Windows is Phase 3), authenticated by a 0600 per-user token; the
// protocol is one newline-delimited JSON request and response per connection.
package daemonctl
