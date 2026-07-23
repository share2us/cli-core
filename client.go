package clicore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// DefaultHTTPClient bounds connection setup and slow-header responses so a slow
// or malicious server (including a presigned-URL host) cannot pin the CLI during
// setup. It deliberately sets no overall Timeout: file up/downloads can be long,
// and the per-request context is what bounds total call duration.
var DefaultHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

const (
	maxRateLimitAttempts = 3
	maxRateLimitWait     = 30 * time.Second
	maxRateLimitTotal    = 60 * time.Second
	// maxJSONResponse caps a success-path JSON body so a hostile/buggy server
	// cannot exhaust memory on a metadata call. API responses are small.
	maxJSONResponse = 8 << 20 // 8 MiB
)

var rateLimitBackoffBase = time.Second
var sleepContext = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func NewClient(apiBase, token string) *Client {
	if apiBase == "" {
		resolved, _, err := ResolveAPIBase()
		if err != nil {
			resolved = DefaultAPIBase
		}
		apiBase = resolved
	}
	return &Client{
		BaseURL:    strings.TrimRight(apiBase, "/"),
		Token:      token,
		HTTPClient: DefaultHTTPClient,
	}
}

type APIError struct {
	Status      int
	Code        string
	Message     string
	RequestID   string
	DeviceLimit *DeviceLimitDetails
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" && e.Message == "" {
		return fmt.Sprintf("api error: status %d", e.Status)
	}
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type DeviceCodeRequest struct {
	DeviceName    string `json:"device_name,omitempty"`
	MachineID     string `json:"machine_id,omitempty"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

type DeviceTokenResponse struct {
	Credential      string   `json:"credential"`
	DeviceSessionID string   `json:"device_session_id"`
	Scopes          []string `json:"scopes"`
	ExpiresAt       string   `json:"expires_at"`
}

type MeResponse struct {
	AccountID string   `json:"account_id"`
	UserID    string   `json:"user_id"`
	Email     string   `json:"email"`
	PlanID    string   `json:"plan_id"`
	PlanName  string   `json:"plan_name"`
	Source    string   `json:"source"`
	Scopes    []string `json:"scopes,omitempty"`
	// MCPEnabled is the hosted-MCP kill-switch (plan entitlement AND the global
	// flag). A pointer so an older API that omits the field is treated as enabled
	// (nil), leaving the per-scope checks to gate access.
	MCPEnabled *bool `json:"mcp_enabled,omitempty"`
}

type UploadCreateRequest struct {
	FileName     string `json:"file_name"`
	SizeBytes    uint64 `json:"size_bytes"`
	ContentClass string `json:"content_class,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	ExpiresIn    string `json:"expires_in,omitempty"`
	// NoExpiry keeps the share indefinitely (no expiry). When true, ExpiresIn is
	// ignored server-side. See --keep / --expires=none.
	NoExpiry       bool           `json:"no_expiry,omitempty"`
	SHA256         string         `json:"sha256,omitempty"`
	SourceRef      string         `json:"source_ref,omitempty"`
	New            bool           `json:"new"`
	Password       string         `json:"password,omitempty"`
	OneTime        bool           `json:"one_time,omitempty"`
	Encrypted      bool           `json:"encrypted,omitempty"`
	EncryptionAlgo string         `json:"encryption_algo,omitempty"`
	Recipients     []string       `json:"recipients,omitempty"`
	MaxViews       uint64         `json:"max_views,omitempty"`
	AllowedDomains []string       `json:"allowed_domains,omitempty"`
	DeniedDomains  []string       `json:"denied_domains,omitempty"`
	Live           bool           `json:"live,omitempty"`
	TargetDevice   string         `json:"target_device,omitempty"`
	SealedKey      string         `json:"sealed_key,omitempty"`
	RecipientEmail string         `json:"recipient_email,omitempty"`
	Targets        []UploadTarget `json:"targets,omitempty"`
	// Source declares the client origin for audit attribution; only "mcp" is
	// honored server-side (an AI-agent upload).
	Source string `json:"source,omitempty"`
	// AllowReshare opts a PRIVATE share into being resharable by recipients
	// (ADR-024, --unrestrict). Pointer so an unset value omits the field and the
	// server default (false) applies; ignored for public shares.
	AllowReshare *bool `json:"allow_reshare,omitempty"`
	// Note is a short message the sharer attaches, shown to viewers on the share
	// page.
	Note string `json:"note,omitempty"`
}

type UploadTarget struct {
	TargetDeviceSessionID string `json:"target_device_session_id"`
	SealedKey             string `json:"sealed_key"`
}

// Teammate targeting (cross-account device-to-device) wire types.

type TeammateDevice struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

type TeammateDeviceList struct {
	Mode    string           `json:"mode"`
	Code    string           `json:"code"`
	Devices []TeammateDevice `json:"devices"`
}

type TeammateSenderPref struct {
	Email string `json:"email"`
	Mode  string `json:"mode"`
}

type TeammatePolicy struct {
	Mode    string               `json:"mode"`
	Senders []TeammateSenderPref `json:"senders"`
}

type PendingInboxShare struct {
	PublicID       string `json:"public_id"`
	FileName       string `json:"file_name"`
	SizeBytes      uint64 `json:"size_bytes"`
	ContentType    string `json:"content_type"`
	SenderEmail    string `json:"sender_email"`
	FromDeviceName string `json:"from_device_name"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
}

type PendingInboxResponse struct {
	Shares []PendingInboxShare `json:"shares"`
}

type UploadCreateResponse struct {
	Upload               PresignedUpload `json:"upload"`
	Share                ShareRef        `json:"share"`
	UploadSessionID      string          `json:"upload_session_id"`
	ExpiresAt            string          `json:"expires_at"`
	Link                 string          `json:"link"`
	SkippedUpload        bool            `json:"skipped_upload"`
	EmailSharesRemaining *int            `json:"email_shares_remaining,omitempty"`
}

type LivePutRequest struct {
	Content     string `json:"content"`
	CRC32       string `json:"crc32"`
	ContentType string `json:"content_type,omitempty"`
}

type LivePutResponse struct {
	Changed    bool   `json:"changed"`
	CRC32      string `json:"crc32"`
	Size       uint64 `json:"size"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type LiveFlushResponse struct {
	PublicID string `json:"public_id"`
	Version  uint64 `json:"version"`
	SHA256   string `json:"sha256"`
	Size     uint64 `json:"size"`
}

type PresignedUpload struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

type ShareRef struct {
	PublicID   string `json:"public_id"`
	Link       string `json:"link"`
	LiveUpdate bool   `json:"live_update"`
	Version    uint64 `json:"version"`
	Targeted   bool   `json:"targeted,omitempty"`
}

type UploadCompleteResponse struct {
	PublicID  string `json:"public_id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
	Version   uint64 `json:"version"`
}

type Share struct {
	PublicID            string   `json:"public_id"`
	FileName            string   `json:"file_name"`
	CreatedAt           string   `json:"created_at"`
	SizeBytes           uint64   `json:"size_bytes"`
	SHA256              string   `json:"sha256"`
	Status              string   `json:"status"`
	ExpiresAt           string   `json:"expires_at"`
	DownloadCount       uint64   `json:"download_count"`
	MaxDownloads        uint64   `json:"max_downloads"`
	ViewCount           uint64   `json:"view_count"`
	MaxViews            uint64   `json:"max_views"`
	Disabled            bool     `json:"disabled"`
	DisabledAt          string   `json:"disabled_at"`
	ContentClass        string   `json:"content_class"`
	Encrypted           bool     `json:"encrypted"`
	EncryptionAlgo      string   `json:"encryption_algo"`
	RecipientRestricted bool     `json:"recipient_restricted"`
	Recipients          []string `json:"recipients,omitempty"`
	AllowedDomains      []string `json:"allowed_domains,omitempty"`
	DeniedDomains       []string `json:"denied_domains,omitempty"`
	DeviceSessionID     string   `json:"device_session_id"`
	DeviceName          string   `json:"device_name"`
	LiveUpdate          bool     `json:"live_update"`
	Version             uint64   `json:"version"`
}

type ListSharesResponse struct {
	Shares []Share `json:"shares"`
}

type DeviceSession struct {
	ID         string `json:"id"`
	DeviceName string `json:"device_name"`
	MachineID  string `json:"machine_id"`
	ClientType string `json:"client_type"`
	PublicKey  string `json:"public_key"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
	ExpiresAt  string `json:"expires_at"`
	Current    bool   `json:"current"`
}

type ListDevicesResponse struct {
	Sessions []DeviceSession `json:"sessions"`
}

type DeviceLimitDetails struct {
	Limit    int             `json:"limit"`
	Sessions []DeviceSession `json:"sessions"`
}

type InboxShare struct {
	PublicID       string `json:"public_id"`
	FileName       string `json:"file_name"`
	SizeBytes      uint64 `json:"size_bytes"`
	ContentType    string `json:"content_type"`
	ContentClass   string `json:"content_class"`
	SealedKey      string `json:"sealed_key"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	FromDeviceName string `json:"from_device_name"`
}

type InboxResponse struct {
	Shares []InboxShare `json:"shares"`
}

type RevokeAllResponse struct {
	Revoked uint64 `json:"revoked"`
}

type AccessControlsRequest struct {
	MaxViews       uint64   `json:"max_views"`
	AllowedDomains []string `json:"allowed_domains"`
	DeniedDomains  []string `json:"denied_domains"`
}

type UsageResponse struct {
	StorageUsedBytes        uint64   `json:"storage_used_bytes"`
	StorageQuotaBytes       uint64   `json:"storage_quota_bytes"`
	MonthlyUploadBytes      uint64   `json:"monthly_upload_bytes"`
	MonthlyUploadLimitBytes uint64   `json:"monthly_upload_limit_bytes"`
	ActiveShares            uint64   `json:"active_shares"`
	MaxActiveShares         uint64   `json:"max_active_shares"`
	MaxFileSizeBytes        uint64   `json:"max_file_size_bytes"`
	MaxDownloadsPerShare    uint64   `json:"max_downloads_per_share"`
	DefaultExpiryHours      uint64   `json:"default_expiry_hours"`
	MaximumExpiryHours      uint64   `json:"maximum_expiry_hours"`
	AllowedContentClasses   []string `json:"allowed_content_classes"`
	PasswordProtection      bool     `json:"password_protection_enabled"`
	OneTimeDownload         bool     `json:"one_time_download_enabled"`
	ClientSideEncryption    bool     `json:"client_side_encryption_enabled"`
}

type UpdateCheckResponse struct {
	CurrentVersion  string          `json:"current_version"`
	LatestVersion   string          `json:"latest_version"`
	UpdateAvailable bool            `json:"update_available"`
	Platform        string          `json:"platform"`
	Downloads       UpdateDownloads `json:"downloads"`
}

type UpdateDownloads struct {
	ArchiveURL string `json:"archive_url"`
	CRC32URL   string `json:"crc32_url"`
	CRC32      string `json:"crc32"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256,omitempty"`
}

type AnalyticsTimelinePoint struct {
	Date      string `json:"date"`
	Views     uint64 `json:"views"`
	Downloads uint64 `json:"downloads"`
}

type ShareAccessEvent struct {
	OccurredAt string `json:"occurred_at"`
	IP         string `json:"ip"`
	Country    string `json:"country"`
	Client     string `json:"client"`
	EventType  string `json:"event_type"`
}

type ShareAnalyticsResponse struct {
	Views           uint64                   `json:"views"`
	Downloads       uint64                   `json:"downloads"`
	UniqueVisitors  uint64                   `json:"unique_visitors"`
	FirstAccessedAt string                   `json:"first_accessed_at"`
	LastAccessedAt  string                   `json:"last_accessed_at"`
	Timeline        []AnalyticsTimelinePoint `json:"timeline"`
	Recent          []ShareAccessEvent       `json:"recent"`
}

func (c *Client) StartDeviceCode(ctx context.Context, request ...DeviceCodeRequest) (DeviceCodeResponse, error) {
	var out DeviceCodeResponse
	var body any
	if len(request) > 0 {
		body = request[0]
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/device-codes", body, &out)
	return out, err
}

func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string) (DeviceTokenResponse, error) {
	var out DeviceTokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/auth/device-codes/"+url.PathEscape(deviceCode)+"/token", nil, &out)
	return out, err
}

func (c *Client) RegisterDeviceKey(ctx context.Context, publicKey string) error {
	body := struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: publicKey}
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/devices/key", body, nil)
}

func (c *Client) Me(ctx context.Context) (MeResponse, error) {
	var out MeResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/auth/me", nil, &out)
	return out, err
}

// OnboardingStatus reports whether the account has completed onboarding and
// whether the current terms/data-share consent still needs accepting.
type OnboardingStatus struct {
	Onboarded       bool   `json:"onboarded"`
	ConsentRequired bool   `json:"consent_required"`
	ConsentVersion  string `json:"consent_version"`
}

func (c *Client) GetOnboarding(ctx context.Context) (OnboardingStatus, error) {
	var out OnboardingStatus
	err := c.doJSON(ctx, http.MethodGet, "/v1/account/onboarding", nil, &out)
	return out, err
}

// SubmitConsent records acceptance of the given terms/data-share version.
func (c *Client) SubmitConsent(ctx context.Context, version string) error {
	body := struct {
		Version string `json:"version"`
	}{Version: version}
	return c.doJSON(ctx, http.MethodPost, "/v1/account/consent", body, nil)
}

// InstallEvent is an anonymous install/update telemetry ping (todo §J.4).
type InstallEvent struct {
	InstallID string `json:"install_id"`
	EventType string `json:"event_type,omitempty"`
	Version   string `json:"version,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

// ReportInstall posts an anonymous install/update ping (unauthenticated).
func (c *Client) ReportInstall(ctx context.Context, e InstallEvent) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/cli/install", e, nil)
}

// NewInstallID returns a random anonymous install id.
func NewInstallID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func (c *Client) ListDevices(ctx context.Context) (ListDevicesResponse, error) {
	var out ListDevicesResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/devices", nil, &out)
	return out, err
}

func (c *Client) RevokeDeviceSession(ctx context.Context, sessionID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/sessions/"+url.PathEscape(sessionID)+"/revoke", nil, nil)
}

func (c *Client) RevokeDeviceSessionWithDeviceCode(ctx context.Context, deviceCode, sessionID string) error {
	body := struct {
		SessionID string `json:"session_id"`
	}{SessionID: sessionID}
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/device-codes/"+url.PathEscape(deviceCode)+"/revoke-session", body, nil)
}

func (c *Client) Logout(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/auth/logout", nil, nil)
}

// TeammateDevices fetches the recipient's registered device public keys (the
// release gate); a disallowed policy returns an APIError with code
// "recipient_not_accepting"; an unregistered recipient returns Code
// "recipient_not_registered" with no devices.
func (c *Client) TeammateDevices(ctx context.Context, email string) (TeammateDeviceList, error) {
	var out TeammateDeviceList
	err := c.doJSON(ctx, http.MethodGet, "/v1/contacts/devices?email="+url.QueryEscape(email), nil, &out)
	return out, err
}

func (c *Client) GetTeammatePolicy(ctx context.Context) (TeammatePolicy, error) {
	var out TeammatePolicy
	err := c.doJSON(ctx, http.MethodGet, "/v1/contacts/policy", nil, &out)
	return out, err
}

func (c *Client) SetTeammatePolicy(ctx context.Context, mode string) error {
	return c.doJSON(ctx, http.MethodPut, "/v1/contacts/policy", map[string]string{"mode": mode}, nil)
}

func (c *Client) SetTeammateSender(ctx context.Context, email, mode string) error {
	return c.doJSON(ctx, http.MethodPut, "/v1/contacts/senders", map[string]string{"email": email, "mode": mode}, nil)
}

func (c *Client) DeleteTeammateSender(ctx context.Context, email string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/contacts/senders?email="+url.QueryEscape(email), nil, nil)
}

// ExposeDeviceToContact allows the given contact (by email) to target one of the
// caller's own devices under the 'approvals' inbound mode.
func (c *Client) ExposeDeviceToContact(ctx context.Context, email, deviceSessionID string) error {
	return c.doJSON(ctx, http.MethodPut, "/v1/contacts/senders/devices",
		map[string]string{"email": email, "device_session_id": deviceSessionID}, nil)
}

// UnexposeDeviceFromContact revokes a contact's access to one of the caller's devices.
func (c *Client) UnexposeDeviceFromContact(ctx context.Context, email, deviceSessionID string) error {
	return c.doJSON(ctx, http.MethodDelete,
		"/v1/contacts/senders/devices?email="+url.QueryEscape(email)+"&device_session_id="+url.QueryEscape(deviceSessionID), nil, nil)
}

// ListExposedDevicesForContact returns the caller's device session ids currently
// exposed to the given contact.
func (c *Client) ListExposedDevicesForContact(ctx context.Context, email string) ([]string, error) {
	var out struct {
		Email     string   `json:"email"`
		DeviceIDs []string `json:"device_ids"`
	}
	err := c.doJSON(ctx, http.MethodGet, "/v1/contacts/senders/devices?email="+url.QueryEscape(email), nil, &out)
	return out.DeviceIDs, err
}

func (c *Client) ListPendingInbox(ctx context.Context) (PendingInboxResponse, error) {
	var out PendingInboxResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/inbox/pending", nil, &out)
	return out, err
}

func (c *Client) ApprovePendingInbox(ctx context.Context, publicID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/inbox/pending/"+url.PathEscape(publicID)+"/approve", nil, nil)
}

func (c *Client) RejectPendingInbox(ctx context.Context, publicID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/inbox/pending/"+url.PathEscape(publicID)+"/reject", nil, nil)
}

// P2PICEServer is a STUN/TURN server with time-limited credentials, issued by the
// room-authorization endpoint.
type P2PICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// P2PRoomAuth is the API's authorization for one relay room. The API is where the
// p2p_streaming_enabled entitlement is actually enforced — the relay only verifies
// the signature on the token minted here (ADR-019).
type P2PRoomAuth struct {
	Room       string         `json:"room"`
	Role       string         `json:"role"`
	Token      string         `json:"token"`
	ExpiresAt  string         `json:"expires_at"`
	RelayURL   string         `json:"relay_url"`
	ICEServers []P2PICEServer `json:"ice_servers"`
}

// AuthorizeP2PRoom asks the API for permission to create ("send") or join ("recv")
// a relay room. The room is only the PUBLIC half of the pairing code — the secret
// half never leaves this machine.
func (c *Client) AuthorizeP2PRoom(ctx context.Context, room, role string) (P2PRoomAuth, error) {
	var out P2PRoomAuth
	body := map[string]string{"room": room, "role": role}
	err := c.doJSON(ctx, http.MethodPost, "/v1/p2p/rooms", body, &out)
	return out, err
}

// APITokenInfo is the non-secret metadata of a personal API token.
type APITokenInfo struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Scopes    []string `json:"scopes"`
	TokenHint string   `json:"token_hint"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

// CreateAPITokenResponse carries the raw token (shown exactly once) plus metadata.
type CreateAPITokenResponse struct {
	Token    string       `json:"token"`
	APIToken APITokenInfo `json:"api_token"`
}

// CreateAPIToken mints a scoped personal API token (ADR-015). Session-only on the
// server, so the caller must be an interactive login, not another PAT. Pass
// expiresInDays=nil for no expiry, or a positive day count.
func (c *Client) CreateAPIToken(ctx context.Context, label string, scopes []string, expiresInDays *int) (CreateAPITokenResponse, error) {
	body := map[string]any{"label": label, "scopes": scopes}
	if expiresInDays != nil {
		body["expires_in_days"] = *expiresInDays
	}
	var out CreateAPITokenResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/account/api-tokens", body, &out)
	return out, err
}

// ResealEntry is one item in the sender's re-seal queue: an in-flight share whose recipient
// re-keyed. The sender re-seals the retained content key to PublicKey and submits it against
// TargetSessionID (Option B, docs/design/teammate-phase-c.md §2).
type ResealEntry struct {
	ShareID         string `json:"share_id"`
	RecipientEmail  string `json:"recipient_email"`
	TargetSessionID string `json:"target_session_id"`
	PublicKey       string `json:"public_key"`
}

type ResealQueueResponse struct {
	Requests []ResealEntry `json:"requests"`
}

// ResealQueue lists in-flight shares the caller sent that need re-sealing to a recipient's
// new device key.
func (c *Client) ResealQueue(ctx context.Context) (ResealQueueResponse, error) {
	var out ResealQueueResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/shares/reseal-queue", nil, &out)
	return out, err
}

// SubmitReseal uploads a content key re-sealed to a recipient's new device public key.
func (c *Client) SubmitReseal(ctx context.Context, publicID, targetSessionID, sealedKey string) error {
	body := map[string]string{"target_session_id": targetSessionID, "sealed_key": sealedKey}
	return c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/reseal", body, nil)
}

// AckInboxShare tells the server a received share was delivered to this device, so it stops
// flagging the share for re-seal and the sender can prune its retained content key.
func (c *Client) AckInboxShare(ctx context.Context, publicID string) error {
	return c.doJSON(ctx, http.MethodPost, "/v1/inbox/"+url.PathEscape(publicID)+"/ack", nil, nil)
}

func (c *Client) CreateUpload(ctx context.Context, upload UploadCreateRequest) (UploadCreateResponse, error) {
	var out UploadCreateResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/uploads", upload, &out)
	return out, err
}

func (c *Client) CreateReplaceUpload(ctx context.Context, publicID string, upload UploadCreateRequest) (UploadCreateResponse, error) {
	var out UploadCreateResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/content", upload, &out)
	return out, err
}

func (c *Client) PutLive(ctx context.Context, publicID string, request LivePutRequest) (LivePutResponse, error) {
	var out LivePutResponse
	err := c.doJSON(ctx, http.MethodPut, "/v1/shares/"+url.PathEscape(publicID)+"/live", request, &out)
	return out, err
}

func (c *Client) FlushShare(ctx context.Context, publicID string) (LiveFlushResponse, error) {
	var out LiveFlushResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/flush", nil, &out)
	return out, err
}

func (c *Client) CompleteUpload(ctx context.Context, uploadSessionID string) (UploadCompleteResponse, error) {
	var out UploadCompleteResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/uploads/"+url.PathEscape(uploadSessionID)+"/complete", nil, &out)
	return out, err
}

func (c *Client) ListShares(ctx context.Context) (ListSharesResponse, error) {
	var out ListSharesResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/shares", nil, &out)
	return out, err
}

func (c *Client) Inbox(ctx context.Context) (InboxResponse, error) {
	var out InboxResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/inbox", nil, &out)
	return out, err
}

func (c *Client) DownloadInboxContent(ctx context.Context, publicID string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/inbox/"+url.PathEscape(publicID)+"/content", nil)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readLimitedBody(resp)
		if isCloudflareChallenge(resp, body) {
			return cloudflareChallengeError(resp.StatusCode)
		}
		if apiErr := decodeAPIErrorFromBody(resp, body); apiErr.Code != "" {
			return apiErr
		}
		return &APIError{Status: resp.StatusCode, Code: "download_failed", Message: fmt.Sprintf("inbox content failed: HTTP %d: %s", resp.StatusCode, string(body))}
	}
	_, err = io.Copy(dst, resp.Body)
	return err
}

func (c *Client) GetShare(ctx context.Context, publicID string) (Share, error) {
	var out Share
	err := c.doJSON(ctx, http.MethodGet, "/v1/shares/"+url.PathEscape(publicID), nil, &out)
	return out, err
}

func (c *Client) ShareAnalytics(ctx context.Context, publicID string) (ShareAnalyticsResponse, error) {
	var out ShareAnalyticsResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/shares/"+url.PathEscape(publicID)+"/analytics", nil, &out)
	return out, err
}

func (c *Client) RevokeShare(ctx context.Context, publicID string) (Share, error) {
	var out Share
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/revoke", nil, &out)
	return out, err
}

func (c *Client) RevokeAllShares(ctx context.Context) (RevokeAllResponse, error) {
	var out RevokeAllResponse
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/revoke-all", nil, &out)
	return out, err
}

func (c *Client) DisableShare(ctx context.Context, publicID string) (Share, error) {
	var out Share
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/disable", nil, &out)
	return out, err
}

func (c *Client) EnableShare(ctx context.Context, publicID string) (Share, error) {
	var out Share
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/enable", nil, &out)
	return out, err
}

func (c *Client) UpdateAccessControls(ctx context.Context, publicID string, controls AccessControlsRequest) (Share, error) {
	var out Share
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/access-controls", controls, &out)
	return out, err
}

func (c *Client) ExtendExpiry(ctx context.Context, publicID string, expiresIn time.Duration) (Share, error) {
	var out Share
	body := struct {
		ExpiresAt string `json:"expires_at"`
	}{
		ExpiresAt: time.Now().UTC().Add(expiresIn).Format(time.RFC3339),
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/shares/"+url.PathEscape(publicID)+"/expiry", body, &out)
	return out, err
}

func (c *Client) DeleteShare(ctx context.Context, publicID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/shares/"+url.PathEscape(publicID), nil, nil)
}

func (c *Client) Usage(ctx context.Context) (UsageResponse, error) {
	var out UsageResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/usage", nil, &out)
	return out, err
}

func (c *Client) CheckUpdate(ctx context.Context, version, osName, arch string) (UpdateCheckResponse, error) {
	query := url.Values{}
	query.Set("version", version)
	query.Set("os", osName)
	query.Set("arch", arch)
	var out UpdateCheckResponse
	err := c.doJSON(ctx, http.MethodGet, "/v1/cli/update?"+query.Encode(), nil, &out)
	return out, err
}

func (c *Client) PutUpload(ctx context.Context, upload PresignedUpload, body io.Reader, size int64) error {
	method := upload.Method
	if method == "" {
		method = http.MethodPut
	}
	req, err := http.NewRequestWithContext(ctx, method, upload.URL, body)
	if err != nil {
		return err
	}
	// S3/R2 presigned PUTs require Content-Length; without it Go would use
	// chunked transfer encoding, which the store rejects (HTTP 411).
	req.ContentLength = size
	for key, value := range upload.Headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := readLimitedBody(resp)
		if isCloudflareChallenge(resp, body) {
			return cloudflareChallengeError(resp.StatusCode)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if isPlainNonJSONBody(resp, body) {
				return &APIError{Status: resp.StatusCode, Code: "rate_limited", Message: strings.TrimSpace(string(body))}
			}
			return rateLimitedError(resp.StatusCode, retryWait(resp.Header.Get("Retry-After"), 0))
		}
		return &APIError{Status: resp.StatusCode, Code: "upload_failed", Message: fmt.Sprintf("presigned upload failed: HTTP %d: %s", resp.StatusCode, string(body))}
	}
	return nil
}

func (c *Client) DownloadURL(ctx context.Context, rawURL string, dst io.Writer) error {
	var totalWait time.Duration
	for attempt := 0; attempt < maxRateLimitAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			_, err = io.Copy(dst, resp.Body)
			return err
		}
		body, readErr := readLimitedBody(resp)
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if isCloudflareChallenge(resp, body) {
			return cloudflareChallengeError(resp.StatusCode)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if isPlainNonJSONBody(resp, body) {
				return &APIError{Status: resp.StatusCode, Code: "rate_limited", Message: strings.TrimSpace(string(body))}
			}
			if apiErr := decodeAPIErrorFromBody(resp, body); apiErr.Code != "" && apiErr.Code != "rate_limited" && apiErr.Code != "too_many_requests" {
				return apiErr
			}
			wait := retryWait(resp.Header.Get("Retry-After"), attempt)
			if attempt < maxRateLimitAttempts-1 && totalWait+wait <= maxRateLimitTotal {
				totalWait += wait
				if err := sleepContext(ctx, wait); err != nil {
					return err
				}
				continue
			}
			return rateLimitedError(resp.StatusCode, wait)
		}
		return &APIError{Status: resp.StatusCode, Code: "download_failed", Message: fmt.Sprintf("download failed: HTTP %d: %s", resp.StatusCode, string(body))}
	}
	return rateLimitedError(http.StatusTooManyRequests, maxRateLimitWait)
}

func (c *Client) doJSON(ctx context.Context, method, path string, in any, out any) error {
	var raw []byte
	if in != nil {
		var err error
		raw, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}

	var totalWait time.Duration
	for attempt := 0; attempt < maxRateLimitAttempts; attempt++ {
		var reqBody io.Reader
		if raw != nil {
			reqBody = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
		if err != nil {
			return err
		}
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			if out == nil {
				io.Copy(io.Discard, resp.Body)
				return nil
			}
			return json.NewDecoder(io.LimitReader(resp.Body, maxJSONResponse)).Decode(out)
		}

		body, readErr := readLimitedBody(resp)
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if isCloudflareChallenge(resp, body) {
			return cloudflareChallengeError(resp.StatusCode)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			if isPlainNonJSONBody(resp, body) {
				return &APIError{Status: resp.StatusCode, Code: "rate_limited", Message: strings.TrimSpace(string(body))}
			}
			if apiErr := decodeAPIErrorFromBody(resp, body); apiErr.Code != "" && apiErr.Code != "rate_limited" && apiErr.Code != "too_many_requests" {
				return apiErr
			}
			wait := retryWait(resp.Header.Get("Retry-After"), attempt)
			if attempt < maxRateLimitAttempts-1 && totalWait+wait <= maxRateLimitTotal {
				totalWait += wait
				if err := sleepContext(ctx, wait); err != nil {
					return err
				}
				continue
			}
			return rateLimitedError(resp.StatusCode, wait)
		}
		return decodeAPIErrorFromBody(resp, body)
	}
	return rateLimitedError(http.StatusTooManyRequests, maxRateLimitWait)
}

func decodeAPIError(resp *http.Response) *APIError {
	body, _ := readLimitedBody(resp)
	return decodeAPIErrorFromBody(resp, body)
}

func decodeAPIErrorFromBody(resp *http.Response, body []byte) *APIError {
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
		Sessions []DeviceSession `json:"sessions"`
		Limit    int             `json:"limit"`
	}
	_ = json.Unmarshal(body, &envelope)
	apiErr := &APIError{
		Status:    resp.StatusCode,
		Code:      envelope.Error.Code,
		Message:   envelope.Error.Message,
		RequestID: envelope.Error.RequestID,
	}
	if apiErr.Code == "device_limit_reached" {
		apiErr.DeviceLimit = &DeviceLimitDetails{
			Limit:    envelope.Limit,
			Sessions: envelope.Sessions,
		}
	}
	return apiErr
}

func readLimitedBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4096))
}

func retryWait(header string, attempt int) time.Duration {
	if d, ok := parseRetryAfter(header); ok {
		return capRateLimitWait(d)
	}
	wait := rateLimitBackoffBase
	for i := 0; i < attempt; i++ {
		wait *= 2
	}
	return capRateLimitWait(wait)
}

func parseRetryAfter(value string) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	wait := time.Until(when)
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

func capRateLimitWait(wait time.Duration) time.Duration {
	if wait > maxRateLimitWait {
		return maxRateLimitWait
	}
	if wait < 0 {
		return 0
	}
	return wait
}

func rateLimitedError(status int, wait time.Duration) error {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return &APIError{Status: status, Code: "rate_limited", Message: fmt.Sprintf("rate limited by the server; try again in ~%ds", seconds)}
}

func isPlainNonJSONBody(resp *http.Response, body []byte) bool {
	if len(strings.TrimSpace(string(body))) == 0 {
		return false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "json") {
		return false
	}
	return !looksLikeJSON(body)
}

func isCloudflareChallenge(resp *http.Response, body []byte) bool {
	if resp == nil || (resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusServiceUnavailable) {
		return false
	}
	if looksLikeJSON(body) {
		return false
	}
	if strings.TrimSpace(resp.Header.Get("cf-mitigated")) != "" || strings.TrimSpace(resp.Header.Get("cf-ray")) != "" {
		return true
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare") {
		return true
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	text := strings.ToLower(strings.TrimSpace(string(body)))
	return strings.Contains(contentType, "text/html") || strings.HasPrefix(text, "<!doctype html") || strings.HasPrefix(text, "<html")
}

func looksLikeJSON(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func cloudflareChallengeError(status int) error {
	return &APIError{
		Status:  status,
		Code:    "cloudflare_challenge",
		Message: "the server returned a Cloudflare challenge that the CLI can't solve - open the share link in a browser, or if this persists contact support@share2.us",
	}
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return DefaultHTTPClient
}

func IsAuthorizationPending(err error) bool {
	apiErr, ok := err.(*APIError)
	return ok && apiErr.Code == "authorization_pending"
}

func IsDeviceLimitReached(err error) bool {
	apiErr, ok := err.(*APIError)
	return ok && apiErr.Code == "device_limit_reached"
}

func DeviceLimitDetailsFromError(err error) (DeviceLimitDetails, bool) {
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Code != "device_limit_reached" || apiErr.DeviceLimit == nil {
		return DeviceLimitDetails{}, false
	}
	return *apiErr.DeviceLimit, true
}

func SleepInterval(interval int) time.Duration {
	if interval <= 0 {
		interval = 5
	}
	return time.Duration(interval) * time.Second
}
