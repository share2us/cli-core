package clicore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// SharenetEvent is one entry in a sharenet channel's timeline (ADR-053).
type SharenetEvent struct {
	ID          int64           `json:"id"`
	Channel     string          `json:"channel"` // project id or "general"
	ProjectName string          `json:"project_name,omitempty"`
	Kind        string          `json:"kind"`
	RefID       string          `json:"ref_id,omitempty"`
	Body        string          `json:"body,omitempty"`
	Meta        json.RawMessage `json:"meta,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	Deleted     bool            `json:"deleted,omitempty"`
	ActorName   string          `json:"actor_name"`
	ActorYou    bool            `json:"actor_you,omitempty"`
	ActorAgent  string          `json:"actor_agent,omitempty"`
	Task        *struct {
		Status      string     `json:"status"`
		Tool        string     `json:"tool,omitempty"`
		Target      string     `json:"target"`
		TargetYours bool       `json:"target_yours,omitempty"`
		Reply       string     `json:"reply,omitempty"`
		DeliveredAt *time.Time `json:"delivered_at,omitempty"`
		CompletedAt *time.Time `json:"completed_at,omitempty"`
	} `json:"task,omitempty"`
	File *struct {
		Name        string `json:"name,omitempty"`
		Size        int64  `json:"size"`
		ContentType string `json:"content_type,omitempty"`
		Available   bool   `json:"available"`
		Secure      bool   `json:"secure,omitempty"`
	} `json:"file,omitempty"`
}

// SharenetEventsQuery picks a channel ("all", "general" or a project id) and a page:
// After returns newer events oldest first; otherwise the newest page, newest first.
type SharenetEventsQuery struct {
	Channel string
	After   int64
	Before  int64
	Limit   int
}

// ListSharenetEvents reads a sharenet's timeline. Unread counts per channel come with it.
func (c *Client) ListSharenetEvents(ctx context.Context, sharenetID string, q SharenetEventsQuery) ([]SharenetEvent, map[string]int, error) {
	v := url.Values{}
	if q.Channel != "" {
		v.Set("channel", q.Channel)
	}
	if q.After > 0 {
		v.Set("after", strconv.FormatInt(q.After, 10))
	}
	if q.Before > 0 {
		v.Set("before", strconv.FormatInt(q.Before, 10))
	}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	var out struct {
		Events []SharenetEvent `json:"events"`
		Unread map[string]int  `json:"unread"`
	}
	path := "/v1/sharenets/" + url.PathEscape(sharenetID) + "/events"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	err := c.doJSON(ctx, http.MethodGet, path, nil, &out)
	return out.Events, out.Unread, err
}

// MarkSharenetRead records how far this account has read a channel.
func (c *Client) MarkSharenetRead(ctx context.Context, sharenetID, channel string, lastEventID int64) error {
	body := map[string]any{"channel": channel, "last_event_id": lastEventID}
	return c.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/events/read", body, nil)
}
