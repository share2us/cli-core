package clicore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	BodyCT      []byte          `json:"body_ct,omitempty"`
	Epoch       int             `json:"epoch,omitempty"`
	ParentID    int64           `json:"parent_id,omitempty"`
	Edited      bool            `json:"edited,omitempty"`
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

// SharenetMessage is a chat message to post (ADR-053 Phase 2). Body for a standard
// sharenet; BodyCT + Epoch + MsgID for a Secure one (see SecureNet.SealMessage).
type SharenetMessage struct {
	Channel  string   `json:"channel"`
	Body     string   `json:"body,omitempty"`
	BodyCT   []byte   `json:"body_ct,omitempty"`
	Epoch    int      `json:"epoch,omitempty"`
	MsgID    string   `json:"msg_id,omitempty"`
	ParentID int64    `json:"parent_id,omitempty"`
	AgentID  string   `json:"agent_id,omitempty"`
	Mentions []string `json:"mentions,omitempty"`
}

// PostSharenetMessage posts into a channel and returns the new event id.
func (c *Client) PostSharenetMessage(ctx context.Context, sharenetID string, m SharenetMessage) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/messages", m, &out)
	return out.ID, err
}

// EditSharenetMessage replaces one of your messages (same body rules as posting).
func (c *Client) EditSharenetMessage(ctx context.Context, sharenetID string, eventID int64, m SharenetMessage) error {
	return c.doJSON(ctx, http.MethodPatch, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/messages/"+strconv.FormatInt(eventID, 10), m, nil)
}

// DeleteSharenetMessage removes a message (yours, or any as the owner/a manager).
func (c *Client) DeleteSharenetMessage(ctx context.Context, sharenetID string, eventID int64) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/messages/"+strconv.FormatInt(eventID, 10), nil, nil)
}

// AgentDM is an agent's direct message with a person (ADR-054 phase 2).
type AgentDM struct {
	ID      string `json:"id"`
	Channel string `json:"channel"` // "dm:<id>": post into it with PostSharenetMessage
	Created bool   `json:"created"`
}

// OpenAgentDM opens (or returns) this agent's direct message with a member of the
// sharenet, named by username. Only the agent's owner's device may call it, for an agent
// admitted to projectID with posting allowed. The first time, the project shows a line
// naming the person (never the content), and the person is notified.
func (c *Client) OpenAgentDM(ctx context.Context, sharenetID, agentID, projectID, username string) (AgentDM, error) {
	var out AgentDM
	body := map[string]string{"agent_id": agentID, "project_id": projectID, "username": strings.TrimPrefix(strings.TrimSpace(username), "@")}
	err := c.doJSON(ctx, http.MethodPost, "/v1/sharenets/"+url.PathEscape(sharenetID)+"/dms", body, &out)
	return out, err
}
