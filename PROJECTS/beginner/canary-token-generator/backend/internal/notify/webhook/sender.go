// ©AngelaMos | 2026
// sender.go

package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

const (
	Channel = "webhook"

	envelopeVersion = "1"
	envelopeEvent   = "canary.triggered"

	defaultMaxTries        = 3
	defaultMaxElapsed      = 30 * time.Second
	defaultInitialInterval = 500 * time.Millisecond
	defaultOverallTimeout  = 10 * time.Second
	defaultDialTimeout     = 5 * time.Second

	contentTypeJSON     = "application/json"
	signatureHeaderName = "X-Canary-Signature"
	signaturePrefix     = "sha256="
)

var (
	ErrChannelNotConfigured = errors.New(
		"webhook: webhook URL not configured",
	)
	ErrInvalidWebhookURL = errors.New("webhook: invalid url")
	ErrWebhookAPI        = errors.New("webhook: api error")
)

type Config struct {
	ManageURL       string
	HMACSecret      string
	HTTPClient      *http.Client
	MaxTries        uint
	MaxElapsed      time.Duration
	InitialInterval time.Duration
}

type Option func(*Config)

func WithMaxTries(n uint) Option { return func(c *Config) { c.MaxTries = n } }

func WithMaxElapsed(d time.Duration) Option {
	return func(c *Config) { c.MaxElapsed = d }
}

func WithInitialInterval(d time.Duration) Option {
	return func(c *Config) { c.InitialInterval = d }
}

func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) { c.HTTPClient = client }
}

type Sender struct {
	manageURL       string
	hmacSecret      string
	httpClient      *http.Client
	maxTries        uint
	maxElapsed      time.Duration
	initialInterval time.Duration
}

func NewSender(cfg Config, opts ...Option) *Sender {
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	if cfg.MaxTries == 0 {
		cfg.MaxTries = defaultMaxTries
	}
	if cfg.MaxElapsed == 0 {
		cfg.MaxElapsed = defaultMaxElapsed
	}
	if cfg.InitialInterval == 0 {
		cfg.InitialInterval = defaultInitialInterval
	}
	return &Sender{
		manageURL:       strings.TrimRight(cfg.ManageURL, "/"),
		hmacSecret:      cfg.HMACSecret,
		httpClient:      cfg.HTTPClient,
		maxTries:        cfg.MaxTries,
		maxElapsed:      cfg.MaxElapsed,
		initialInterval: cfg.InitialInterval,
	}
}

func defaultHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	return &http.Client{
		Timeout: defaultOverallTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   defaultDialTimeout,
			ResponseHeaderTimeout: defaultOverallTimeout,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       30 * time.Second,
		},
	}
}

func (s *Sender) Channel() string { return Channel }

func (s *Sender) Send(
	ctx context.Context,
	info event.NotifyInfo,
	evt *event.Event,
) error {
	if strings.TrimSpace(info.WebhookURL) == "" {
		return ErrChannelNotConfigured
	}
	if err := validateURL(info.WebhookURL); err != nil {
		return err
	}

	body, err := json.Marshal(buildEnvelope(info, evt, s.manageURL))
	if err != nil {
		return fmt.Errorf("webhook: marshal envelope: %w", err)
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = s.initialInterval
	expBackoff.MaxInterval = 5 * time.Second

	_, err = backoff.Retry(
		ctx,
		func() (struct{}, error) {
			return struct{}{}, s.doRequest(ctx, info.WebhookURL, body)
		},
		backoff.WithBackOff(expBackoff),
		backoff.WithMaxTries(s.maxTries),
		backoff.WithMaxElapsedTime(s.maxElapsed),
	)
	return err
}

func (s *Sender) doRequest(
	ctx context.Context,
	endpoint string,
	body []byte,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return backoff.Permanent(
			fmt.Errorf("webhook: build request: %w", err),
		)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	if s.hmacSecret != "" {
		req.Header.Set(
			signatureHeaderName,
			computeSignature(s.hmacSecret, body),
		)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: do request: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			slog.WarnContext(ctx, "webhook: close body",
				"error", cErr)
		}
	}()

	respBody, rErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if rErr != nil {
		slog.WarnContext(ctx, "webhook: read body", "error", rErr)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return backoff.Permanent(fmt.Errorf(
			"%w: status=%d body=%s",
			ErrWebhookAPI, resp.StatusCode, string(respBody),
		))
	default:
		return fmt.Errorf(
			"%w: status=%d body=%s",
			ErrWebhookAPI, resp.StatusCode, string(respBody),
		)
	}
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrInvalidWebhookURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf(
			"%w: scheme must be http or https, got %q",
			ErrInvalidWebhookURL, u.Scheme,
		)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidWebhookURL)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not allowed", ErrInvalidWebhookURL)
	}
	return nil
}

type envelope struct {
	Version string         `json:"version"`
	Event   string         `json:"event"`
	Token   tokenSection   `json:"token"`
	Trigger triggerSection `json:"trigger"`
}

type tokenSection struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Memo      string `json:"memo"`
	ManageURL string `json:"manage_url"`
}

type triggerSection struct {
	TriggeredAt time.Time       `json:"triggered_at"`
	SourceIP    string          `json:"source_ip"`
	UserAgent   string          `json:"user_agent"`
	Geo         geoSection      `json:"geo"`
	Extra       json.RawMessage `json:"extra"`
}

type geoSection struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ASNOrg  string `json:"asn_org"`
}

func buildEnvelope(
	info event.NotifyInfo,
	evt *event.Event,
	manageURL string,
) envelope {
	extra := evt.Extra
	if len(extra) == 0 {
		extra = json.RawMessage(`{}`)
	}
	return envelope{
		Version: envelopeVersion,
		Event:   envelopeEvent,
		Token: tokenSection{
			ID:        info.TokenID,
			Type:      info.Type,
			Memo:      info.Memo,
			ManageURL: buildManageURL(manageURL, info.ManageID),
		},
		Trigger: triggerSection{
			TriggeredAt: evt.TriggeredAt.UTC(),
			SourceIP:    evt.SourceIP,
			UserAgent:   derefStr(evt.UserAgent),
			Geo: geoSection{
				Country: derefStr(evt.GeoCountry),
				City:    derefStr(evt.GeoCity),
				ASNOrg:  derefStr(evt.GeoASNOrg),
			},
			Extra: extra,
		},
	}
}

func buildManageURL(base, id string) string {
	if base == "" || id == "" {
		return ""
	}
	return base + "/m/" + id
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func computeSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
