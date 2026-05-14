// ©AngelaMos | 2026
// service.go

package notify

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
)

const defaultSendTimeout = 30 * time.Second

type Service struct {
	senders     map[string]Sender
	status      StatusWriter
	logger      *slog.Logger
	sendTimeout time.Duration
	wg          sync.WaitGroup
}

type Option func(*Service)

func WithLogger(l *slog.Logger) Option {
	return func(s *Service) { s.logger = l }
}

func WithSendTimeout(d time.Duration) Option {
	return func(s *Service) { s.sendTimeout = d }
}

func NewService(status StatusWriter, opts ...Option) *Service {
	s := &Service{
		senders:     make(map[string]Sender),
		status:      status,
		logger:      slog.Default(),
		sendTimeout: defaultSendTimeout,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Service) Register(senders ...Sender) {
	for _, sender := range senders {
		if sender == nil {
			continue
		}
		s.senders[sender.Channel()] = sender
	}
}

func (s *Service) Notify(info event.NotifyInfo, evt *event.Event) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.dispatch(info, evt)
	}()
}

func (s *Service) Wait() {
	s.wg.Wait()
}

func (s *Service) dispatch(info event.NotifyInfo, evt *event.Event) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		s.sendTimeout,
	)
	defer cancel()

	sender, ok := s.senders[info.AlertChannel]
	if !ok {
		s.logger.WarnContext(ctx, "notify: no sender registered",
			"channel", info.AlertChannel,
			"event_id", evt.ID,
			"token_id", info.TokenID,
		)
		s.markStatus(ctx, evt.ID, event.NotifyFailed, nil)
		return
	}

	if err := sender.Send(ctx, info, evt); err != nil {
		s.logger.WarnContext(ctx, "notify: send failed",
			"channel", info.AlertChannel,
			"event_id", evt.ID,
			"token_id", info.TokenID,
			"error", err,
		)
		s.markStatus(ctx, evt.ID, event.NotifyFailed, nil)
		return
	}

	now := time.Now().UTC()
	s.markStatus(ctx, evt.ID, event.NotifySent, &now)
}

func (s *Service) markStatus(
	ctx context.Context,
	eventID int64,
	status event.NotifyStatus,
	sentAt *time.Time,
) {
	if s.status == nil {
		return
	}
	if err := s.status.UpdateNotifyStatus(
		ctx,
		eventID,
		status,
		sentAt,
	); err != nil {
		s.logger.WarnContext(ctx, "notify: status writeback failed",
			"event_id", eventID,
			"status", status,
			"error", err,
		)
	}
}
