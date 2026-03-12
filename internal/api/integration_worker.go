package api

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

func (s *Server) appendEventLocked(event AuditEvent) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	event.EventType = strings.TrimSpace(event.EventType)
	event.ProjectID = strings.TrimSpace(event.ProjectID)
	event.ScanID = strings.TrimSpace(event.ScanID)
	event.Actor = strings.TrimSpace(event.Actor)
	event.RequestID = strings.TrimSpace(event.RequestID)
	s.prependEventLocked(event)
	if s.store != nil {
		_ = s.store.AppendAuditEvent(event)
	}
	s.notifyDashboardSubscribers()
}

func (s *Server) prependEventLocked(event AuditEvent) {
	s.events = append([]AuditEvent{event}, s.events...)
	if len(s.events) > 500 {
		s.events = s.events[:500]
	}
}

func (s *Server) subscribeDashboardStream() chan struct{} {
	ch := make(chan struct{}, 1)
	s.streamMu.Lock()
	s.streamSubscribers[ch] = struct{}{}
	s.streamMu.Unlock()
	return ch
}

func (s *Server) unsubscribeDashboardStream(ch chan struct{}) {
	s.streamMu.Lock()
	delete(s.streamSubscribers, ch)
	s.streamMu.Unlock()
	close(ch)
}

func (s *Server) notifyDashboardSubscribers() {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	for ch := range s.streamSubscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Server) enqueueIntegrationJob(job IntegrationJob) (string, error) {
	if s.store == nil {
		return "", nil
	}
	created, err := s.store.EnqueueIntegrationJob(job)
	if err != nil {
		return "", err
	}
	s.dataMu.Lock()
	s.appendEventLocked(AuditEvent{
		EventType: "integration_job_enqueued",
		ProjectID: created.ProjectRef,
		ScanID:    created.ExternalRef,
		CreatedAt: time.Now().UTC(),
	})
	s.dataMu.Unlock()
	return created.ID, nil
}

func (s *Server) startIntegrationWorker() {
	if s.store == nil {
		return
	}
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.workerCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.workerCancel = cancel
	s.workerDone = done
	go s.runIntegrationWorker(ctx, done)
}

func (s *Server) stopIntegrationWorker() {
	s.workerMu.Lock()
	cancel := s.workerCancel
	done := s.workerDone
	s.workerCancel = nil
	s.workerDone = nil
	s.workerMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Server) runIntegrationWorker(ctx context.Context, done chan struct{}) {
	defer close(done)
	interval := s.integrationPollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runIntegrationWorkerCycle(ctx)
		}
	}
}

func (s *Server) runIntegrationWorkerCycle(ctx context.Context) {
	if s.store == nil {
		return
	}
	job, err := s.store.ClaimDueIntegrationJob(time.Now().UTC())
	if err != nil || job == nil {
		return
	}
	now := time.Now().UTC()
	processErr := s.processIntegrationJob(ctx, *job)
	if processErr == nil {
		event := AuditEvent{
			EventType: "integration_job_succeeded",
			ProjectID: job.ProjectRef,
			ScanID:    job.ExternalRef,
			CreatedAt: now,
		}
		_ = s.store.MarkIntegrationJobSucceededWithAuditEvent(job.ID, now, event)
		s.dataMu.Lock()
		s.prependEventLocked(event)
		s.dataMu.Unlock()
		return
	}

	if isRetryableIntegrationError(processErr) && job.AttemptCount < job.MaxAttempts {
		nextAttempt := now.Add(s.integrationBackoff(job.AttemptCount))
		event := AuditEvent{
			EventType: "integration_job_retry_scheduled",
			ProjectID: job.ProjectRef,
			ScanID:    job.ExternalRef,
			CreatedAt: now,
		}
		_ = s.store.MarkIntegrationJobRetryWithAuditEvent(job.ID, processErr.Error(), nextAttempt, now, event)
		s.dataMu.Lock()
		s.prependEventLocked(event)
		s.dataMu.Unlock()
		return
	}

	event := AuditEvent{
		EventType: "integration_job_failed",
		ProjectID: job.ProjectRef,
		ScanID:    job.ExternalRef,
		CreatedAt: now,
	}
	_ = s.store.MarkIntegrationJobFailedWithAuditEvent(job.ID, processErr.Error(), now, event)
	s.dataMu.Lock()
	s.prependEventLocked(event)
	s.dataMu.Unlock()
}

func (s *Server) processIntegrationJob(_ context.Context, job IntegrationJob) error {
	if strings.TrimSpace(job.JobType) != "webhook_event" {
		return nil
	}
	if strings.TrimSpace(job.Payload) == "" {
		return &integrationRetryableError{msg: "missing job payload"}
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(job.Payload), &payload); err != nil {
		return err
	}
	retryCount := 0
	if raw, ok := payload["simulate_transient_failures"]; ok {
		switch v := raw.(type) {
		case float64:
			retryCount = int(v)
		case int:
			retryCount = v
		}
	}
	if retryCount > 0 && job.AttemptCount <= retryCount {
		return &integrationRetryableError{msg: "transient integration processing failure"}
	}
	return nil
}

func (s *Server) integrationBackoff(attempt int) time.Duration {
	base := s.integrationRetryBase
	if base <= 0 {
		base = 1 * time.Second
	}
	maxDelay := s.integrationRetryMax
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func (s *Server) loadPersistentState() error {
	if s.store == nil {
		return nil
	}

	// Persist bootstrap keys supplied via environment and then load full key state.
	for key, id := range s.keyIndex {
		meta, ok := s.keysByID[id]
		if !ok {
			continue
		}
		if err := s.store.EnsureBootstrapAPIKey(key, meta); err != nil {
			return err
		}
	}

	keys, err := s.store.LoadAPIKeys()
	if err != nil {
		return err
	}
	for _, item := range keys {
		keyHash := normalizeStoredAPIKeyHash(item.KeyHash)
		if keyHash != "" {
			if currentID, exists := s.keyHashes[keyHash]; exists && currentID != item.Metadata.ID {
				delete(s.keysByID, currentID)
				for rawKey, indexedID := range s.keyIndex {
					if indexedID == currentID {
						s.keyIndex[rawKey] = item.Metadata.ID
					}
				}
			}
			if item.Metadata.Revoked {
				delete(s.keyHashes, keyHash)
			} else {
				s.keyHashes[keyHash] = item.Metadata.ID
			}
		}
		s.keysByID[item.Metadata.ID] = item.Metadata
	}

	projects, err := s.store.LoadProjects()
	if err != nil {
		return err
	}
	s.projects = projects

	scans, err := s.store.LoadScans(2000)
	if err != nil {
		return err
	}
	s.scans = scans

	events, err := s.store.LoadAuditEvents(500)
	if err != nil {
		return err
	}
	if len(events) > 0 {
		s.events = events
		return nil
	}
	if len(s.events) > 0 {
		_ = s.store.AppendAuditEvent(s.events[0])
	}
	return nil
}
