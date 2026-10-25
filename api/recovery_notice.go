package api

import (
	"context"
	"fmt"
	"net/mail"
	"time"

	"github.com/tpt-solutions/tpt-identity/internal/store"
)

// RecoveryNoticeSender tells a guardian that a recovery request was started for an account it guards.
// The notice carries no token and no share, only the request id, so a guardian learns of the request
// and can object. Without a sender, initiation still works and the response says no notices went out.
type RecoveryNoticeSender interface {
	SendRecoveryNotice(ctx context.Context, email, requestID, subjectDID string, startedAt time.Time) error
}

// validateGuardianEmails checks that every address belongs to a named guardian and parses as an address.
func validateGuardianEmails(emails map[string]string, guardians []string) error {
	known := make(map[string]bool, len(guardians))
	for _, g := range guardians {
		known[g] = true
	}
	for guardian, addr := range emails {
		if !known[guardian] {
			return fmt.Errorf("guardian_emails names %s, which is not a guardian", guardian)
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return fmt.Errorf("guardian_emails for %s is not an email address", guardian)
		}
	}
	return nil
}

// noticeGuardians sends a recovery notice to each guardian that has an address. It returns the guardian
// DIDs that were notified and those that were not (no sender configured, or delivery failed). A failed
// notice does not stop the recovery, but the caller is told which guardians did not hear of it.
func (s *Server) noticeGuardians(ctx context.Context, cfg *store.RecoveryConfig, requestID, subjectDID string, startedAt time.Time) (notified, failed []string) {
	for _, guardian := range cfg.GuardianDIDs {
		addr, ok := cfg.GuardianEmails[guardian]
		if !ok {
			continue
		}
		if s.recoveryNotices == nil {
			failed = append(failed, guardian)
			continue
		}
		if err := s.recoveryNotices.SendRecoveryNotice(ctx, addr, requestID, subjectDID, startedAt); err != nil {
			s.logger.Error("recovery notice not delivered", "guardian", guardian, "request_id", requestID, "err", err)
			failed = append(failed, guardian)
			continue
		}
		notified = append(notified, guardian)
	}
	return notified, failed
}
