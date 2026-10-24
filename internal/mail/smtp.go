// Package mail delivers the platform's out-of-band messages (magic links, password resets) over SMTP.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTP sends mail through an SMTP relay. Credentials are only sent over STARTTLS, unless
// InsecureNoTLS is set for local development against a relay without TLS.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// InsecureNoTLS allows plaintext SMTP, with no STARTTLS and no credentials. Use it only for a
	// relay on the same machine or a trusted network.
	InsecureNoTLS bool
	// BaseURL is the public URL of this server, used in password-reset instructions.
	BaseURL string
}

// Send delivers one plain-text message. It refuses header injection and honours ctx for the dial
// and the whole conversation.
func (s *SMTP) Send(ctx context.Context, to, subject, body string) error {
	if s.Host == "" || s.From == "" {
		return errors.New("mail: smtp host and from address are required")
	}
	for _, v := range []string{to, subject, s.From} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("mail: header value contains a line break")
		}
	}
	port := s.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: dial %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: greeting: %w", err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("mail: EHLO: %w", err)
	}
	if !s.InsecureNoTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("mail: relay does not offer STARTTLS; refusing to send")
		}
		if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mail: STARTTLS: %w", err)
		}
		if s.Username != "" {
			auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("mail: auth: %w", err)
			}
		}
	}

	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("mail: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	msg := "From: " + s.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		body + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("mail: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: end of data: %w", err)
	}
	return c.Quit()
}

// SendMagicLink emails a single-use sign-in link. It satisfies api.MagicLinkSender.
func (s *SMTP) SendMagicLink(ctx context.Context, email, verifyURL string, expiresAt time.Time) error {
	body := "Use this link to sign in. It works once and expires at " +
		expiresAt.UTC().Format(time.RFC3339) + ".\n\n" + verifyURL + "\n\n" +
		"If you did not ask for this, ignore this message."
	return s.Send(ctx, email, "Your sign-in link", body)
}

// SendPasswordReset emails a password-reset token. It satisfies api.PasswordResetSender. The
// token is sent once and works until expiresAt.
func (s *SMTP) SendPasswordReset(ctx context.Context, identifier, rawToken string, expiresAt time.Time) error {
	body := "A password reset was requested for this account. The reset token expires at " +
		expiresAt.UTC().Format(time.RFC3339) + ".\n\n" +
		"Token: " + rawToken + "\n\n" +
		"Submit it with the new password to " + strings.TrimRight(s.BaseURL, "/") + "/auth/password/reset/confirm.\n\n" +
		"If you did not ask for this, ignore this message."
	return s.Send(ctx, identifier, "Password reset", body)
}
