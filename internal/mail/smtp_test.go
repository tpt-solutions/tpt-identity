package mail

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRelay accepts one plaintext SMTP conversation and records what was sent.
type fakeRelay struct {
	ln   net.Listener
	mu   sync.Mutex
	rcpt string
	data string
}

func newFakeRelay(t *testing.T) (*fakeRelay, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeRelay{ln: ln}
	go f.serve()
	return f, ln.Addr().(*net.TCPAddr).Port
}

func (f *fakeRelay) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	write("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			write("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			write("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			f.mu.Lock()
			f.rcpt = cmd
			f.mu.Unlock()
			write("250 ok")
		case cmd == "DATA":
			write("354 go ahead")
			var body strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				body.WriteString(l)
			}
			f.mu.Lock()
			f.data = body.String()
			f.mu.Unlock()
			write("250 queued")
		case cmd == "QUIT":
			write("221 bye")
			return
		default:
			write("502 unexpected")
		}
	}
}

func testSMTP(port int) *SMTP {
	return &SMTP{Host: "127.0.0.1", Port: port, From: "identity@example.com", InsecureNoTLS: true, BaseURL: "https://identity.example.com/"}
}

// A magic link is delivered to the address that asked for it, with the link in the body.
func TestSendMagicLinkDelivers(t *testing.T) {
	relay, port := newFakeRelay(t)
	link := "https://identity.example.com/auth/magiclink/verify?token=abc123"
	err := testSMTP(port).SendMagicLink(context.Background(), "pat@example.com", link, time.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if !strings.Contains(relay.rcpt, "<pat@example.com>") {
		t.Errorf("recipient = %q", relay.rcpt)
	}
	if !strings.Contains(relay.data, link) {
		t.Errorf("message body lacks the link:\n%s", relay.data)
	}
}

// A password-reset message names the confirm endpoint on the configured base URL.
func TestSendPasswordResetNamesEndpoint(t *testing.T) {
	relay, port := newFakeRelay(t)
	err := testSMTP(port).SendPasswordReset(context.Background(), "pat@example.com", "reset-token-xyz", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if !strings.Contains(relay.data, "https://identity.example.com/auth/password/reset/confirm") {
		t.Errorf("reset message lacks the confirm endpoint:\n%s", relay.data)
	}
}

// A line break in a recipient is refused before anything is sent, so headers cannot be injected.
func TestSendRefusesHeaderInjection(t *testing.T) {
	_, port := newFakeRelay(t)
	err := testSMTP(port).Send(context.Background(), "pat@example.com\r\nBcc: victim@example.com", "hi", "body")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("want a line-break error, got %v", err)
	}
}

// Without InsecureNoTLS the sender needs STARTTLS. The fake relay does not offer it, so it refuses.
func TestSendRefusesWithoutSTARTTLS(t *testing.T) {
	_, port := newFakeRelay(t)
	s := testSMTP(port)
	s.InsecureNoTLS = false
	err := s.Send(context.Background(), "pat@example.com", "hi", "body")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want a STARTTLS refusal, got %v", err)
	}
}
