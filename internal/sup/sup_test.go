package sup

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// One process exits: Run stops the others and names it.
func TestRunFailFast(t *testing.T) {
	out := &safeBuf{}
	s := &Supervisor{Out: out, StopTimeout: 2 * time.Second}
	start := time.Now()
	err := s.Run(context.Background(), []Process{
		{Name: "sleeper", Path: "/bin/sleep", Args: []string{"60"}},
		{Name: "quitter", Path: "/bin/sh", Args: []string{"-c", "echo hello; exit 3"}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "quitter exited (exit status 3)") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the sleeper was not stopped")
	}
	if !strings.Contains(out.String(), "[quitter] hello") {
		t.Fatalf("output not prefixed:\n%s", out.String())
	}
}

// Cancel stops everything and returns nil; Exec works under the reaper.
func TestRunCancelAndExec(t *testing.T) {
	out := &safeBuf{}
	s := &Supervisor{Out: out, StopTimeout: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	var execOut []byte
	var execErr, execFail error
	done := make(chan struct{})
	err := s.Run(ctx, []Process{{Name: "sleeper", Path: "/bin/sleep", Args: []string{"60"}}}, func(bctx context.Context) {
		execOut, execErr = s.Exec(bctx, "/bin/sh", "-c", "echo from-exec")
		_, execFail = s.Exec(bctx, "/bin/sh", "-c", "exit 2")
		close(done)
		cancel()
	})
	<-done
	if err != nil {
		t.Fatalf("Run = %v", err)
	}
	if execErr != nil || strings.TrimSpace(string(execOut)) != "from-exec" {
		t.Fatalf("Exec = %q, %v", execOut, execErr)
	}
	if execFail == nil || !strings.Contains(execFail.Error(), "exit status 2") {
		t.Fatalf("failing Exec = %v", execFail)
	}
}
