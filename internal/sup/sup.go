// Package sup is the process supervisor of the DC container: PID 1 starts
// the long-lived processes, prefixes their output, reaps every child
// (including orphans re-parented to PID 1) and stops everything when one of
// them exits, so the engine's restart policy restarts the container
// (fail fast instead of half-running).
package sup

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Process is one supervised program.
type Process struct {
	Name string
	Path string
	Args []string
	// Env is added to the environment of the supervisor.
	Env []string
}

// Supervisor runs a set of processes.
type Supervisor struct {
	// Out receives the prefixed output (stdout of the container).
	Out io.Writer
	// StatusFile, when set, gets {"name": pid} of the running processes
	// (read by the health command).
	StatusFile string
	// StopTimeout is how long the processes get after SIGTERM.
	StopTimeout time.Duration

	mu       sync.Mutex
	running  map[int]string
	exited   map[int]chan syscall.WaitStatus
	outMu    sync.Mutex
	children sync.WaitGroup
}

// logf writes one supervisor line.
func (s *Supervisor) logf(format string, args ...any) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	fmt.Fprintf(s.Out, "[sc-dc-init] "+format+"\n", args...)
}

// prefix copies r to the output line by line, each line prefixed.
func (s *Supervisor) prefix(name string, r io.Reader) {
	defer s.children.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		s.outMu.Lock()
		fmt.Fprintf(s.Out, "[%s] %s\n", name, sc.Text())
		s.outMu.Unlock()
	}
}

// start launches p without letting exec wait for it: the reaper collects
// every exit status, so exec.Cmd.Wait is never called.
func (s *Supervisor) start(p Process) (int, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(p.Path, p.Args...)
	cmd.Env = append(os.Environ(), p.Env...)
	cmd.Stdout, cmd.Stderr = pw, pw
	cmd.Stdin = nil
	// Own process group, so a stop reaches the program's own children.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return 0, fmt.Errorf("%s: %w", p.Name, err)
	}
	_ = pw.Close()
	s.children.Add(1)
	go s.prefix(p.Name, pr)
	return cmd.Process.Pid, nil
}

// reap collects exited children until none is left to collect now.
func (s *Supervisor) reap() {
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if pid <= 0 || err != nil {
			return
		}
		s.mu.Lock()
		if ch, ok := s.exited[pid]; ok {
			ch <- ws
			delete(s.exited, pid)
		}
		s.mu.Unlock()
	}
}

func (s *Supervisor) writeStatus() {
	if s.StatusFile == "" {
		return
	}
	s.mu.Lock()
	m := map[string]int{}
	for pid, name := range s.running {
		m[name] = pid
	}
	s.mu.Unlock()
	b, _ := json.Marshal(m)
	tmp := s.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		_ = os.Rename(tmp, s.StatusFile)
	}
}

// Run starts every process and blocks until ctx is cancelled (then stops
// them and returns nil) or one of them exits (then stops the others and
// returns an error naming it). bg, when not nil, is called once everything
// started; it may use Exec to run programs under the reaper.
func (s *Supervisor) Run(ctx context.Context, procs []Process, bg func(ctx context.Context)) error {
	if s.StopTimeout == 0 {
		s.StopTimeout = 30 * time.Second
	}
	s.running = map[int]string{}
	s.exited = map[int]chan syscall.WaitStatus{}
	sigchld := make(chan os.Signal, 16)
	signal.Notify(sigchld, syscall.SIGCHLD)
	defer signal.Stop(sigchld)

	done := make(chan struct {
		name string
		ws   syscall.WaitStatus
	}, len(procs))
	startErr := func() error {
		for _, p := range procs {
			s.mu.Lock()
			pid, err := s.start(p)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			ch := make(chan syscall.WaitStatus, 1)
			s.running[pid] = p.Name
			s.exited[pid] = ch
			s.mu.Unlock()
			s.logf("started %s (pid %d)", p.Name, pid)
			go func(name string, ch chan syscall.WaitStatus) {
				ws := <-ch
				done <- struct {
					name string
					ws   syscall.WaitStatus
				}{name, ws}
			}(p.Name, ch)
		}
		return nil
	}()
	s.writeStatus()
	bgCtx, cancelBG := context.WithCancel(ctx)
	defer cancelBG()
	if startErr == nil && bg != nil {
		go bg(bgCtx)
	}
	var failed error = startErr
	if failed == nil {
	loop:
		for {
			select {
			case <-ctx.Done():
				s.logf("stopping (signal)")
				break loop
			case <-sigchld:
				s.reap()
			case d := <-done:
				failed = fmt.Errorf("%s exited (%s)", d.name, describe(d.ws))
				s.mu.Lock()
				for pid, n := range s.running {
					if n == d.name {
						delete(s.running, pid)
					}
				}
				s.mu.Unlock()
				s.logf("%v; stopping the others so the container restarts", failed)
				break loop
			}
		}
	}
	cancelBG()
	s.stopAll(sigchld)
	s.writeStatus()
	return failed
}

// stopAll sends SIGTERM to every running process group, waits up to
// StopTimeout, then SIGKILL.
func (s *Supervisor) stopAll(sigchld chan os.Signal) {
	s.mu.Lock()
	for pid := range s.running {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	s.mu.Unlock()
	deadline := time.After(s.StopTimeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		s.reap()
		s.mu.Lock()
		for pid := range s.running {
			if _, waiting := s.exited[pid]; !waiting {
				delete(s.running, pid)
			}
		}
		left := len(s.running)
		s.mu.Unlock()
		if left == 0 {
			return
		}
		select {
		case <-sigchld:
		case <-tick.C:
		case <-deadline:
			s.mu.Lock()
			for pid, name := range s.running {
				s.logf("%s did not stop in %s; killing it", name, s.StopTimeout)
				_ = syscall.Kill(-pid, syscall.SIGKILL)
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			s.mu.Unlock()
			deadline = time.After(5 * time.Second)
		}
	}
}

// Exec runs a program under the running supervisor (its exit status is
// collected by the reaper) and returns its combined output. Only valid
// inside the bg callback of Run.
func (s *Supervisor) Exec(ctx context.Context, path string, args ...string) ([]byte, error) {
	f, err := os.CreateTemp("", "sc-exec-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()
	cmd := exec.Command(path, args...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ch := make(chan syscall.WaitStatus, 1)
	s.mu.Lock()
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.exited[cmd.Process.Pid] = ch
	s.mu.Unlock()
	var ws syscall.WaitStatus
	select {
	case ws = <-ch:
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		ws = <-ch
	}
	out, _ := os.ReadFile(f.Name())
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return out, fmt.Errorf("%s: %s", filepath.Base(path), describe(ws))
	}
	return out, nil
}

func describe(ws syscall.WaitStatus) string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		return "signal " + ws.Signal().String()
	}
	return "unknown status"
}
