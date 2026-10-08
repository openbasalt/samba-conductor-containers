package dc

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

func lookupGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

func uidOf(name string) int {
	u, err := user.Lookup(name)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return n
}

func portOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// Kernel time states (adjtimex return values) and status bits.
const (
	timeError = 5
	staUnsync = 0x0040
)

// clockSynced reads the kernel's synchronization status with a read-only
// adjtimex call (no capability needed). known is false when the call is
// refused (some seccomp profiles).
func clockSynced() (synced, known bool) {
	var tx syscall.Timex
	st, err := syscall.Adjtimex(&tx)
	if err != nil {
		return false, false
	}
	return st != timeError && tx.Status&staUnsync == 0, true
}

// checkClock refuses provision and join on an unsynchronized clock: skew
// breaks Kerberos at the worst moment.
func checkClock(allowUnsynced bool) error {
	synced, known := clockSynced()
	if !known || synced {
		return nil
	}
	if allowUnsynced {
		return nil
	}
	return errors.New("the host's kernel clock is not synchronized (adjtimex reports TIME_ERROR): synchronize the host " +
		"(chrony, systemd-timesyncd) first, or set SC_ALLOW_UNSYNCED_CLOCK=1 for a throwaway lab")
}

// randomPassword returns a password that satisfies the AD complexity rule
// (upper, lower, digit and a symbol), 24 characters.
func randomPassword() (string, error) {
	sets := []string{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "-_.+=@%"}
	all := sets[0] + sets[1] + sets[2] + sets[3]
	pick := func(s string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
		if err != nil {
			return 0, err
		}
		return s[n.Int64()], nil
	}
	out := make([]byte, 0, 24)
	for _, s := range sets {
		b, err := pick(s)
		if err != nil {
			return "", err
		}
		out = append(out, b)
	}
	for len(out) < 24 {
		b, err := pick(all)
		if err != nil {
			return "", err
		}
		out = append(out, b)
	}
	// Shuffle so the classes are not at fixed positions.
	for i := len(out) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(n.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}
