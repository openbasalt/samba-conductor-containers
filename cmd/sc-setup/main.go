// Command sc-setup is the one-shot configuration of the Samba Conductor
// service containers (run as root, once, before the services start):
//
//	sc-setup conductor | idp | sync | backup
//	sc-setup version
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
	"github.com/openbasalt/samba-conductor-containers/internal/setup"
)

var version = "dev"

const usage = `usage: sc-setup conductor|idp|sync|backup

One-shot configuration of a service container (as root, in the service's own
image, under the compose "setup" profile). Configuration comes from SC_*
variables, secrets from files in /run/secrets; see the containers
documentation for each command's variables and secrets.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	env := envcfg.FromOS()
	if err := env.Check(setup.Allowed, "put it in a file under /run/secrets (compose secrets:)"); err != nil {
		fmt.Fprintln(os.Stderr, "sc-setup:", err)
		os.Exit(1)
	}
	s := &setup.Setup{Env: env, Out: os.Stdout, Chown: true}
	var err error
	switch os.Args[1] {
	case "conductor":
		err = s.Conductor(ctx)
	case "idp":
		err = s.IDP(ctx)
	case "sync":
		err = s.Sync(ctx)
	case "backup":
		err = s.Backup(ctx)
	case "version", "--version":
		fmt.Println("sc-setup", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sc-setup:", err)
		os.Exit(1)
	}
}
