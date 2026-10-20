// Command sc-dc-init is the entry point (PID 1) of the Samba Conductor DC
// container image.
//
//	sc-dc-init                       first boot (provision, join or restore) when the volume is empty, then run
//	sc-dc-init health                the healthcheck (exit 0 = healthy)
//	sc-dc-init account idp|sync|backup [--name N] [--password-file F]
//	                                 create a service account (backup: replication rights only)
//	sc-dc-init account provisioner [--ou DN]... [--google-first] [--name N] [--password-file F]
//	                                 conductor-provisioner's account, delegated on the managed OUs
//	sc-dc-init dns-name NAME...      add NAME.<domain> A <SC_HOST_IP>
//	sc-dc-init show-initial-password | forget-initial-password
//	sc-dc-init version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/openbasalt/samba-conductor-containers/internal/dc"
	"github.com/openbasalt/samba-conductor-containers/internal/envcfg"
)

var version = "dev"

const usage = `usage: sc-dc-init [COMMAND]

  (no command)                 start the DC: the first boot when the volumes are empty
                               (SC_MODE=provision|join|restore), then chronyd, samba and
                               conductor-helper under supervision
  health                       healthcheck: exit 0 when the DC serves
  account idp|sync|backup [--name NAME] [--password-file FILE]
                               create a service account or set its password from a file
                               (default /run/secrets/idp-ad-password, sync-ad-password,
                               backup-account); backup gets the replication rights only
  account provisioner [--ou DN]... [--google-first] [--name NAME] [--password-file FILE]
                               conductor-provisioner's delegated account (default
                               svc-conductor-prov, /run/secrets/provisioner-ad-password),
                               sensitive, with the reset-password entries on each managed OU
                               (default OU=People,<domain>; created when missing);
                               --google-first adds the rights of the Google-first plan
  dns-name NAME...             add NAME.<domain> A <SC_HOST_IP> (conductor, idp)
  show-initial-password        print the generated Administrator password
  forget-initial-password      delete it from the volume
  version
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	cmd := ""
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "", "start":
		err = start(ctx)
	case "health":
		err = dc.Health(ctx, os.Stdout)
	case "account":
		err = account(ctx, args)
	case "dns-name":
		var c *dc.Config
		if c, _, err = dc.Load(envcfg.FromOS()); err == nil {
			if len(args) == 0 {
				err = fmt.Errorf("usage: sc-dc-init dns-name NAME")
				break
			}
			err = dc.DNSName(ctx, os.Stdout, c, args)
		}
	case "show-initial-password":
		err = dc.ShowInitialPassword(os.Stdout)
	case "forget-initial-password":
		err = dc.ForgetInitialPassword(os.Stdout)
	case "version", "--version":
		fmt.Println("sc-dc-init", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sc-dc-init:", err)
		return 1
	}
	return 0
}

func start(ctx context.Context) error {
	c, confirm, err := dc.Load(envcfg.FromOS())
	if err != nil {
		return err
	}
	r := &dc.Runner{Cfg: c, Confirm: confirm, Out: os.Stdout, Image: dc.ReadImageInfo(dc.ImageInfo)}
	r.Image["INIT_VERSION"] = version
	fmt.Printf("[sc-dc-init] %s, image %s (Samba DC, conductor-helper %s)\n", version, r.Image["IMAGE_VERSION"], r.Image["CONDUCTOR_VERSION"])
	return r.Start(ctx)
}

func account(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sc-dc-init account idp|sync|backup|provisioner [--name NAME] [--password-file FILE]")
	}
	kind := args[0]
	fs := flag.NewFlagSet("account", flag.ContinueOnError)
	name := fs.String("name", "", "account name (default svc-conductor-<kind>)")
	pw := fs.String("password-file", "", "file holding the password")
	var ous ouList
	googleFirst := false
	if kind == "provisioner" {
		fs.Var(&ous, "ou", "managed OU (DN), repeatable (default OU=People,<domain>)")
		fs.BoolVar(&googleFirst, "google-first", false, "add the rights of the Google-first plan operations")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if kind == "provisioner" {
		return dc.ProvisionerAccount(ctx, os.Stdout, dc.ProvisionerOptions{Name: *name, PasswordFile: *pw, OUs: ous, GoogleFirst: googleFirst})
	}
	return dc.Account(ctx, os.Stdout, kind, *name, *pw)
}

// ouList collects repeated --ou flags.
type ouList []string

func (l *ouList) String() string { return strings.Join(*l, "; ") }

func (l *ouList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
