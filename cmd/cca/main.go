// Command cca is the continuous control assurance binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/aelasmar01Lab/control-assurance/internal/db"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `cca: continuous control assurance

Usage:
  cca <command> [arguments]

Commands:
  requirements list        List every requirement in the built-in framework packs
  packs validate [file]... Validate pack files (the built-in packs when no file is given)
  migrate up               Apply pending database migrations (needs DATABASE_URL)
  migrate status           Show which migrations are applied (needs DATABASE_URL)
  version                  Print the build version

Not implemented yet: serve, collect, evaluate, export
`

// errUsage marks an error caused by how the command was invoked.
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	case "requirements":
		err = runRequirements(args[1:], stdout)
	case "packs":
		err = runPacks(args[1:], stdout)
	case "migrate":
		err = runMigrate(ctx, args[1:], stdout)
	case "serve", "collect", "evaluate", "export":
		err = errors.New("not implemented")
	default:
		err = fmt.Errorf("%w: unknown command", errUsage)
	}
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "cca %s: %v\n", args[0], err)
	if errors.Is(err, errUsage) {
		fmt.Fprintf(stderr, "\n%s", usage)
		return 2
	}
	return 1
}

func runRequirements(args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "list" {
		return fmt.Errorf("%w: expected \"requirements list\"", errUsage)
	}
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		return err
	}
	for i, p := range all {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		f := p.Framework
		fmt.Fprintf(stdout, "%s %s (%s)\n", f.Title, f.Version, f.License)
		fmt.Fprintf(stdout, "  source:        %s@%s\n", f.Source.Repository, f.Source.Commit)
		fmt.Fprintf(stdout, "  source file:   %s\n", f.Source.Path)
		fmt.Fprintf(stdout, "  source sha256: %s\n", f.Source.SHA256)
		fmt.Fprintf(stdout, "  retrieved:     %s\n", f.Source.Retrieved)
		fmt.Fprintf(stdout, "  pack sha256:   %s\n\n", p.ContentSHA256)

		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tGROUP\tTITLE")
		for _, r := range p.Requirements {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Group, r.Title)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "\n%d requirements\n", len(p.Requirements))
	}
	return nil
}

func runPacks(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return fmt.Errorf("%w: expected \"packs validate [file]...\"", errUsage)
	}
	files := args[1:]
	if len(files) == 0 {
		all, err := pack.LoadFS(packs.FS)
		if err != nil {
			return err
		}
		for _, p := range all {
			fmt.Fprintf(stdout, "ok  %s %s (%d requirements)\n",
				p.Framework.Key, p.Framework.Version, len(p.Requirements))
		}
		return nil
	}

	failed := 0
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // the operator names the file to validate
		if err == nil {
			_, err = pack.Parse(data)
		}
		if err != nil {
			failed++
			fmt.Fprintf(stdout, "FAIL %s: %v\n", f, err)
			continue
		}
		fmt.Fprintf(stdout, "ok  %s\n", f)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d pack files are invalid", failed, len(files))
	}
	return nil
}

func runMigrate(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || (args[0] != "up" && args[0] != "status") {
		return fmt.Errorf("%w: expected \"migrate up\" or \"migrate status\"", errUsage)
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}

	if args[0] == "up" {
		applied, err := db.MigrateUp(ctx, url)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			fmt.Fprintln(stdout, "no pending migrations")
		}
		for _, v := range applied {
			fmt.Fprintf(stdout, "applied %05d\n", v)
		}
		return nil
	}

	statuses, err := db.MigrateStatus(ctx, url)
	if err != nil {
		return err
	}
	for _, s := range statuses {
		state := "pending"
		if s.Applied {
			state = "applied"
		}
		fmt.Fprintf(stdout, "%-8s %s\n", state, s.Source)
	}
	return nil
}
