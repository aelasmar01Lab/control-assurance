package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"text/tabwriter"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
	"github.com/aelasmar01Lab/control-assurance/internal/web"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

func openStore(ctx context.Context) (*store.Store, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	return store.Open(ctx, url)
}

func openEvidence() (*evidence.FS, error) {
	dir := os.Getenv("CCA_EVIDENCE_DIR")
	if dir == "" {
		dir = "data/evidence"
	}
	return evidence.NewFS(dir)
}

// githubToken returns GITHUB_TOKEN, or failing that the token of the GitHub
// CLI's current login. The token is never printed.
func githubToken(ctx context.Context) (string, error) {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t, nil
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		return "", errors.New("GITHUB_TOKEN is not set and the GitHub CLI (gh) is not installed")
	}
	out, err := exec.CommandContext(ctx, gh, "auth", "token").Output() //nolint:gosec // fixed arguments, path from LookPath
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "", errors.New("GITHUB_TOKEN is not set and `gh auth token` returned no token; run `gh auth login`")
	}
	return strings.TrimSpace(string(out)), nil
}

func runPacksLoad(ctx context.Context, stdout io.Writer) error {
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		return err
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, p := range all {
		imported, err := st.ImportPack(ctx, p)
		if err != nil {
			return err
		}
		state := "already imported"
		if imported {
			state = "imported"
		}
		fmt.Fprintf(stdout, "%s %s: %s (%d requirements)\n",
			p.Framework.Key, p.Framework.Version, state, len(p.Requirements))
	}
	return nil
}

func runCollect(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "github" {
		return fmt.Errorf("%w: expected \"collect github [owner/name]...\"", errUsage)
	}
	repos := args[1:]
	if len(repos) == 0 {
		for _, r := range strings.Split(os.Getenv("CCA_GITHUB_REPOS"), ",") {
			if r = strings.TrimSpace(r); r != "" {
				repos = append(repos, r)
			}
		}
	}
	if len(repos) == 0 {
		return fmt.Errorf("%w: name at least one repository, or set CCA_GITHUB_REPOS", errUsage)
	}
	for _, r := range repos {
		if !github.ValidRepository(r) {
			return fmt.Errorf("%w: %q is not an owner/name repository", errUsage, r)
		}
	}

	token, err := githubToken(ctx)
	if err != nil {
		return err
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	ev, err := openEvidence()
	if err != nil {
		return err
	}
	svc := &assurance.Service{Store: st, Evidence: ev, GitHub: &github.Client{Token: token}}

	runs, err := svc.CollectGitHub(ctx, repos)
	failed := 0
	for _, r := range runs {
		if !r.Succeeded {
			failed++
			fmt.Fprintf(stdout, "run %d  %s  FAILED  class=%s  %s\n", r.RunID, r.Repository, r.ErrorClass, r.ErrorDetail)
			continue
		}
		coverage := "complete"
		if !r.InventoryComplete {
			coverage = "INCOMPLETE"
		}
		fmt.Fprintf(stdout, "run %d  %s  succeeded  coverage=%s  observation=%d  evidence=%s\n",
			r.RunID, r.Repository, coverage, r.ObservationID, r.PayloadSHA256)
	}
	if err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d collection runs failed; no result was changed by them", failed, len(runs))
	}
	return nil
}

func runEvaluate(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"evaluate\" takes no arguments", errUsage)
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	ev, err := openEvidence()
	if err != nil {
		return err
	}
	svc := &assurance.Service{Store: st, Evidence: ev}

	evals, err := svc.Evaluate(ctx)
	for _, e := range evals {
		line := fmt.Sprintf("evaluation %d  observation=%d  %s v%s  %s", e.EvaluationID, e.ObservationID, e.CheckKey, e.CheckVersion, e.Result)
		if e.Finding != store.FindingUnchanged {
			line += "  finding " + string(e.Finding)
		}
		fmt.Fprintf(stdout, "%s\n    %s\n", line, e.Explanation)
	}
	if err != nil {
		return err
	}
	if len(evals) == 0 {
		fmt.Fprintln(stdout, "nothing to evaluate")
	}
	return nil
}

func runResults(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"results\" takes no arguments", errUsage)
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	rows, err := st.LatestResults(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "not evaluated: no check has produced a result yet")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RESOURCE\tCHECK\tRESULT\tEVALUATION\tOBSERVATION\tCOLLECTED\tEVIDENCE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s v%s\t%s\t%d\t%d\t%s\t%s\n", r.Resource, r.CheckKey, r.CheckVersion, r.Result,
			r.EvaluationID, r.ObservationID, r.CollectedAt.UTC().Format("2006-01-02 15:04:05Z"), r.PayloadSHA256[:12])
	}
	return tw.Flush()
}

func runFindings(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "list" {
		return fmt.Errorf("%w: expected \"findings list\"", errUsage)
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	rows, err := st.Findings(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no findings")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FINDING\tSTATE\tRESOURCE\tCHECK\tOPENED BY\tCLOSED BY")
	for _, f := range rows {
		state, closedBy := "open", "-"
		if !f.Open() {
			state = "closed"
			closedBy = fmt.Sprintf("evaluation %d", *f.ClosingEvaluationID)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\tevaluation %d\t%s\n", f.ID, state, f.Resource, f.CheckKey, f.OpeningEvaluationID, closedBy)
	}
	return tw.Flush()
}

func runChecks(args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "guide" {
		return fmt.Errorf("%w: expected \"checks guide\"", errUsage)
	}
	fmt.Fprint(stdout, check.Guide())
	return nil
}

func runServe(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"serve\" takes no arguments; set CCA_ADDR to change the address", errUsage)
	}
	addr := os.Getenv("CCA_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	fmt.Fprintf(stdout, "serving read-only pages on http://%s (Ctrl-C to stop)\n", addr)
	return web.Serve(ctx, addr, st)
}
