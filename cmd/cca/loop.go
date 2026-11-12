package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"text/tabwriter"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
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

// openService connects to the database and evidence store. The caller must
// call the returned close function.
func openService(ctx context.Context) (*assurance.Service, func(), error) {
	st, err := openStore(ctx)
	if err != nil {
		return nil, nil, err
	}
	ev, err := openEvidence()
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return &assurance.Service{Store: st, Evidence: ev}, st.Close, nil
}

// cliActor returns the user this invocation acts as, named by CCA_USER.
// The CLI authenticates nobody: whoever can run it already holds the
// database credentials. CCA_USER decides which permissions apply and whose
// name is written to the decision log.
func cliActor(ctx context.Context, svc *assurance.Service) (authz.Actor, error) {
	name := strings.TrimSpace(os.Getenv("CCA_USER"))
	if name == "" {
		return authz.Actor{}, errors.New("CCA_USER is not set; name the user to act as, for example CCA_USER=operator")
	}
	actor, err := svc.ActorByUsername(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return authz.Actor{}, fmt.Errorf("CCA_USER %q is not a user; run \"cca users seed\" to create the lab users", name)
	}
	return actor, err
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
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	results, err := svc.LoadCatalog(ctx, actor, all)
	for _, r := range results {
		state := "already imported"
		if r.Imported {
			state = "imported"
		}
		fmt.Fprintf(stdout, "%s %s: %s (%d requirements)\n", r.Key, r.Version, state, r.Requirements)
	}
	return err
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

	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	// Check permission before fetching a credential the actor may not use.
	if err := authz.Can(actor, authz.RunCollection, authz.Resource{}); err != nil {
		return err
	}
	token, err := githubToken(ctx)
	if err != nil {
		return err
	}
	svc.GitHub = &github.Client{Token: token}

	runs, err := svc.CollectGitHub(ctx, actor, repos)
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
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}

	evals, err := svc.Evaluate(ctx, actor)
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
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	ov, err := svc.Overview(ctx, actor)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTROL\tSTATE\tWHY")
	for _, c := range ov.Controls {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Control.Key, c.State, strings.Join(c.Reasons, " "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(stdout)
	if len(ov.Results) == 0 {
		fmt.Fprintln(stdout, "not evaluated: no check has produced a result yet")
		return nil
	}
	tw = tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RESOURCE\tCHECK\tRESULT\tEVALUATION\tOBSERVATION\tCOLLECTED\tEVIDENCE")
	for _, r := range ov.Results {
		fmt.Fprintf(tw, "%s\t%s v%s\t%s\t%d\t%d\t%s\t%s\n", r.Resource, r.CheckKey, r.CheckVersion, r.Result,
			r.EvaluationID, r.ObservationID, r.CollectedAt.UTC().Format("2006-01-02 15:04:05Z"), r.PayloadSHA256[:12])
	}
	return tw.Flush()
}

func runFindings(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "list" {
		return fmt.Errorf("%w: expected \"findings list\"", errUsage)
	}
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	rows, err := svc.Findings(ctx, actor)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no findings")
		return nil
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FINDING\tSTATE\tRESOURCE\tCHECK\tOPENED BY\tCLOSED BY\tEXCEPTIONS\tNOTES")
	for _, f := range rows {
		state, closedBy := "open", "-"
		if !f.Open() {
			state = "closed"
			closedBy = fmt.Sprintf("evaluation %d", *f.ClosingEvaluationID)
		}
		var exceptions []string
		for _, x := range f.Exceptions {
			exceptions = append(exceptions, x.DisplayStatus)
		}
		if len(exceptions) == 0 {
			exceptions = []string{"-"}
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\tevaluation %d\t%s\t%s\t%d\n", f.ID, state, f.Resource, f.CheckKey,
			f.OpeningEvaluationID, closedBy, strings.Join(exceptions, ","), len(f.Notes))
	}
	return tw.Flush()
}

func runExport(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"export\" takes no arguments", errUsage)
	}
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	data, err := svc.Export(ctx, actor)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func runUsers(ctx context.Context, args []string, stdout io.Writer) error {
	seed := len(args) == 1 && args[0] == "seed"
	reset := len(args) == 2 && args[0] == "reset-password"
	if !seed && !reset {
		return fmt.Errorf("%w: expected \"users seed\" or \"users reset-password <username>\"", errUsage)
	}
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()

	if reset {
		password, err := svc.ResetPassword(ctx, args[1])
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no user named %q", args[1])
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\t%s\n\nThis password is shown once and is not stored.\n", args[1], password)
		return nil
	}

	users, err := svc.SeedLabUsers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tROLE\tPASSWORD")
	created := 0
	for _, u := range users {
		password := "(already exists; unchanged)"
		if u.Password != "" {
			password = u.Password
			created++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", u.Username, u.Role, password)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if created > 0 {
		fmt.Fprintln(stdout, "\nThese are lab accounts. Passwords are shown once and are not stored; use \"cca users reset-password\" if one is lost.")
	}
	return nil
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
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	fmt.Fprintf(stdout, "serving on http://%s (Ctrl-C to stop)\n", addr)
	return web.Serve(ctx, addr, svc, web.Options{SecureCookies: os.Getenv("CCA_COOKIE_SECURE") == "1"})
}
