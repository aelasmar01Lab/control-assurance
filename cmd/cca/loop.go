package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/assurance"
	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/db"
	"github.com/aelasmar01Lab/control-assurance/internal/demo"
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

// openEvidence opens the evidence store: an S3 bucket when
// CCA_EVIDENCE_S3_BUCKET is set, otherwise a local directory.
func openEvidence(ctx context.Context) (evidence.Store, error) {
	if bucket := os.Getenv("CCA_EVIDENCE_S3_BUCKET"); bucket != "" {
		profile := os.Getenv("CCA_EVIDENCE_AWS_PROFILE")
		if profile == "" {
			return nil, errors.New("CCA_EVIDENCE_S3_BUCKET is set but CCA_EVIDENCE_AWS_PROFILE is not; the evidence store needs its own AWS profile")
		}
		if profile == os.Getenv("AWS_PROFILE") {
			return nil, errors.New("CCA_EVIDENCE_AWS_PROFILE and AWS_PROFILE name the same profile; the evidence store and the collector must use different roles")
		}
		prefix := os.Getenv("CCA_EVIDENCE_S3_PREFIX")
		if prefix == "" {
			prefix = "evidence"
		}
		return evidence.OpenS3(ctx, profile, bucket, prefix)
	}
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
	ev, err := openEvidence(ctx)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	org := os.Getenv("CCA_ORGANIZATION")
	if org == "" {
		org = control.DefaultOrganization
	}
	if _, ok := control.ScopeFor(org); !ok {
		st.Close()
		return nil, nil, fmt.Errorf("CCA_ORGANIZATION is %q, and there is no scope/%s.yaml", org, org)
	}
	return &assurance.Service{Store: st, Evidence: ev, Organization: org}, st.Close, nil
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

// githubCollectors returns the GitHub collectors, using GITHUB_TOKEN or the
// GitHub CLI's login.
func githubCollectors(ctx context.Context) (map[string]assurance.CollectFunc, error) {
	token, err := githubToken(ctx)
	if err != nil {
		return nil, err
	}
	return (&github.Client{Token: token}).Collectors(), nil
}

// awsCollectors returns the AWS collectors and the API they call, using the
// SDK's standard credential chain (AWS_PROFILE, AWS_REGION).
func awsCollectors(ctx context.Context) (map[string]assurance.CollectFunc, aws.API, error) {
	sdk, err := aws.NewSDK(ctx)
	if err != nil {
		return nil, nil, err
	}
	return (&aws.Collector{API: sdk}).Collectors(), sdk, nil
}

func workerCount() int {
	if n, err := strconv.Atoi(os.Getenv("CCA_WORKERS")); err == nil && n > 0 && n <= 16 {
		return n
	}
	return 4
}

func printRuns(stdout io.Writer, runs []assurance.RunSummary) (failed int) {
	for _, r := range runs {
		if !r.Succeeded {
			failed++
			retry := "not retried"
			if r.RetryRunID != 0 {
				retry = fmt.Sprintf("retry queued as run %d for %s", r.RetryRunID, r.RetryAt.UTC().Format("15:04:05Z"))
			}
			fmt.Fprintf(stdout, "run %d  %s  %s  attempt %d  FAILED  class=%s  %s  (%s)\n",
				r.RunID, r.Kind, r.Target, r.Attempt, r.ErrorClass, r.ErrorDetail, retry)
			continue
		}
		coverage := "complete"
		if !r.InventoryComplete {
			coverage = "INCOMPLETE"
		}
		fmt.Fprintf(stdout, "run %d  %s  %s  attempt %d  succeeded  coverage=%s  observation=%d  evidence=%s\n",
			r.RunID, r.Kind, r.Target, r.Attempt, coverage, r.ObservationID, r.PayloadSHA256[:12])
	}
	return failed
}

func runCollect(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || (args[0] != "github" && args[0] != "aws") {
		return fmt.Errorf("%w: expected \"collect github [owner/name]...\" or \"collect aws\"", errUsage)
	}
	provider, targets := args[0], args[1:]
	if provider == "aws" && len(targets) > 0 {
		return fmt.Errorf("%w: \"collect aws\" takes no arguments; the account is the one the credentials belong to", errUsage)
	}
	if provider == "github" {
		if len(targets) == 0 {
			for _, r := range strings.Split(os.Getenv("CCA_GITHUB_REPOS"), ",") {
				if r = strings.TrimSpace(r); r != "" {
					targets = append(targets, r)
				}
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("%w: name at least one repository, or set CCA_GITHUB_REPOS", errUsage)
		}
		for _, r := range targets {
			if !github.ValidRepository(r) {
				return fmt.Errorf("%w: %q is not an owner/name repository", errUsage, r)
			}
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
	if provider == "github" {
		if svc.Collectors, err = githubCollectors(ctx); err != nil {
			return err
		}
	} else {
		var api aws.API
		if svc.Collectors, api, err = awsCollectors(ctx); err != nil {
			return err
		}
		// The account is whichever one the credentials belong to.
		account, err := api.AccountID(ctx)
		if err != nil {
			return fmt.Errorf("could not identify the AWS account: %w", err)
		}
		targets = []string{account}
	}

	queued, err := svc.RequestCollection(ctx, actor, provider, targets, nil)
	if err != nil {
		return err
	}
	for _, q := range queued {
		if !q.Queued {
			fmt.Fprintf(stdout, "run %d  %s  %s  already waiting; not queued again\n", q.RunID, q.Kind, q.Target)
		}
	}
	runs, err := svc.Work(ctx, actor, workerCount())
	failed := printRuns(stdout, runs)
	if err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d collection runs failed; no result was changed by them", failed, len(runs))
	}
	return nil
}

// envDuration reads a duration from the environment, or returns def.
func envDuration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q is not a positive duration such as 24h or 30s", name, v)
	}
	return d, nil
}

// runWorker schedules due collection, runs it and evaluates the new
// evidence, once or until interrupted.
func runWorker(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	once := len(args) == 1 && args[0] == "--once"
	if len(args) > 1 || (len(args) == 1 && !once) {
		return fmt.Errorf("%w: expected \"worker\" or \"worker --once\"", errUsage)
	}
	interval, err := envDuration("CCA_COLLECT_INTERVAL", 24*time.Hour)
	if err != nil {
		return err
	}
	tick, err := envDuration("CCA_WORKER_TICK", 30*time.Second)
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
	for _, action := range []authz.Action{authz.RunCollection, authz.RunEvaluation} {
		if err := authz.Can(actor, action, authz.Resource{}); err != nil {
			return err
		}
	}

	// A source whose credentials are missing is left out: its runs stay
	// queued and show as waiting on the integration health page.
	svc.Collectors = map[string]assurance.CollectFunc{}
	if gh, err := githubCollectors(ctx); err != nil {
		fmt.Fprintf(stderr, "worker: GitHub collection is off: %v\n", err)
	} else {
		maps.Copy(svc.Collectors, gh)
	}
	if awsc, _, err := awsCollectors(ctx); err != nil {
		fmt.Fprintf(stderr, "worker: AWS collection is off: %v\n", err)
	} else {
		maps.Copy(svc.Collectors, awsc)
	}
	if len(svc.Collectors) == 0 {
		return errors.New("no source has usable credentials")
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	pass := func() error {
		queued, err := svc.ScheduleDue(ctx, actor, interval)
		if err != nil {
			return fmt.Errorf("schedule: %w", err)
		}
		n := 0
		for _, q := range queued {
			if q.Queued {
				n++
			}
		}
		if n > 0 {
			fmt.Fprintf(stdout, "scheduled %d collection run(s)\n", n)
		}
		runs, err := svc.Work(ctx, actor, workerCount())
		printRuns(stdout, runs)
		if err != nil {
			return fmt.Errorf("collect: %w", err)
		}
		evals, err := svc.Evaluate(ctx, actor)
		for _, e := range evals {
			line := fmt.Sprintf("evaluation %d  %s v%s  %s", e.EvaluationID, e.CheckKey, e.CheckVersion, e.Result)
			if e.Finding != store.FindingUnchanged {
				line += "  finding " + string(e.Finding)
			}
			fmt.Fprintln(stdout, line)
		}
		if err != nil {
			return fmt.Errorf("evaluate: %w", err)
		}
		return nil
	}

	if once {
		return pass()
	}
	fmt.Fprintf(stdout, "worker started: collecting every %s, checking the queue every %s (Ctrl-C to stop)\n", interval, tick)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		if err := pass(); err != nil && ctx.Err() == nil {
			// Keep going: a later pass may succeed, and the queue keeps the work.
			fmt.Fprintf(stderr, "worker: %v\n", err)
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(stdout, "worker stopped")
			return nil
		case <-ticker.C:
		}
	}
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

// parseMoment reads a date (the start of that day, UTC) or an RFC 3339 time.
func parseMoment(v string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q is not a date (2026-11-01) or a time (2026-11-01T09:00:00Z)", errUsage, v)
	}
	return t.UTC(), nil
}

func runPackage(ctx context.Context, args []string, stdout io.Writer) error {
	const form = "expected \"package --from <when> --to <when> --out <directory or file.zip>\" or \"package verify <directory or file.zip>\""
	if len(args) == 2 && args[0] == "verify" {
		fsys, err := assurance.OpenPackage(args[len(args)-1])
		if err != nil {
			return err
		}
		v, err := assurance.VerifyPackage(fsys)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "manifest sha256  %s\nperiod           %s to %s\nfiles            %d\nevaluations      %d, of which %d reproduce\n",
			v.ManifestSHA256, v.PeriodFrom.Format(time.RFC3339), v.PeriodTo.Format(time.RFC3339), v.Files, v.Evaluations, v.Reproduced)
		for _, p := range v.Problems {
			fmt.Fprintln(stdout, "PROBLEM  "+p)
		}
		if !v.OK() {
			return fmt.Errorf("the package has %d problem(s)", len(v.Problems))
		}
		fmt.Fprintln(stdout, "The package is intact and every evaluation in it reproduces.")
		return nil
	}

	opts := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		opts[args[i]] = args[i+1]
	}
	if len(args) != 6 || opts["--from"] == "" || opts["--to"] == "" || opts["--out"] == "" {
		return fmt.Errorf("%w: %s", errUsage, form)
	}
	from, err := parseMoment(opts["--from"])
	if err != nil {
		return err
	}
	to, err := parseMoment(opts["--to"])
	if err != nil {
		return err
	}
	out := opts["--out"]

	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	p, err := svc.BuildPackage(ctx, actor, from, to)
	if err != nil {
		return err
	}
	if strings.HasSuffix(out, ".zip") {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the operator names the output file
		if err != nil {
			return err
		}
		if err := p.WriteZip(f); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	} else if err := p.WriteDir(out); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s\nperiod           %s to %s\nmanifest sha256  %s\n", out,
		p.Manifest.PeriodFrom.Format(time.RFC3339), p.Manifest.PeriodTo.Format(time.RFC3339), p.ManifestSHA256)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	keys := slices.Sorted(maps.Keys(p.Manifest.Counts))
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%d\n", strings.ReplaceAll(k, "_", " "), p.Manifest.Counts[k])
	}
	return tw.Flush()
}

// runEvidence copies every payload on record from the local evidence
// directory into the configured S3 store. Payloads are filed under their
// hash and never overwritten, so running it again copies nothing twice.
func runEvidence(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 1 || args[0] != "copy-to-s3" {
		return fmt.Errorf("%w: expected \"evidence copy-to-s3\"", errUsage)
	}
	if os.Getenv("CCA_EVIDENCE_S3_BUCKET") == "" {
		return errors.New("CCA_EVIDENCE_S3_BUCKET is not set")
	}
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	dst, err := openEvidence(ctx)
	if err != nil {
		return err
	}
	dir := os.Getenv("CCA_EVIDENCE_DIR")
	if dir == "" {
		dir = "data/evidence"
	}
	src, err := evidence.NewFS(dir)
	if err != nil {
		return err
	}
	hashes, err := st.PayloadHashes(ctx)
	if err != nil {
		return err
	}
	for _, sha := range hashes {
		// Both the read and the read-back are verified against the hash.
		data, err := src.Get(ctx, sha)
		if err != nil {
			return err
		}
		if _, _, err := dst.Put(ctx, data); err != nil {
			return err
		}
		if _, err := dst.Get(ctx, sha); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "%d payloads are in the S3 evidence store, each verified against its hash\n", len(hashes))
	return nil
}

func runReproduce(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"reproduce\" takes no arguments", errUsage)
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
	r, err := svc.Reproduce(ctx, actor)
	if err != nil {
		return err
	}
	for _, m := range r.Mismatches {
		fmt.Fprintln(stdout, "MISMATCH  "+m)
	}
	fmt.Fprintf(stdout, "%d of %d stored evaluations reproduce from their stored evidence and recorded check version\n", r.Reproduced, r.Evaluations)
	if len(r.Mismatches) > 0 {
		return fmt.Errorf("%d evaluation(s) do not reproduce", len(r.Mismatches))
	}
	return nil
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

func runRequirementsStatus(ctx context.Context, stdout io.Writer) error {
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	actor, err := cliActor(ctx, svc)
	if err != nil {
		return err
	}
	reqs, err := svc.Requirements(ctx, actor)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "REQUIREMENT\tSTATE\tRESTS ON")
	for _, r := range reqs {
		rests := "no control: " + r.Rationale
		if len(r.Controls) > 0 {
			var parts []string
			for _, c := range r.Controls {
				parts = append(parts, fmt.Sprintf("%s is %s (%s mapping)", c.Key, c.State, c.Strength))
			}
			rests = strings.Join(parts, "; ")
		}
		fmt.Fprintf(tw, "%s %s %s\t%s\t%s\n", r.Framework, r.ID, r.Title, r.State, rests)
	}
	return tw.Flush()
}

// runDemo seeds a clean database with the synthetic demo history, unless it
// is already there, and serves it. It refuses a database holding anything else.
func runDemo(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: \"demo\" takes no arguments", errUsage)
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL is not set")
	}
	if os.Getenv("CCA_EVIDENCE_S3_BUCKET") != "" {
		return errors.New("the demo keeps its synthetic evidence in a local directory; unset CCA_EVIDENCE_S3_BUCKET")
	}
	if _, err := db.MigrateUp(ctx, url); err != nil {
		return err
	}
	svc, closeSvc, err := openService(ctx)
	if err != nil {
		return err
	}
	defer closeSvc()
	// The demo is always the fictional company, whatever the environment says.
	svc.Organization = demo.Organization

	seeded, err := demo.Seeded(ctx, svc.Store)
	if err != nil {
		return err
	}
	if !seeded {
		fmt.Fprintln(stdout, "Seeding the demo. Everything below is synthetic; nothing is collected from a real system.")
		fmt.Fprintf(stdout, "%s Its %d people have addresses at %s, a domain reserved for examples.\n\n", demo.Business, len(demo.People), demo.Domain)
		steps, err := demo.Seed(ctx, svc, time.Now())
		if err != nil {
			return fmt.Errorf("seed the demo: %w", err)
		}
		for _, s := range steps {
			fmt.Fprintf(stdout, "  %s  %s\n", s.At.Format("2006-01-02 15:04 UTC"), s.Text)
		}
	}

	addr := os.Getenv("CCA_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	shown := addr
	if host, port, err := net.SplitHostPort(addr); err == nil && (host == "" || host == "0.0.0.0") {
		shown = "127.0.0.1:" + port
	}
	fmt.Fprintf(stdout, "\nDemo ready at http://%s (Ctrl-C to stop). Synthetic data only.\n\n", shown)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tPASSWORD\tCAN")
	can := map[string]string{
		"operator": "run collection and evaluation", "control-owner": "add notes, request exceptions, submit evidence",
		"reviewer": "decide exceptions, review evidence", "auditor": "read, export and download review packages",
	}
	for _, name := range demo.Users {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, demo.Password(name), can[name])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "\nThese passwords are published. The demo holds no real data; do not put any in it.")

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return web.Serve(ctx, addr, svc, web.Options{Demo: true})
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
