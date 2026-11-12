package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/content"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
)

// defaultReviewer is the name written into a signature when --as is not given.
const defaultReviewer = "ali"

// loadDisk reads the content and packs under root, as files rather than as
// built into the binary, so that an edit can be checked before a build.
func loadDisk(root string) (*content.Set, content.Problems, error) {
	for _, dir := range []string{"packs", "controls", "mappings", "tracking"} {
		if st, err := os.Stat(filepath.Join(root, dir)); err != nil || !st.IsDir() { //nolint:gosec // the operator names the content root
			return nil, nil, fmt.Errorf("%s has no %s directory; run this from the repository root, or pass --root", root, dir)
		}
	}
	packsList, err := pack.LoadFS(os.DirFS(filepath.Join(root, "packs")))
	if err != nil {
		return nil, nil, fmt.Errorf("packs: %w", err)
	}
	set, problems := content.Load(os.DirFS(root), content.BuiltInRefs(packsList))
	return set, problems, nil
}

func runContent(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: expected \"content validate\" or \"content load\"", errUsage)
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("content validate", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		root := fs.String("root", ".", "")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return fmt.Errorf("%w: expected \"content validate [--root dir]\"", errUsage)
		}
		set, problems, err := loadDisk(*root)
		if err != nil {
			return err
		}
		if len(problems) > 0 {
			for _, p := range problems {
				fmt.Fprintln(stdout, "FAIL "+p.String())
			}
			return fmt.Errorf("%d problems in the content files", len(problems))
		}
		exclusions := 0
		for _, sc := range set.Scopes {
			exclusions += len(sc.Exclusions)
		}
		fmt.Fprintf(stdout, "ok  %d controls, %d mappings, %d tracking entries, %d organizations with %d exclusions\n",
			len(set.Controls), len(set.Mappings), len(set.Tracking), len(set.Scopes), exclusions)
		return nil
	case "load":
		if len(args) != 1 {
			return fmt.Errorf("%w: expected \"content load\"", errUsage)
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
		results, err := svc.LoadContent(ctx, actor)
		recorded := 0
		for _, r := range results {
			if r.Recorded {
				recorded++
				fmt.Fprintf(stdout, "%s: new revision %s (%s)\n", r.Key, r.ContentSHA256[:12], r.Review)
			}
		}
		if err == nil {
			fmt.Fprintf(stdout, "%d controls, %d new revisions\n", len(results), recorded)
		}
		return err
	}
	return fmt.Errorf("%w: expected \"content validate\" or \"content load\"", errUsage)
}

func runReview(args []string, stdout io.Writer) error {
	const expected = "expected \"review status\", \"review queue\", \"review verify\", \"review sign <file>\" or \"review unsign <file>\""
	if len(args) == 0 {
		return fmt.Errorf("%w: %s", errUsage, expected)
	}
	fs := flag.NewFlagSet("review "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", ".", "")
	as := fs.String("as", defaultReviewer, "")
	requirement := fs.String("requirement", "", "")
	controlKey := fs.String("control", "", "")
	all := fs.Bool("all", false, "")
	// Flags may come before or after the file.
	var files []string
	rest := args[1:]
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return fmt.Errorf("%w: %w", errUsage, err)
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	set, problems, err := loadDisk(*root)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status", "queue":
		if len(files) != 0 {
			return fmt.Errorf("%w: %s", errUsage, expected)
		}
		if blocking := contentProblems(problems); len(blocking) > 0 {
			return fmt.Errorf("the content files are not valid; run \"cca content validate\":\n%w", blocking)
		}
		q := content.BuildQueue(set)
		if args[0] == "status" {
			fmt.Fprint(stdout, q.StatusText())
		} else {
			fmt.Fprint(stdout, q.Markdown())
		}
		return nil
	case "verify":
		if len(files) != 0 {
			return fmt.Errorf("%w: %s", errUsage, expected)
		}
		if len(problems) > 0 {
			for _, p := range problems {
				fmt.Fprintln(stdout, "FAIL "+p.String())
			}
			return fmt.Errorf("%d problems; a review is of specific content, so an entry edited after signing is signed again or set back to draft", len(problems))
		}
		q := content.BuildQueue(set)
		fmt.Fprintf(stdout, "ok  every reviewed entry reads as it did when it was signed (%d reviewed, %d draft)\n", q.Reviewed(), q.Drafts())
		return nil
	case "sign", "unsign":
		if len(files) != 1 {
			return fmt.Errorf("%w: name one file under controls/, mappings/, tracking/ or scope/", errUsage)
		}
		return signFile(stdout, *root, files[0], set, problems,
			content.Selector{Requirement: *requirement, Control: *controlKey, All: *all}, *as, args[0] == "unsign")
	}
	return fmt.Errorf("%w: %s", errUsage, expected)
}

// contentProblems drops the problems that are only about signatures.
func contentProblems(problems content.Problems) content.Problems {
	var out content.Problems
	for _, p := range problems {
		if !p.Review {
			out = append(out, p)
		}
	}
	return out
}

func signFile(stdout io.Writer, root, file string, set *content.Set, problems content.Problems, sel content.Selector, reviewer string, unsign bool) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
		return fmt.Errorf("%s is not under %s", file, root)
	}
	rel = filepath.ToSlash(rel)

	// What a signature covers must be valid. A stale signature in the same
	// file is not a reason to refuse: signing is how it is put right.
	var blocking content.Problems
	for _, p := range contentProblems(problems) {
		if p.Path == rel {
			blocking = append(blocking, p)
		}
	}
	if len(blocking) > 0 {
		return fmt.Errorf("the file is not valid, so nothing in it was signed:\n%w", blocking)
	}
	if reviewer == "" {
		return errors.New("--as needs a name")
	}

	data, err := os.ReadFile(abs) //nolint:gosec // the reviewer names the file to sign, and it is checked to be under the root
	if err != nil {
		return err
	}
	out, signed, err := content.Sign(data, rel, set, sel, reviewer, time.Now().Format("2006-01-02"), unsign)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs) //nolint:gosec // same file as read above
	if err != nil {
		return err
	}
	if err := os.WriteFile(abs, out, info.Mode().Perm()); err != nil { //nolint:gosec // same file as read above
		return err
	}
	verb := "signed as " + reviewer
	if unsign {
		verb = "set back to draft"
	}
	for _, s := range signed {
		fmt.Fprintf(stdout, "%s: %s (%s)\n", s.Entry, verb, s.Hash[:12])
	}
	fmt.Fprintf(stdout, "%d entries in %s.\n", len(signed), rel)

	// The review queue and the control guide both show review labels, so
	// they are rebuilt from the files as they now stand.
	regenerated, err := regenerateDocs(absRoot)
	if err != nil {
		return fmt.Errorf("the entries were signed, but the generated documents were not rebuilt: %w", err)
	}
	for _, doc := range regenerated {
		fmt.Fprintf(stdout, "rebuilt %s\n", doc)
	}
	fmt.Fprintln(stdout, "Commit the changed files to keep the review.")
	return nil
}

// regenerateDocs rewrites the documents generated from the content files,
// where the root has them.
func regenerateDocs(root string) ([]string, error) {
	set, problems, err := loadDisk(root)
	if err != nil {
		return nil, err
	}
	if blocking := contentProblems(problems); len(blocking) > 0 {
		return nil, blocking
	}
	packsList, err := pack.LoadFS(os.DirFS(filepath.Join(root, "packs")))
	if err != nil {
		return nil, err
	}
	controls, tracked := control.FromSet(set)
	docs := map[string]string{
		"docs/review-queue.md": content.BuildQueue(set).Markdown(),
		"docs/controls.md":     control.GuideFor(packsList, controls, tracked, set.Scopes),
	}
	var done []string
	for _, name := range []string{"docs/review-queue.md", "docs/controls.md"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if _, err := os.Stat(path); err != nil { //nolint:gosec // a fixed name under the content root
			continue // not a checkout that keeps this document
		}
		if err := os.WriteFile(path, []byte(docs[name]), 0o644); err != nil { //nolint:gosec // a generated document inside the repository
			return done, err
		}
		done = append(done, name)
	}
	return done, nil
}
