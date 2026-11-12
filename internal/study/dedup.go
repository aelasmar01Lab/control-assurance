// Package study holds the deduplication case study: a harness that stores
// one documented synthetic dataset under three strategies and measures each.
package study

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/evidence"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

// Dataset describes the synthetic dataset. Every number that shapes it is
// here, and the same Dataset always generates the same bytes.
type Dataset struct {
	Seed uint64
	// Days is how many daily collections each resource has.
	Days int

	// Repositories have branch rules: configuration that seldom changes.
	Repositories int
	// RuleChangeChance is the chance per repository per day that a rule changes.
	RuleChangeChance float64
	// ReorderChance is the chance per collection that the source returns
	// the same rules in a different order, with object keys in a different
	// order. It is an assumption of the study, not a measured property of
	// GitHub.
	ReorderChance float64

	// Accounts have IAM credential reports: activity that changes whenever
	// someone signs in or a key is used.
	BusyAccounts  int // some credential is used every day
	QuietAccounts int // a credential is used on QuietUseChance of days
	UsersPerAcct  int32
	// QuietUseChance is the chance per quiet account per day of any use.
	QuietUseChance float64
}

// Default is the dataset the published case study uses.
var Default = Dataset{
	Seed: 20261112, Days: 180,
	Repositories: 40, RuleChangeChance: 0.02, ReorderChance: 0.30,
	BusyAccounts: 2, QuietAccounts: 3, UsersPerAcct: 12, QuietUseChance: 0.10,
}

// start is the first collection day of the dataset.
var start = time.Date(2026, 1, 1, 6, 0, 0, 0, time.UTC)

// observation is one synthetic collection.
type observation struct {
	kind string
	// raw is what the source returned, as captured.
	raw []byte
	// normalized is the product's evidence payload for the same collection.
	normalized []byte
	asOf       time.Time
	// expected is each check's result and explanation at collection time.
	expected []string
}

var checksByKind = map[string][]string{
	github.BranchRulesKind: {"GH-01", "GH-02"},
	aws.IAMCredentialsKind: {"AWS-01", "AWS-02"},
}

// evaluate applies the kind's checks to a normalized payload.
func evaluate(kind string, payload []byte, asOf time.Time) ([]string, error) {
	var out []string
	for _, key := range checksByKind[kind] {
		c, ok := check.Lookup(key, "1")
		if !ok {
			return nil, fmt.Errorf("check %s version 1 is not registered", key)
		}
		result, explanation, err := c.Eval(check.Input{Payload: payload, AsOf: asOf})
		if err != nil {
			return nil, err
		}
		out = append(out, string(result)+" "+explanation)
	}
	return out, nil
}

// rawRules is the captured form of a branch-rules collection.
type rawRules struct {
	Repository    string            `json:"repository"`
	DefaultBranch string            `json:"default_branch"`
	Protected     bool              `json:"protected"`
	Rules         []json.RawMessage `json:"rules"`
}

// normalizeRules turns a captured branch-rules collection into the payload
// the product stores, using the product's own normalizer.
func normalizeRules(raw []byte) ([]byte, error) {
	var r rawRules
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	rules := make([]github.Rule, len(r.Rules))
	for i, one := range r.Rules {
		if err := json.Unmarshal(one, &rules[i]); err != nil {
			return nil, err
		}
	}
	b, err := github.NormalizeBranchRules(r.Repository, r.DefaultBranch, r.Protected, true, rules)
	if err != nil {
		return nil, err
	}
	return b.Payload()
}

// rawCredentials is the captured form of an IAM credentials collection.
type rawCredentials struct {
	Account   string           `json:"account"`
	ReportCSV string           `json:"report_csv"`
	Summary   map[string]int32 `json:"summary"`
}

func normalizeCredentials(raw []byte) ([]byte, error) {
	var r rawCredentials
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	c, err := aws.NormalizeIAMCredentials(r.Account, []byte(r.ReportCSV), r.Summary)
	if err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

func normalize(kind string, raw []byte) ([]byte, error) {
	if kind == github.BranchRulesKind {
		return normalizeRules(raw)
	}
	return normalizeCredentials(raw)
}

// rule is the generator's model of one branch rule.
type rule struct {
	typ       string
	rulesetID int
	params    [][2]string // key and JSON value, in a canonical order
}

// encode writes the rule as the source might, with object keys in the
// given order.
func (r rule) encode(repo string, rng *rand.Rand, shuffle bool) json.RawMessage {
	params := slices.Clone(r.params)
	fields := [][2]string{
		{"type", fmt.Sprintf("%q", r.typ)},
		{"ruleset_source_type", `"Repository"`},
		{"ruleset_source", fmt.Sprintf("%q", repo)},
		{"ruleset_id", fmt.Sprint(r.rulesetID)},
	}
	if shuffle {
		rng.Shuffle(len(params), func(i, j int) { params[i], params[j] = params[j], params[i] })
		rng.Shuffle(len(fields), func(i, j int) { fields[i], fields[j] = fields[j], fields[i] })
	}
	object := func(pairs [][2]string, sep string) string {
		parts := make([]string, len(pairs))
		for i, p := range pairs {
			parts[i] = fmt.Sprintf("%q:%s%s", p[0], sep, p[1])
		}
		return "{" + strings.Join(parts, ","+sep) + "}"
	}
	sep := ""
	if shuffle {
		sep = " " // the same value with different white space
	}
	fields = append(fields, [2]string{"parameters", object(params, sep)})
	return json.RawMessage(object(fields, sep))
}

func newRules(rng *rand.Rand) []rule {
	rules := []rule{
		{typ: "pull_request", rulesetID: 1, params: [][2]string{
			{"dismiss_stale_reviews_on_push", "true"}, {"require_code_owner_review", "false"},
			{"require_last_push_approval", "false"}, {"required_approving_review_count", fmt.Sprint(rng.IntN(3))},
			{"required_review_thread_resolution", "true"},
		}},
		{typ: "required_status_checks", rulesetID: 1, params: [][2]string{
			{"required_status_checks", `[{"context":"ci"},{"context":"lint"}]`}, {"strict_required_status_checks_policy", "true"},
		}},
		{typ: "deletion", rulesetID: 1}, {typ: "non_fast_forward", rulesetID: 1},
		{typ: "required_linear_history", rulesetID: 2}, {typ: "required_signatures", rulesetID: 2},
	}
	return rules[:2+rng.IntN(len(rules)-1)]
}

const reportHeader = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active," +
	"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service," +
	"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service," +
	"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"

// iamUser is the generator's model of one IAM user.
type iamUser struct {
	name             string
	human            bool
	mfa              bool
	created          time.Time
	lastUsed         time.Time
	lastRegion, last string
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05+00:00") }

func (u iamUser) row(account string) string {
	arn := fmt.Sprintf("arn:aws:iam::%s:user/%s", account, u.name)
	if u.human {
		return fmt.Sprintf("%s,%s,%s,true,%s,%s,%s,%t,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
			u.name, arn, stamp(u.created), stamp(u.lastUsed), stamp(u.created), stamp(u.created.AddDate(0, 0, 365)), u.mfa)
	}
	return fmt.Sprintf("%s,%s,%s,false,N/A,N/A,N/A,false,true,%s,%s,%s,%s,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
		u.name, arn, stamp(u.created), stamp(u.created), stamp(u.lastUsed), u.lastRegion, u.last)
}

// generate builds the dataset's observations, in collection order.
func (d Dataset) generate() ([]observation, error) {
	rng := rand.New(rand.NewPCG(d.Seed, d.Seed^0x9e3779b97f4a7c15)) //nolint:gosec // a seeded generator is the point: the dataset must be reproducible
	var out []observation
	add := func(kind string, raw []byte, asOf time.Time) error {
		normalized, err := normalize(kind, raw)
		if err != nil {
			return fmt.Errorf("normalize %s: %w", kind, err)
		}
		expected, err := evaluate(kind, normalized, asOf)
		if err != nil {
			return fmt.Errorf("evaluate %s: %w", kind, err)
		}
		out = append(out, observation{kind: kind, raw: raw, normalized: normalized, asOf: asOf, expected: expected})
		return nil
	}

	repos := make([][]rule, d.Repositories)
	for i := range repos {
		repos[i] = newRules(rng)
	}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
	services := []string{"s3", "sts", "ec2", "iam"}
	accounts := make([][]iamUser, d.BusyAccounts+d.QuietAccounts)
	for a := range accounts {
		for u := range d.UsersPerAcct {
			accounts[a] = append(accounts[a], iamUser{
				name: fmt.Sprintf("synthetic-user-%02d", u), human: u%3 == 0, mfa: u%6 == 0,
				created: start.AddDate(0, 0, -30-rng.IntN(300)), lastUsed: start.AddDate(0, 0, -1-rng.IntN(20)),
				lastRegion: regions[rng.IntN(len(regions))], last: services[rng.IntN(len(services))],
			})
		}
	}

	for day := range d.Days {
		at := start.AddDate(0, 0, day)
		for i, rules := range repos {
			if rng.Float64() < d.RuleChangeChance {
				// The approval count on the pull-request rule changes.
				rules[0].params[3][1] = fmt.Sprint(rng.IntN(3))
			}
			repo := fmt.Sprintf("synthetic-org/repo-%02d", i)
			shuffle := rng.Float64() < d.ReorderChance
			encoded := make([]json.RawMessage, len(rules))
			for j, r := range rules {
				encoded[j] = r.encode(repo, rng, shuffle)
			}
			if shuffle {
				rng.Shuffle(len(encoded), func(a, b int) { encoded[a], encoded[b] = encoded[b], encoded[a] })
			}
			raw, err := json.Marshal(rawRules{Repository: repo, DefaultBranch: "main", Protected: true, Rules: encoded})
			if err != nil {
				return nil, err
			}
			if err := add(github.BranchRulesKind, raw, at); err != nil {
				return nil, err
			}
		}
		for a, users := range accounts {
			busy := a < d.BusyAccounts
			if busy || rng.Float64() < d.QuietUseChance {
				// One to three credentials are used today.
				for range 1 + rng.IntN(3) {
					u := &users[rng.IntN(len(users))]
					u.lastUsed = at.Add(-time.Duration(rng.IntN(20*3600)) * time.Second)
					u.lastRegion, u.last = regions[rng.IntN(len(regions))], services[rng.IntN(len(services))]
				}
			}
			account := fmt.Sprintf("%012d", a+1)
			var b strings.Builder
			b.WriteString(reportHeader + "\n")
			fmt.Fprintf(&b, "<root_account>,arn:aws:iam::%s:root,%s,not_supported,no_information,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n",
				account, stamp(start.AddDate(-2, 0, 0)))
			for _, u := range users {
				b.WriteString(u.row(account) + "\n")
			}
			raw, err := json.Marshal(rawCredentials{Account: account, ReportCSV: b.String(), Summary: map[string]int32{
				"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, "Users": int32(d.UsersPerAcct), "Policies": 14, "Roles": 9, "Groups": 2,
			}})
			if err != nil {
				return nil, err
			}
			// The report was generated shortly before it was collected.
			if err := add(aws.IAMCredentialsKind, raw, at.Add(-20*time.Minute)); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// Strategy is one way of storing the dataset.
type Strategy string

// The three strategies compared.
const (
	NoDedup        Strategy = "No deduplication"
	RawHash        Strategy = "Raw-byte hash"
	NormalizedHash Strategy = "Normalized hash"
)

// Strategies lists the strategies in the order they are reported.
var Strategies = []Strategy{NoDedup, RawHash, NormalizedHash}

// Measurement is what one strategy cost for one kind of evidence, or for all.
type Measurement struct {
	Observations int
	// Payloads is how many distinct payloads were stored, and Bytes their
	// total size.
	Payloads int
	Bytes    int64
	// MedianRead and P95Read are the times to read back and verify one
	// observation's payload.
	MedianRead time.Duration
	P95Read    time.Duration
	// Reproduced is how many observations gave the result and explanation
	// recorded at collection when their checks were re-applied to what was
	// read back.
	Reproduced int
}

// Result is the study's outcome.
type Result struct {
	Dataset Dataset
	// ByKind holds each strategy's measurement per kind of evidence, and
	// Total across both.
	ByKind map[Strategy]map[string]Measurement
	Total  map[Strategy]Measurement
	// RawBytes and NormalizedBytes are the dataset's size before storage.
	RawBytes        map[string]int64
	NormalizedBytes map[string]int64
}

// Kinds lists the kinds of evidence in the dataset, in report order.
var Kinds = []string{github.BranchRulesKind, aws.IAMCredentialsKind}

// Run generates the dataset, stores it under each strategy in a fresh
// directory beneath dir, reads every observation back, and measures.
func Run(d Dataset, dir string) (*Result, error) {
	observations, err := d.generate()
	if err != nil {
		return nil, err
	}
	res := &Result{
		Dataset: d, ByKind: map[Strategy]map[string]Measurement{}, Total: map[Strategy]Measurement{},
		RawBytes: map[string]int64{}, NormalizedBytes: map[string]int64{},
	}
	for _, o := range observations {
		res.RawBytes[o.kind] += int64(len(o.raw))
		res.NormalizedBytes[o.kind] += int64(len(o.normalized))
	}
	ctx := context.Background()

	for n, strategy := range Strategies {
		root := filepath.Join(dir, fmt.Sprintf("strategy-%d", n))
		store, err := evidence.NewFS(root)
		if err != nil {
			return nil, err
		}
		// refs[i] is where observation i's payload was stored.
		refs := make([]string, len(observations))
		stored := map[string]map[string]int64{} // kind -> ref -> size
		for _, k := range Kinds {
			stored[k] = map[string]int64{}
		}
		for i, o := range observations {
			data := o.raw
			if strategy == NormalizedHash {
				data = o.normalized
			}
			if strategy == NoDedup {
				// One file per observation, whatever it holds.
				refs[i] = filepath.Join(root, fmt.Sprintf("%03d", i%512), fmt.Sprintf("%08d", i))
				if err := os.MkdirAll(filepath.Dir(refs[i]), 0o750); err != nil {
					return nil, err
				}
				if err := os.WriteFile(refs[i], data, 0o600); err != nil {
					return nil, err
				}
			} else if refs[i], _, err = store.Put(ctx, data); err != nil {
				return nil, err
			}
			stored[o.kind][refs[i]] = int64(len(data))
		}

		// Read every observation back once, in a fixed shuffled order.
		order := rand.New(rand.NewPCG(d.Seed, 7)).Perm(len(observations)) //nolint:gosec // a fixed read order, not a secret
		times := map[string][]time.Duration{}
		reproduced := map[string]int{}
		for _, i := range order {
			o := observations[i]
			begin := time.Now()
			var data []byte
			if strategy == NoDedup {
				data, err = os.ReadFile(refs[i])
				// Verify, as the hashed strategies do on every read.
				_ = sha256.Sum256(data)
			} else {
				data, err = store.Get(ctx, refs[i])
			}
			times[o.kind] = append(times[o.kind], time.Since(begin))
			if err != nil {
				return nil, err
			}
			// Raw payloads must be normalized again before a check can read them.
			if strategy != NormalizedHash {
				if data, err = normalize(o.kind, data); err != nil {
					return nil, err
				}
			}
			got, err := evaluate(o.kind, data, o.asOf)
			if err != nil {
				return nil, err
			}
			if slices.Equal(got, o.expected) {
				reproduced[o.kind]++
			}
		}

		res.ByKind[strategy] = map[string]Measurement{}
		var all []time.Duration
		total := Measurement{}
		for _, k := range Kinds {
			m := Measurement{Observations: len(times[k]), Payloads: len(stored[k]), Reproduced: reproduced[k]}
			for _, size := range stored[k] {
				m.Bytes += size
			}
			m.MedianRead, m.P95Read = percentile(times[k], 50), percentile(times[k], 95)
			res.ByKind[strategy][k] = m
			total.Observations += m.Observations
			total.Payloads += m.Payloads
			total.Bytes += m.Bytes
			total.Reproduced += m.Reproduced
			all = append(all, times[k]...)
		}
		total.MedianRead, total.P95Read = percentile(all, 50), percentile(all, 95)
		res.Total[strategy] = total
	}
	return res, nil
}

func percentile(times []time.Duration, p int) time.Duration {
	if len(times) == 0 {
		return 0
	}
	sorted := slices.Clone(times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[min(len(sorted)-1, len(sorted)*p/100)]
}

// Fingerprint is a hash of everything in the result that does not depend on
// the machine: the dataset and every count and byte total, but no timing.
func (r *Result) Fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "%+v\n", r.Dataset)
	for _, s := range Strategies {
		for _, k := range Kinds {
			m := r.ByKind[s][k]
			fmt.Fprintf(h, "%s %s %d %d %d %d\n", s, k, m.Observations, m.Payloads, m.Bytes, m.Reproduced)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Hardware describes the machine in a line, as far as it can be read.
func Hardware() string {
	cpu := ""
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			cpu = strings.TrimSpace(string(out))
		}
	case "linux":
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if name, ok := strings.CutPrefix(line, "model name"); ok {
					cpu = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), ":"))
					break
				}
			}
		}
	}
	if cpu == "" {
		cpu = "CPU model not read"
	}
	return fmt.Sprintf("%s, %d logical CPUs, %s/%s, %s", cpu, runtime.NumCPU(), runtime.GOOS, runtime.GOARCH, runtime.Version())
}
