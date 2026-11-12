// Package github reads evidence from the GitHub REST API. It is the only
// package that talks to GitHub, and it only reads.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/collect"
)

const (
	// APIVersion is the REST API version every request pins.
	APIVersion = "2026-03-10"

	// BranchRulesKind names the observation CollectBranchRules produces.
	BranchRulesKind = "github.branch_rules"
	// BranchRulesNormalizer versions the shape of the BranchRules payload.
	// Changing which fields are kept or how they are ordered means a new version.
	BranchRulesNormalizer = "github.branch_rules/1"

	defaultBaseURL  = "https://api.github.com"
	defaultMaxPages = 10
	pageSize        = 100
	maxBodyBytes    = 8 << 20
)

// ErrorClass says why a collection attempt failed. The classes are shared
// by every collector.
type ErrorClass = collect.Class

// The error classes a GitHub collection can end in.
const (
	ClassAuth        = collect.Auth
	ClassPermission  = collect.Permission
	ClassRateLimited = collect.RateLimited
	ClassNotFound    = collect.NotFound
	ClassNetwork     = collect.Network
	ClassServer      = collect.Server
	ClassMalformed   = collect.Malformed
	ClassUnexpected  = collect.Unexpected
)

// Error is a classified collection failure.
type Error = collect.Error

// Rule is one active rule that applies to a branch.
type Rule struct {
	Type              string          `json:"type"`
	RulesetID         int64           `json:"ruleset_id"`
	RulesetSource     string          `json:"ruleset_source"`
	RulesetSourceType string          `json:"ruleset_source_type"`
	Parameters        json.RawMessage `json:"parameters,omitempty"`
}

// BranchRules is the normalized evidence for the rules active on a
// repository's default branch at collection time.
type BranchRules struct {
	Repository    string `json:"repository"`
	DefaultBranch string `json:"default_branch"`
	// BranchProtected is GitHub's own "protected" flag for the branch. It can
	// be true when no rule is visible, for example under classic branch
	// protection, which this collector does not read.
	BranchProtected bool `json:"branch_protected"`
	// RulesComplete is false when the rule listing had more pages than were read.
	RulesComplete bool   `json:"rules_complete"`
	Rules         []Rule `json:"rules"`
}

// Payload returns the canonical bytes stored as evidence. The same branch
// state always yields the same bytes.
func (b *BranchRules) Payload() ([]byte, error) {
	return json.Marshal(b)
}

// Client is a read-only GitHub REST client.
type Client struct {
	// Token is sent as a bearer token when non-empty.
	Token string
	// BaseURL defaults to https://api.github.com.
	BaseURL string
	// HTTP defaults to a client with a 30 second timeout.
	HTTP *http.Client
	// MaxPages caps how many pages of a listing are read. Defaults to 10.
	MaxPages int
}

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ValidRepository reports whether s looks like "owner/name".
func ValidRepository(s string) bool { return repoPattern.MatchString(s) }

// CollectBranchRules reads the active rules on repo's default branch.
// repo is "owner/name". Any failure is returned as an *Error.
func (c *Client) CollectBranchRules(ctx context.Context, repo string) (*BranchRules, error) {
	defaultBranch, err := c.defaultBranch(ctx, repo)
	if err != nil {
		return nil, err
	}
	branchPath := "/repos/" + repo + "/branches/" + url.PathEscape(defaultBranch)

	var branch struct {
		Protected bool `json:"protected"`
	}
	if _, err := c.get(ctx, branchPath, &branch); err != nil {
		return nil, err
	}

	out := &BranchRules{
		Repository:      repo,
		DefaultBranch:   defaultBranch,
		BranchProtected: branch.Protected,
		RulesComplete:   true,
		Rules:           []Rule{},
	}

	maxPages := c.maxPages()
	next := fmt.Sprintf("/repos/%s/rules/branches/%s?per_page=%d",
		repo, url.PathEscape(defaultBranch), pageSize)
	for page := 1; next != ""; page++ {
		if page > maxPages {
			// More pages exist than this collector reads. Say so rather
			// than present a partial listing as the whole.
			out.RulesComplete = false
			break
		}
		var rules []Rule
		link, err := c.get(ctx, next, &rules)
		if err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, rules...)
		next = link
	}

	if err := out.normalize(); err != nil {
		return nil, err
	}
	return out, nil
}

// NormalizeBranchRules builds the evidence for a branch from rules as the
// API returned them. It keeps every field of every rule and drops none; it
// sorts the rules by type then ruleset, and re-encodes each rule's
// parameters with object keys sorted and insignificant white space removed.
func NormalizeBranchRules(repo, defaultBranch string, protected, complete bool, rules []Rule) (*BranchRules, error) {
	out := &BranchRules{
		Repository: repo, DefaultBranch: defaultBranch, BranchProtected: protected,
		RulesComplete: complete, Rules: append([]Rule{}, rules...),
	}
	if err := out.normalize(); err != nil {
		return nil, err
	}
	return out, nil
}

// normalize puts the rules into their canonical form and order.
func (b *BranchRules) normalize() error {
	for i := range b.Rules {
		canonical, err := canonicalJSON(b.Rules[i].Parameters)
		if err != nil {
			return &Error{Class: ClassMalformed, Detail: "rule parameters are not valid JSON"}
		}
		b.Rules[i].Parameters = canonical
	}
	sort.SliceStable(b.Rules, func(i, j int) bool {
		x, y := b.Rules[i], b.Rules[j]
		if x.Type != y.Type {
			return x.Type < y.Type
		}
		return x.RulesetID < y.RulesetID
	})
	return nil
}

// canonicalJSON re-encodes raw with object keys sorted, so equal values have
// equal bytes.
func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// response is what one GET returned.
type response struct {
	status int
	header http.Header
	body   []byte
	path   string
}

// message returns the "message" field of a GitHub error body, or "".
func (r *response) message() string {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Message
}

// failure turns a non-success response into a classified error.
func (r *response) failure() *Error {
	e := &Error{Class: classify(r.status, r.header), Detail: fmt.Sprintf("GET %s returned %d", r.path, r.status)}
	if e.Class == ClassRateLimited {
		e.RetryAfter = retryAfter(r.header, time.Now())
	}
	return e
}

// fetch performs one GET and returns the response whatever its status. Only
// a request that produced no usable response is an error.
func (c *Client) fetch(ctx context.Context, pathOrURL string) (*response, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	target := pathOrURL
	if strings.HasPrefix(pathOrURL, "/") {
		target = base + pathOrURL
	} else if !strings.HasPrefix(pathOrURL, base+"/") {
		// A next-page link must stay on the API host the token was meant for.
		return nil, &Error{Class: ClassMalformed, Detail: "next-page link points outside the API host"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, &Error{Class: ClassNetwork, Detail: "could not build request"}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", "control-assurance-collector")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		detail := "request failed"
		if errors.As(err, &urlErr) {
			// urlErr.Err omits the URL, and the token is never in the URL.
			detail = "request failed: " + urlErr.Err.Error()
		}
		return nil, &Error{Class: ClassNetwork, Detail: detail}
	}
	defer func() { _ = resp.Body.Close() }()

	path := req.URL.Path
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, &Error{Class: ClassNetwork, Detail: fmt.Sprintf("GET %s: response body could not be read", path)}
	}
	if len(body) > maxBodyBytes {
		return nil, &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response larger than %d bytes", path, maxBodyBytes)}
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: body, path: path}, nil
}

// get fetches pathOrURL, decodes the JSON body into dst, and returns the URL
// of the next page if the response names one.
func (c *Client) get(ctx context.Context, pathOrURL string, dst any) (next string, err error) {
	resp, err := c.fetch(ctx, pathOrURL)
	if err != nil {
		return "", err
	}
	if resp.status != http.StatusOK {
		return "", resp.failure()
	}
	if err := json.Unmarshal(resp.body, dst); err != nil {
		return "", &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response is not the expected JSON", resp.path)}
	}
	return nextLink(resp.header.Get("Link")), nil
}

func classify(code int, header http.Header) ErrorClass {
	switch {
	case code == http.StatusUnauthorized:
		return ClassAuth
	case code == http.StatusForbidden || code == http.StatusTooManyRequests:
		if header.Get("X-RateLimit-Remaining") == "0" || header.Get("Retry-After") != "" ||
			code == http.StatusTooManyRequests {
			return ClassRateLimited
		}
		return ClassPermission
	case code == http.StatusNotFound:
		return ClassNotFound
	case code >= 500:
		return ClassServer
	default:
		return ClassUnexpected
	}
}

// retryAfter reads how long GitHub asked the caller to wait: the Retry-After
// header in seconds, or failing that the time the rate limit resets.
func retryAfter(header http.Header, now time.Time) time.Duration {
	if secs, err := strconv.Atoi(header.Get("Retry-After")); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if epoch, err := strconv.ParseInt(header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if d := time.Unix(epoch, 0).Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// defaultBranch returns the name of repo's default branch. It is the first
// call of every collection, so a missing or hidden repository is reported
// the same way whatever is being collected.
func (c *Client) defaultBranch(ctx context.Context, repo string) (string, error) {
	if !ValidRepository(repo) {
		return "", &Error{Class: ClassNotFound, Detail: fmt.Sprintf("%q is not an owner/name repository", repo)}
	}
	var repository struct {
		DefaultBranch string `json:"default_branch"`
	}
	if _, err := c.get(ctx, "/repos/"+repo, &repository); err != nil {
		return "", err
	}
	if repository.DefaultBranch == "" {
		return "", &Error{Class: ClassMalformed, Detail: "repository response has no default_branch"}
	}
	return repository.DefaultBranch, nil
}

func (c *Client) maxPages() int {
	if c.MaxPages <= 0 {
		return defaultMaxPages
	}
	return c.MaxPages
}

// Collectors returns the client's collectors, keyed by the kind of
// observation each produces. The target of each is an "owner/name" repository.
func (c *Client) Collectors() map[string]func(ctx context.Context, repo string) (*collect.Snapshot, error) {
	return map[string]func(ctx context.Context, repo string) (*collect.Snapshot, error){
		BranchRulesKind: func(ctx context.Context, repo string) (*collect.Snapshot, error) {
			b, err := c.CollectBranchRules(ctx, repo)
			if err != nil {
				return nil, err
			}
			return snapshot(BranchRulesKind, BranchRulesNormalizer, b, b.RulesComplete)
		},
		AlertsKind: func(ctx context.Context, repo string) (*collect.Snapshot, error) {
			a, err := c.CollectAlerts(ctx, repo)
			if err != nil {
				return nil, err
			}
			return snapshot(AlertsKind, AlertsNormalizer, a, a.AlertsComplete)
		},
		SecurityPolicyKind: func(ctx context.Context, repo string) (*collect.Snapshot, error) {
			p, err := c.CollectSecurityPolicy(ctx, repo)
			if err != nil {
				return nil, err
			}
			return snapshot(SecurityPolicyKind, SecurityPolicyNormalizer, p, true)
		},
	}
}

// Kinds lists the kinds of observation collected from a repository.
var Kinds = []string{BranchRulesKind, AlertsKind, SecurityPolicyKind}

func snapshot(kind, normalizer string, v any, complete bool) (*collect.Snapshot, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, &Error{Class: collect.Storage, Detail: "evidence could not be encoded"}
	}
	return &collect.Snapshot{Kind: kind, Normalizer: normalizer, Payload: payload, Complete: complete}, nil
}

var nextLinkPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts the rel="next" URL from a Link header, or "".
func nextLink(header string) string {
	m := nextLinkPattern.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	return m[1]
}
