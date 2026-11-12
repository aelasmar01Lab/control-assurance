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
	"strings"
	"time"
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

// ErrorClass says why a collection attempt failed. It is recorded on the run
// and never becomes a check result.
type ErrorClass string

// The error classes a GitHub collection can end in.
const (
	ClassAuth        ErrorClass = "auth"               // credential missing, invalid or expired
	ClassPermission  ErrorClass = "permission"         // credential valid but not allowed to read this
	ClassRateLimited ErrorClass = "rate_limited"       // primary or secondary rate limit
	ClassNotFound    ErrorClass = "not_found"          // repository or branch does not exist, or is hidden
	ClassNetwork     ErrorClass = "network"            // no usable HTTP response
	ClassServer      ErrorClass = "server"             // GitHub returned a 5xx
	ClassMalformed   ErrorClass = "malformed_response" // response was not the expected JSON
	ClassUnexpected  ErrorClass = "unexpected_status"  // any other non-success status
)

// Error is a classified collection failure.
type Error struct {
	Class  ErrorClass
	Detail string
}

func (e *Error) Error() string { return string(e.Class) + ": " + e.Detail }

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
	if !ValidRepository(repo) {
		return nil, &Error{Class: ClassNotFound, Detail: fmt.Sprintf("%q is not an owner/name repository", repo)}
	}

	var repository struct {
		DefaultBranch string `json:"default_branch"`
	}
	if _, err := c.get(ctx, "/repos/"+repo, &repository); err != nil {
		return nil, err
	}
	if repository.DefaultBranch == "" {
		return nil, &Error{Class: ClassMalformed, Detail: "repository response has no default_branch"}
	}
	branchPath := "/repos/" + repo + "/branches/" + url.PathEscape(repository.DefaultBranch)

	var branch struct {
		Protected bool `json:"protected"`
	}
	if _, err := c.get(ctx, branchPath, &branch); err != nil {
		return nil, err
	}

	out := &BranchRules{
		Repository:      repo,
		DefaultBranch:   repository.DefaultBranch,
		BranchProtected: branch.Protected,
		RulesComplete:   true,
		Rules:           []Rule{},
	}

	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	next := fmt.Sprintf("/repos/%s/rules/branches/%s?per_page=%d",
		repo, url.PathEscape(repository.DefaultBranch), pageSize)
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

	for i := range out.Rules {
		canonical, err := canonicalJSON(out.Rules[i].Parameters)
		if err != nil {
			return nil, &Error{Class: ClassMalformed, Detail: "rule parameters are not valid JSON"}
		}
		out.Rules[i].Parameters = canonical
	}
	sort.SliceStable(out.Rules, func(i, j int) bool {
		a, b := out.Rules[i], out.Rules[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.RulesetID < b.RulesetID
	})
	return out, nil
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

// get fetches pathOrURL, decodes the JSON body into dst, and returns the URL
// of the next page if the response names one.
func (c *Client) get(ctx context.Context, pathOrURL string, dst any) (next string, err error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	target := pathOrURL
	if strings.HasPrefix(pathOrURL, "/") {
		target = base + pathOrURL
	} else if !strings.HasPrefix(pathOrURL, base+"/") {
		// A next-page link must stay on the API host the token was meant for.
		return "", &Error{Class: ClassMalformed, Detail: "next-page link points outside the API host"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", &Error{Class: ClassNetwork, Detail: "could not build request"}
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
		return "", &Error{Class: ClassNetwork, Detail: detail}
	}
	defer func() { _ = resp.Body.Close() }()

	path := req.URL.Path
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Class: classify(resp), Detail: fmt.Sprintf("GET %s returned %d", path, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return "", &Error{Class: ClassNetwork, Detail: fmt.Sprintf("GET %s: response body could not be read", path)}
	}
	if len(body) > maxBodyBytes {
		return "", &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response larger than %d bytes", path, maxBodyBytes)}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return "", &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response is not the expected JSON", path)}
	}
	return nextLink(resp.Header.Get("Link")), nil
}

func classify(resp *http.Response) ErrorClass {
	switch code := resp.StatusCode; {
	case code == http.StatusUnauthorized:
		return ClassAuth
	case code == http.StatusForbidden || code == http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "" ||
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

var nextLinkPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts the rel="next" URL from a Link header, or "".
func nextLink(header string) string {
	m := nextLinkPattern.FindStringSubmatch(header)
	if m == nil {
		return ""
	}
	return m[1]
}
