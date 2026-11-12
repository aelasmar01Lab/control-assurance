package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	// SecurityPolicyKind names the observation CollectSecurityPolicy produces.
	SecurityPolicyKind = "github.security_policy"
	// SecurityPolicyNormalizer versions the shape of the SecurityPolicy payload.
	SecurityPolicyNormalizer = "github.security_policy/1"
)

// SecurityPolicyPaths are the places GitHub looks for a repository's
// security policy, in the order they are checked.
var SecurityPolicyPaths = []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}

// PolicyFile is a security policy file that exists on the default branch.
type PolicyFile struct {
	Path string `json:"path"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

// SecurityPolicy is the normalized evidence for whether a repository
// publishes a security policy file.
type SecurityPolicy struct {
	Repository    string       `json:"repository"`
	DefaultBranch string       `json:"default_branch"`
	PathsChecked  []string     `json:"paths_checked"`
	Found         []PolicyFile `json:"found"`
}

// CollectSecurityPolicy looks for a security policy file at each standard
// path on repo's default branch. It reads file metadata only, not content.
func (c *Client) CollectSecurityPolicy(ctx context.Context, repo string) (*SecurityPolicy, error) {
	branch, err := c.defaultBranch(ctx, repo)
	if err != nil {
		return nil, err
	}
	out := &SecurityPolicy{Repository: repo, DefaultBranch: branch, PathsChecked: SecurityPolicyPaths, Found: []PolicyFile{}}
	for _, path := range SecurityPolicyPaths {
		resp, err := c.fetch(ctx, "/repos/"+repo+"/contents/"+path)
		if err != nil {
			return nil, err
		}
		if resp.status == http.StatusNotFound {
			// The repository was just read, so this 404 is about the file.
			continue
		}
		if resp.status != http.StatusOK {
			return nil, resp.failure()
		}
		var file struct {
			Type string `json:"type"`
			Path string `json:"path"`
			SHA  string `json:"sha"`
			Size int64  `json:"size"`
		}
		if err := json.Unmarshal(resp.body, &file); err != nil {
			// A directory at this path is listed as an array: not a policy file.
			var listing []json.RawMessage
			if json.Unmarshal(resp.body, &listing) == nil {
				continue
			}
			return nil, &Error{Class: ClassMalformed, Detail: fmt.Sprintf("GET %s: response is not the expected JSON", resp.path)}
		}
		if file.Type != "file" {
			continue
		}
		out.Found = append(out.Found, PolicyFile{Path: path, SHA: file.SHA, Size: file.Size})
	}
	return out, nil
}
