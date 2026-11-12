package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

// asOf is the moment the synthetic evidence below describes.
var asOf = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func daysAgo(n int) time.Time { return asOf.Add(-time.Duration(n) * 24 * time.Hour) }

func ptr(t time.Time) *time.Time { return &t }

func encode(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type checkCase struct {
	name        string
	key         string
	evidence    any
	want        Result
	wantExplain string
}

func runCases(t *testing.T, cases []checkCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := Lookup(tt.key, "1")
			if !ok {
				t.Fatalf("check %s version 1 not registered", tt.key)
			}
			in := Input{Payload: encode(t, tt.evidence), AsOf: asOf}
			got, explanation, err := c.Eval(in)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got != tt.want {
				t.Errorf("result = %s, want %s (%s)", got, tt.want, explanation)
			}
			if !strings.Contains(explanation, tt.wantExplain) {
				t.Errorf("explanation = %q, want it to contain %q", explanation, tt.wantExplain)
			}
			// The same input always gives the same answer.
			again, explanation2, _ := c.Eval(in)
			if again != got || explanation2 != explanation {
				t.Error("evaluating the same input twice gave different answers")
			}
		})
	}
}

func alerts(enabled, complete bool, list ...github.Alert) github.Alerts {
	if list == nil {
		list = []github.Alert{}
	}
	return github.Alerts{Repository: "lab-org/lab-repo", AlertsEnabled: enabled, AlertsComplete: complete, Alerts: list}
}

func alert(n int, severity string, ageDays int) github.Alert {
	return github.Alert{Number: n, Severity: severity, Package: "synthetic-package", Ecosystem: "npm", Advisory: "GHSA-fake", CreatedAt: daysAgo(ageDays)}
}

func TestGH03(t *testing.T) {
	runCases(t, []checkCase{
		{"no open alerts", "GH-03", alerts(true, true), Pass, "0 open alert(s)"},
		{"alerts within their deadlines", "GH-03", alerts(true, true, alert(1, "critical", 30), alert(2, "medium", 90)), Pass, "2 open alert(s)"},
		{"low severity is not judged", "GH-03", alerts(true, true, alert(1, "low", 400)), Pass, "1 low severity"},
		{"high past 30 days", "GH-03", alerts(true, true, alert(7, "high", 31)), Fail, "#7 high"},
		{"critical past 30 days", "GH-03", alerts(true, true, alert(8, "critical", 45)), Fail, "open 45 days"},
		{"medium past 90 days", "GH-03", alerts(true, true, alert(9, "medium", 91)), Fail, "deadline 90"},
		{"medium at 60 days is within deadline", "GH-03", alerts(true, true, alert(9, "medium", 60)), Pass, "none past its deadline"},
		{"unknown severity gets the short deadline", "GH-03", alerts(true, true, alert(3, "severe", 31)), Fail, "severity not recognised"},
		{"alerts turned off is not zero alerts", "GH-03", alerts(false, true), NotEvaluated, "not a count of zero"},
		{"truncated listing with nothing overdue", "GH-03", alerts(true, false, alert(1, "high", 2)), NotEvaluated, "Incomplete coverage"},
		{"truncated listing that includes an overdue alert", "GH-03", alerts(true, false, alert(1, "high", 40)), Fail, "#1 high"},
	})
}

func policy(found ...github.PolicyFile) github.SecurityPolicy {
	if found == nil {
		found = []github.PolicyFile{}
	}
	return github.SecurityPolicy{Repository: "lab-org/lab-repo", DefaultBranch: "main", PathsChecked: github.SecurityPolicyPaths, Found: found}
}

func TestGH04(t *testing.T) {
	runCases(t, []checkCase{
		{"policy at the root", "GH-04", policy(github.PolicyFile{Path: "SECURITY.md", SHA: "abc", Size: 300}), Pass, "SECURITY.md exists on main"},
		{"policy under .github", "GH-04", policy(github.PolicyFile{Path: ".github/SECURITY.md", SHA: "abc", Size: 10}), Pass, ".github/SECURITY.md"},
		{"pass says the content was not read", "GH-04", policy(github.PolicyFile{Path: "SECURITY.md", Size: 1}), Pass, "content was not read"},
		{"no policy file", "GH-04", policy(), Fail, "No non-empty security policy file"},
		{"an empty file is not a policy", "GH-04", policy(github.PolicyFile{Path: "SECURITY.md", Size: 0}), Fail, "exists but is empty"},
		{"fail names the organisation-level limit", "GH-04", policy(), Fail, ".github repository is not read"},
	})
}

func credentials(rootMFA, rootKeys bool, users ...aws.User) aws.IAMCredentials {
	all := []aws.User{{Name: "<root_account>", Root: true, MFAActive: rootMFA}}
	return aws.IAMCredentials{AccountID: "000000000000", RootMFAEnabled: rootMFA, RootAccessKeysPresent: rootKeys, Users: append(all, users...)}
}

func person(name string, mfa bool, lastUsedDays int) aws.User {
	return aws.User{Name: name, Created: ptr(daysAgo(400)), PasswordEnabled: true, MFAActive: mfa,
		PasswordLastUsed: ptr(daysAgo(lastUsedDays)), PasswordLastChanged: ptr(daysAgo(300))}
}

func machine(name string, usedDays, rotatedDays int) aws.User {
	key := aws.AccessKey{Slot: 1, Active: true, LastRotated: ptr(daysAgo(rotatedDays))}
	if usedDays >= 0 {
		key.LastUsed = ptr(daysAgo(usedDays))
	}
	return aws.User{Name: name, Created: ptr(daysAgo(400)), AccessKeys: []aws.AccessKey{key, {Slot: 2}}}
}

func TestAWS01(t *testing.T) {
	runCases(t, []checkCase{
		{"everyone has MFA", "AWS-01", credentials(true, false, person("ana", true, 1), machine("deploy", 1, 10)), Pass, "all 1 IAM user(s)"},
		{"no password users at all", "AWS-01", credentials(true, false, machine("deploy", 1, 10)), Pass, "all 0 IAM user(s)"},
		{"a password user without MFA", "AWS-01", credentials(true, false, person("ana", true, 1), person("ben", false, 1)), Fail, "ben"},
		{"root without MFA", "AWS-01", credentials(false, false, person("ana", true, 1)), Fail, "root user has no MFA"},
		{"both problems are named", "AWS-01", credentials(false, false, person("ben", false, 1)), Fail, "root user has no MFA; 1 IAM user(s)"},
		{"states the age of the report", "AWS-01", credentials(true, false), Pass, "up to four hours old"},
	})
}

func TestAWS02(t *testing.T) {
	neverUsedOld := aws.User{Name: "forgotten", Created: ptr(daysAgo(400)), PasswordEnabled: true, PasswordLastChanged: ptr(daysAgo(120))}
	neverUsedNew := aws.User{Name: "newcomer", Created: ptr(daysAgo(5)), PasswordEnabled: true, PasswordLastChanged: ptr(daysAgo(5))}
	inactiveKey := aws.User{Name: "retired", AccessKeys: []aws.AccessKey{{Slot: 1, Active: false, LastUsed: ptr(daysAgo(900))}}}
	runCases(t, []checkCase{
		{"everything in recent use", "AWS-02", credentials(true, false, person("ana", true, 3), machine("deploy", 10, 200)), Pass, "none of 2 IAM password(s)"},
		{"used exactly 90 days ago is within the threshold", "AWS-02", credentials(true, false, person("ana", true, 90)), Pass, ""},
		{"password idle 91 days", "AWS-02", credentials(true, false, person("ana", true, 91)), Fail, "ana password idle 91 days"},
		{"access key idle", "AWS-02", credentials(true, false, machine("deploy", 120, 300)), Fail, "deploy access key 1 idle 120 days"},
		{"key never used, created long ago", "AWS-02", credentials(true, false, machine("deploy", -1, 100)), Fail, "idle 100 days"},
		{"key never used, created recently", "AWS-02", credentials(true, false, machine("deploy", -1, 5)), Pass, ""},
		{"password never used, set long ago", "AWS-02", credentials(true, false, neverUsedOld), Fail, "forgotten password idle 120 days"},
		{"password never used, set recently", "AWS-02", credentials(true, false, neverUsedNew), Pass, ""},
		{"an inactive key is not judged", "AWS-02", credentials(true, false, inactiveKey), Pass, "none of 0"},
		{"root access keys", "AWS-02", credentials(true, true, person("ana", true, 3)), Fail, "root user has access keys"},
	})
}

func trails(list ...aws.Trail) aws.Trails {
	if list == nil {
		list = []aws.Trail{}
	}
	return aws.Trails{AccountID: "000000000000", Region: "us-east-1", Trails: list}
}

func TestAWS03(t *testing.T) {
	good := aws.Trail{Name: "main", ARN: "arn:synthetic:main", MultiRegion: true, LogFileValidation: true, StatusReadable: true, Logging: true}
	change := func(f func(*aws.Trail)) aws.Trail {
		t := good
		t.Name = "other"
		f(&t)
		return t
	}
	single := change(func(t *aws.Trail) { t.MultiRegion = false })
	unvalidated := change(func(t *aws.Trail) { t.LogFileValidation = false })
	stopped := change(func(t *aws.Trail) { t.Logging = false })
	unreadable := change(func(t *aws.Trail) { t.StatusReadable, t.Logging = false, false })
	runCases(t, []checkCase{
		{"a qualifying trail", "AWS-03", trails(good), Pass, "Trail main"},
		{"a qualifying trail among others", "AWS-03", trails(single, stopped, good), Pass, "Trail main"},
		{"no trails", "AWS-03", trails(), Fail, "no CloudTrail trail"},
		{"single-Region only", "AWS-03", trails(single), Fail, "covers one Region only"},
		{"validation off", "AWS-03", trails(unvalidated), Fail, "log file validation off"},
		{"not logging", "AWS-03", trails(stopped), Fail, "is not logging"},
		{"status refused", "AWS-03", trails(unreadable), NotEvaluated, "refused its status"},
		{"status refused on one, another qualifies", "AWS-03", trails(unreadable, good), Pass, "Trail main"},
		{"status refused on one, the other falls short", "AWS-03", trails(unreadable, stopped), NotEvaluated, "is unknown"},
	})
}

func TestAWS04(t *testing.T) {
	logging := func(bucket, group string) aws.BedrockLogging {
		return aws.BedrockLogging{AccountID: "000000000000", Region: "us-east-1", S3Bucket: bucket, CloudWatchLogGroup: group}
	}
	runCases(t, []checkCase{
		{"an S3 destination", "AWS-04", logging("synthetic-logs", ""), Pass, "S3 bucket synthetic-logs"},
		{"a CloudWatch destination", "AWS-04", logging("", "/synthetic/bedrock"), Pass, "CloudWatch log group /synthetic/bedrock"},
		{"both destinations", "AWS-04", logging("synthetic-logs", "/synthetic/bedrock"), Pass, " and "},
		{"nothing configured", "AWS-04", logging("", ""), Fail, "no destination configured in us-east-1"},
	})
}

// Every check states what a pass does not establish, and is tied to a control.
func TestEveryCheckStatesItsLimits(t *testing.T) {
	keys := map[string]bool{}
	for _, c := range All() {
		keys[c.Key] = true
		for name, v := range map[string]string{
			"assertion": c.Assertion, "source": c.Source, "permission": c.Permission,
			"establishes": c.Establishes, "does not establish": c.DoesNotEstablish, "control": c.Control, "mapping": c.Mapping,
		} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s has no %s", c.Key, name)
			}
		}
		if strings.Contains(strings.ToLower(c.Assertion+c.Establishes), "compliant") {
			t.Errorf("%s uses the word compliant", c.Key)
		}
	}
	for _, want := range []string{"GH-01", "GH-02", "GH-03", "GH-04", "AWS-01", "AWS-02", "AWS-03", "AWS-04", "REC-01"} {
		if !keys[want] {
			t.Errorf("check %s is not registered", want)
		}
	}
}
