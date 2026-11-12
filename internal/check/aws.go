package check

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
)

const (
	credentialSource     = "AWS IAM: the credential report (`GenerateCredentialReport`, `GetCredentialReport`) and `GetAccountSummary`" //nolint:gosec // documentation text, not a credential
	credentialPermission = "`iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:GetAccountSummary`"                         //nolint:gosec // IAM action names, not a credential
	reportAge            = "IAM may serve a report up to four hours old; ages are measured to the report's generation time."
)

// unusedThreshold is how long a credential may go unused before AWS-02
// fails. It is this project's policy choice, not a framework figure, and
// changing it means a new check version.
const unusedThreshold = 90 * 24 * time.Hour

var aws01 = Check{
	Key:              "AWS-01",
	Version:          "1",
	ObservationKind:  aws.IAMCredentialsKind,
	Assertion:        "Every IAM user with a console password has MFA, and so does the root user.",
	Source:           credentialSource,
	Permission:       credentialPermission,
	Establishes:      "The MFA state of IAM users and of root when the credential report was generated.",
	DoesNotEstablish: "Anything about federated or IAM Identity Center users, or the strength of the factor.",
	Control:          "Human access",
	Mapping:          "MVSP 4.2, partial.",
	Eval:             evalAWS01,
}

var aws02 = Check{
	Key:              "AWS-02",
	Version:          "1",
	ObservationKind:  aws.IAMCredentialsKind,
	Assertion:        "No IAM console password or active access key has gone unused for more than 90 days, and root has no access keys.",
	Source:           credentialSource,
	Permission:       credentialPermission,
	Establishes:      "Last-use dates of IAM passwords and access keys when the credential report was generated.",
	DoesNotEstablish: "Whether the access is still needed, or anything about roles and federated sessions.",
	Control:          "Credential lifecycle",
	Mapping:          "MVSP 4.2, partial. The 90 day threshold is a policy choice, not a framework figure.",
	Eval:             evalAWS02,
}

func decodeCredentials(payload []byte) (*aws.IAMCredentials, error) {
	var c aws.IAMCredentials
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", aws.IAMCredentialsKind, err)
	}
	if c.AccountID == "" {
		return nil, fmt.Errorf("%s payload has no account", aws.IAMCredentialsKind)
	}
	return &c, nil
}

// list joins names for an explanation, naming at most five.
func list(names []string) string {
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}

func evalAWS01(in Input) (Result, string, error) {
	c, err := decodeCredentials(in.Payload)
	if err != nil {
		return "", "", err
	}
	var without []string
	withPassword := 0
	for _, u := range c.Users {
		if u.Root || !u.PasswordEnabled {
			continue
		}
		withPassword++
		if !u.MFAActive {
			without = append(without, u.Name)
		}
	}
	var problems []string
	if !c.RootMFAEnabled {
		problems = append(problems, "the root user has no MFA")
	}
	if len(without) > 0 {
		problems = append(problems, fmt.Sprintf("%d IAM user(s) have a console password and no MFA: %s", len(without), list(without)))
	}
	if len(problems) > 0 {
		return Fail, fmt.Sprintf("In account %s, %s. %s", c.AccountID, strings.Join(problems, "; "), reportAge), nil
	}
	return Pass, fmt.Sprintf("In account %s the root user has MFA, and all %d IAM user(s) with a console password have MFA. %s",
		c.AccountID, withPassword, reportAge), nil
}

// lastActivity returns the newest of the times that are set.
func lastActivity(times ...*time.Time) *time.Time {
	var newest *time.Time
	for _, t := range times {
		if t != nil && (newest == nil || t.After(*newest)) {
			newest = t
		}
	}
	return newest
}

func evalAWS02(in Input) (Result, string, error) {
	c, err := decodeCredentials(in.Payload)
	if err != nil {
		return "", "", err
	}
	// unused describes a credential idle past the threshold, or "" if it is not.
	unused := func(what string, last *time.Time) string {
		if last == nil {
			return what + " has no recorded use or creation date"
		}
		if idle := in.AsOf.Sub(*last); idle > unusedThreshold {
			return fmt.Sprintf("%s idle %d days", what, int(idle.Hours()/24))
		}
		return ""
	}
	var stale []string
	judged := 0
	for _, u := range c.Users {
		if u.Root {
			continue
		}
		if u.PasswordEnabled {
			judged++
			// A password never used is measured from when it was set.
			if s := unused(u.Name+" password", lastActivity(u.PasswordLastUsed, u.PasswordLastChanged, u.Created)); s != "" {
				stale = append(stale, s)
			}
		}
		for _, k := range u.AccessKeys {
			if !k.Active {
				continue
			}
			judged++
			// A key never used is measured from when it was created or rotated.
			if s := unused(fmt.Sprintf("%s access key %d", u.Name, k.Slot), lastActivity(k.LastUsed, k.LastRotated)); s != "" {
				stale = append(stale, s)
			}
		}
	}
	var problems []string
	if c.RootAccessKeysPresent {
		problems = append(problems, "the root user has access keys")
	}
	if len(stale) > 0 {
		problems = append(problems, fmt.Sprintf("%d credential(s) unused for more than 90 days: %s", len(stale), list(stale)))
	}
	if len(problems) > 0 {
		return Fail, fmt.Sprintf("In account %s, %s. %s", c.AccountID, strings.Join(problems, "; "), reportAge), nil
	}
	return Pass, fmt.Sprintf("In account %s the root user has no access keys, and none of %d IAM password(s) and active access key(s) has gone unused for more than 90 days. %s",
		c.AccountID, judged, reportAge), nil
}

var aws03 = Check{
	Key:              "AWS-03",
	Version:          "1",
	ObservationKind:  aws.TrailsKind,
	Assertion:        "A multi-Region CloudTrail trail is logging, with log file validation on.",
	Source:           "AWS CloudTrail: `DescribeTrails` and `GetTrailStatus`",
	Permission:       "`cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`",
	Establishes:      "At collection time a trail covering every Region was recording, and its log files are tamper-evident.",
	DoesNotEstablish: "The application logging MVSP 2.7 describes, which events the trail selects, retention, or that anyone reads the logs.",
	Control:          "Audit logging",
	Mapping:          "MVSP 2.7, supporting.",
	Eval:             evalAWS03,
}

func evalAWS03(in Input) (Result, string, error) {
	var t aws.Trails
	if err := json.Unmarshal(in.Payload, &t); err != nil {
		return "", "", fmt.Errorf("decode %s payload: %w", aws.TrailsKind, err)
	}
	if t.AccountID == "" {
		return "", "", fmt.Errorf("%s payload has no account", aws.TrailsKind)
	}
	var unreadable, shortfalls []string
	for _, trail := range t.Trails {
		switch {
		case !trail.MultiRegion:
			shortfalls = append(shortfalls, trail.Name+" covers one Region only")
		case !trail.LogFileValidation:
			shortfalls = append(shortfalls, trail.Name+" has log file validation off")
		case !trail.StatusReadable:
			unreadable = append(unreadable, trail.Name)
		case !trail.Logging:
			shortfalls = append(shortfalls, trail.Name+" is not logging")
		default:
			return Pass, fmt.Sprintf("Trail %s in account %s is multi-Region, is logging, and has log file validation on (read from %s).",
				trail.Name, t.AccountID, t.Region), nil
		}
	}
	switch {
	case len(unreadable) > 0:
		return NotEvaluated, fmt.Sprintf(
			"Account %s has a multi-Region trail with validation on (%s), but this credential was refused its status, so whether it is logging is unknown.",
			t.AccountID, list(unreadable)), nil
	case len(t.Trails) == 0:
		return Fail, fmt.Sprintf("Account %s has no CloudTrail trail visible from %s.", t.AccountID, t.Region), nil
	default:
		return Fail, fmt.Sprintf("No trail in account %s is multi-Region, logging and validated: %s.", t.AccountID, list(shortfalls)), nil
	}
}

var aws04 = Check{
	Key:              "AWS-04",
	Version:          "1",
	ObservationKind:  aws.BedrockLoggingKind,
	Assertion:        "Bedrock model invocation logging has a destination configured in the lab Region.",
	Source:           "AWS Bedrock: `GetModelInvocationLoggingConfiguration`",
	Permission:       "`bedrock:GetModelInvocationLoggingConfiguration`",
	Establishes:      "A logging destination was configured in that Region at collection time.",
	DoesNotEstablish: "That the account uses Bedrock, the quality or retention of the logs, anything about other Regions, or any guardrail.",
	Control:          "AI usage logging",
	Mapping:          "No MVSP requirement. Intended for a NIST AI RMF mapping in a later release.",
	Eval:             evalAWS04,
}

func evalAWS04(in Input) (Result, string, error) {
	var b aws.BedrockLogging
	if err := json.Unmarshal(in.Payload, &b); err != nil {
		return "", "", fmt.Errorf("decode %s payload: %w", aws.BedrockLoggingKind, err)
	}
	if b.AccountID == "" || b.Region == "" {
		return "", "", fmt.Errorf("%s payload has no account or Region", aws.BedrockLoggingKind)
	}
	var destinations []string
	if b.S3Bucket != "" {
		destinations = append(destinations, "S3 bucket "+b.S3Bucket)
	}
	if b.CloudWatchLogGroup != "" {
		destinations = append(destinations, "CloudWatch log group "+b.CloudWatchLogGroup)
	}
	if len(destinations) == 0 {
		return Fail, fmt.Sprintf("Bedrock model invocation logging has no destination configured in %s of account %s.", b.Region, b.AccountID), nil
	}
	return Pass, fmt.Sprintf("Bedrock model invocation logging in %s of account %s delivers to %s.",
		b.Region, b.AccountID, strings.Join(destinations, " and ")), nil
}
