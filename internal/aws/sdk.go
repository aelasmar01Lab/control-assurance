package aws

import (
	"context"
	"errors"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/aelasmar01Lab/control-assurance/internal/collect"
)

// SDK implements API with the AWS SDK. It uses the SDK's standard
// credential chain, so AWS_PROFILE and AWS_REGION select the role and Region.
type SDK struct {
	region  string
	sts     *sts.Client
	iam     *iam.Client
	trail   *cloudtrail.Client
	bedrock *bedrock.Client
}

// NewSDK loads the shared AWS configuration. It makes no AWS call.
func NewSDK(ctx context.Context) (*SDK, error) {
	// The SDK's own retries are turned off: the job queue decides when to
	// try again, and records each attempt.
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(1))
	if err != nil {
		return nil, Classify("load AWS configuration", err)
	}
	if cfg.Region == "" {
		return nil, &collect.Error{Class: collect.Auth, Detail: "no AWS Region is configured; set AWS_REGION or a profile with a region"}
	}
	return &SDK{
		region: cfg.Region, sts: sts.NewFromConfig(cfg), iam: iam.NewFromConfig(cfg),
		trail: cloudtrail.NewFromConfig(cfg), bedrock: bedrock.NewFromConfig(cfg),
	}, nil
}

// Region is the Region the regional calls are made in.
func (s *SDK) Region() string { return s.region }

// AccountID returns the account the credentials belong to.
func (s *SDK) AccountID(ctx context.Context) (string, error) {
	out, err := s.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", Classify("sts:GetCallerIdentity", err)
	}
	return awssdk.ToString(out.Account), nil
}

// GenerateCredentialReport asks IAM for a report and says whether it is ready.
func (s *SDK) GenerateCredentialReport(ctx context.Context) (bool, error) {
	out, err := s.iam.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
	if err != nil {
		return false, Classify("iam:GenerateCredentialReport", err)
	}
	return out.State == iamtypes.ReportStateTypeComplete, nil
}

// CredentialReport returns the report as CSV and when IAM generated it.
func (s *SDK) CredentialReport(ctx context.Context) ([]byte, time.Time, error) {
	out, err := s.iam.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, time.Time{}, Classify("iam:GetCredentialReport", err)
	}
	return out.Content, awssdk.ToTime(out.GeneratedTime), nil
}

// AccountSummary returns IAM's account summary counters.
func (s *SDK) AccountSummary(ctx context.Context) (map[string]int32, error) {
	out, err := s.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, Classify("iam:GetAccountSummary", err)
	}
	return out.SummaryMap, nil
}

// Trails describes the trails visible in the Region, including the shadow
// of a multi-Region trail whose home is elsewhere.
func (s *SDK) Trails(ctx context.Context) ([]Trail, error) {
	out, err := s.trail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, Classify("cloudtrail:DescribeTrails", err)
	}
	trails := make([]Trail, 0, len(out.TrailList))
	for _, t := range out.TrailList {
		trails = append(trails, Trail{
			Name: awssdk.ToString(t.Name), ARN: awssdk.ToString(t.TrailARN), HomeRegion: awssdk.ToString(t.HomeRegion),
			MultiRegion:       awssdk.ToBool(t.IsMultiRegionTrail),
			LogFileValidation: awssdk.ToBool(t.LogFileValidationEnabled),
			OrganizationTrail: awssdk.ToBool(t.IsOrganizationTrail),
		})
	}
	return trails, nil
}

// TrailLogging reports whether the trail is currently logging.
func (s *SDK) TrailLogging(ctx context.Context, arn string) (bool, error) {
	out, err := s.trail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: &arn})
	if err != nil {
		return false, Classify("cloudtrail:GetTrailStatus", err)
	}
	return awssdk.ToBool(out.IsLogging), nil
}

// BedrockLogging returns the model invocation logging destinations.
func (s *SDK) BedrockLogging(ctx context.Context) (string, string, error) {
	out, err := s.bedrock.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
	if err != nil {
		return "", "", Classify("bedrock:GetModelInvocationLoggingConfiguration", err)
	}
	var bucket, group string
	if cfg := out.LoggingConfig; cfg != nil {
		if cfg.S3Config != nil {
			bucket = awssdk.ToString(cfg.S3Config.BucketName)
		}
		if cfg.CloudWatchConfig != nil {
			group = awssdk.ToString(cfg.CloudWatchConfig.LogGroupName)
		}
	}
	return bucket, group, nil
}

// errorCodes maps the AWS error codes the collector expects to a class.
var errorCodes = map[string]collect.Class{
	"ExpiredToken":                   collect.Auth,
	"ExpiredTokenException":          collect.Auth,
	"InvalidClientTokenId":           collect.Auth,
	"UnrecognizedClientException":    collect.Auth,
	"SignatureDoesNotMatch":          collect.Auth,
	"InvalidSignatureException":      collect.Auth,
	"IncompleteSignature":            collect.Auth,
	"MissingAuthenticationToken":     collect.Auth,
	"AuthFailure":                    collect.Auth,
	"RequestExpired":                 collect.Auth,
	"AccessDenied":                   collect.Permission,
	"AccessDeniedException":          collect.Permission,
	"UnauthorizedOperation":          collect.Permission,
	"Throttling":                     collect.RateLimited,
	"ThrottlingException":            collect.RateLimited,
	"ThrottledException":             collect.RateLimited,
	"TooManyRequestsException":       collect.RateLimited,
	"RequestLimitExceeded":           collect.RateLimited,
	"LimitExceeded":                  collect.RateLimited,
	"NoSuchEntity":                   collect.NotFound,
	"TrailNotFoundException":         collect.NotFound,
	"ResourceNotFoundException":      collect.NotFound,
	"InternalFailure":                collect.Server,
	"InternalServerException":        collect.Server,
	"ServiceFailure":                 collect.Server,
	"ServiceUnavailable":             collect.Server,
	"ServiceUnavailableException":    collect.Server,
	"CloudTrailInternalServerError":  collect.Server,
	"OperationNotPermittedException": collect.Permission,
}

// Classify turns an AWS SDK error into a classified collection error. The
// detail names the operation and the error code, never the request.
func Classify(operation string, err error) *collect.Error {
	var ce *collect.Error
	if errors.As(err, &ce) {
		return ce
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		class, known := errorCodes[api.ErrorCode()]
		switch {
		case known:
		case api.ErrorFault() == smithy.FaultServer:
			class = collect.Server
		default:
			class = collect.Unexpected
		}
		return &collect.Error{Class: class, Detail: operation + ": " + api.ErrorCode()}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &collect.Error{Class: collect.Network, Detail: operation + ": the request timed out or was stopped"}
	}
	var de *smithy.DeserializationError
	if errors.As(err, &de) {
		return &collect.Error{Class: collect.Malformed, Detail: operation + ": the response could not be decoded"}
	}
	// No AWS service answered. Either no credentials could be found or
	// refreshed, or the request never reached the service.
	if msg := err.Error(); strings.Contains(msg, "credentials") || strings.Contains(msg, "shared config profile") {
		return &collect.Error{Class: collect.Auth, Detail: operation + ": no usable AWS credentials"}
	}
	return &collect.Error{Class: collect.Network, Detail: operation + ": the request did not reach AWS"}
}
