# Verification scenarios

The maintainer's discovery document, kept outside the repository, lists
eleven scenarios the product must be verified against. This page names the
tests that assert each one. A test in `internal/assurance` checks that
every test named here exists. All data in these tests is synthetic.

"Already covered" means the tests existed before this page was written.
"Completed" means part of the expected behavior had no assertion, and a
test was added in `internal/assurance/scenarios_test.go`.

| # | Scenario | Expected behavior | Tests | Status |
| --- | --- | --- | --- | --- |
| 1 | The source data is valid and the assertion holds | The pass names the observation just collected, its stored bytes and the check version in force | `TestPassLinksToItsEvidenceAndCheckVersion`, `TestStoredEvaluationsReproduce`, `TestFailFindingPassLoop` | Completed |
| 2 | The assertion really fails | One finding opens on the resource, and its explanation states the condition that was not met | `TestFailureNamesTheResourceAndTheCondition`, `TestFailFindingPassLoop` | Completed |
| 3 | A permission is missing or a credential has expired | The run fails with a class, no result changes and nothing passes | `TestInvalidTokenIsACollectionErrorNotAResult`, `TestEveryFault`, `TestNoFaultProducesAResult`, `TestCredentialReportFaults` | Already covered |
| 4 | Pagination is cut short or the inventory is partial | The run records incomplete coverage and the check reads not evaluated, never pass or fail | `TestTruncatedPaginationIsIncompleteCoverage`, `TestCollectAlertsTruncated`, `TestEveryFault` | Already covered |
| 5 | A timeout, throttling or a brief outage | Retries are bounded by a stated policy, each attempt is its own run, and integration health shows the problem | `TestRetriesFollowThePolicy`, `TestRateLimitWaitsAsLongAsTheSourceAsks`, `TestEveryFault`, `TestIntegrationHealth` | Already covered |
| 6 | The same work runs twice | One queued attempt per job, one finding per condition, one evaluation per observation, and no attempt taken by two workers | `TestSameJobTwiceCreatesNoDuplicate`, `TestWorkersNeverShareAnAttempt`, `TestFailFindingPassLoop` | Already covered |
| 7 | The payload is unchanged between collections | The bytes are stored once and each collection keeps its own observation, time and evaluation | `TestUnchangedPayloadKeepsEveryObservation`, `TestIdenticalEvidenceSharesOnePayload`, `TestStudy` | Completed |
| 8 | A check's logic changes | The new version adds evaluations beside the old ones, rewrites none, and each old one still reproduces under its own version | `TestNewCheckVersionAddsEvaluationsAndOldOnesStillReproduce` | Already covered |
| 9 | An exception is approved and later expires | The check still reads fail throughout, and at expiry the control needs attention again with nothing written | `TestExpiredExceptionReturnsControlToNeedsAttention`, `TestRequesterCannotApproveOwnException`, `TestFullLoopKeepsEveryStep` | Already covered |
| 10 | A request or export without authorization | The service refuses according to the permission matrix, for every action and for an actor with no role, and a signed-out browser reaches no page, export or package | `TestServiceEnforcesTheMatrix`, `TestAuditorReadsAndExportsButNeverWrites`, `TestActorWithoutARoleReachesNothing`, `TestSignInIsRequired`, `TestAuditorInTheBrowser`, `TestNoActorIsDenied` | Completed |
| 11 | A package for a past period | Scope, period, evidence, results and decisions agree with each other and with the period's end, and the package verifies | `TestReviewPackageHoldsTheFailTheExceptionAndThePass`, `TestReviewPackageIsAsOfThePeriodEnd`, `TestReviewPackageIsTheSameWhenRegenerated`, `TestVerifyPackage` | Already covered |

## What was missing

- **Scenario 1.** Earlier tests showed a pass and showed that stored
  evaluations reproduce. None asserted that the pass names the observation
  of the collection that produced it and not an older one.
- **Scenario 2.** Earlier tests counted findings. None read the finding's
  resource or its explanation.
- **Scenario 7.** The earlier test compared two hashes and two observation
  identifiers. It did not show that one payload is on record, or that each
  observation keeps its own time and run.
- **Scenario 10.** Every role was tested against the matrix, and export is
  allowed to every role, so no test showed an export being refused. The
  new test calls every service method as nobody, as a role with no user and
  as an undefined role, and fails if a method is added without being
  listed. The signed-out browser test now covers every page, the export
  and the package.

## Limits

- For scenario 2, the explanation names the branch and the unmet
  condition, and the finding names the repository. The explanation alone
  does not name the repository.
- Scenario 5 is tested with an injected clock and synthetic sources. No
  test waits out a real timeout against GitHub or AWS.
- Scenario 10 covers the service and the site. The command line acts as
  the operator and has no sign-in of its own.
