# Walkthrough

A script for showing the application in under ten minutes, using the seeded
demo. Everything in the demo is synthetic. It shows Pellwick, a fictional
company of 25 people that sells scheduling software to outpatient clinics,
with an AI scheduling assistant on Amazon Bedrock. Pellwick does not exist;
its people have addresses at the reserved domain `pellwick.example`.

```sh
make demo        # needs only Docker; ready at http://127.0.0.1:8080
```

The terminal prints the history that was seeded and four sign-in names with
their demo passwords.

## 1. What a result is (1 minute)

Sign in as `auditor`. On **Overview**:

- Each control has a state and, beside it, the reasons. *Supported* always
  lists the checks it rests on. Nothing says "compliant".
- Under **Current results**, each row is one check version applied to one
  stored piece of evidence, with the hash of that evidence.
- `dependency-remediation` reads **not evaluated**: Dependabot alerts were
  turned off on the repository, and that is not the same as having no alerts.

## 2. A failure that became a finding, an exception, a fix (2 minutes)

Open **Findings**.

- Three closed findings on the repository, `pellwick-example/scheduling-api`
  (GH-01, GH-02, GH-04). Each shows
  the evaluation that opened it and the later passing evaluation that closed
  it. GH-01 and GH-02 also show a remediation note and an exception that was
  requested by `control-owner` and approved by `reviewer`.
- One open finding, AWS-04. Its exception was approved and has since
  **expired**. Nothing ran at the moment of expiry; the control simply
  reads *needs attention* again.

Open **Decision log**: every one of those steps, with who and why.

## 3. A collection failure is not a result (2 minutes)

Open **Integration health** and scroll to **Collection runs**.

- On the third day, three runs failed with class `auth`: the token was
  rejected. They are not retried, because a rejected credential stays
  rejected.
- On the fourth day, three runs failed with class `server` and each has a
  **retry** a minute later that succeeded.
- Go back to **Overview**: none of those failures appears among the
  results. A failed collection produces no evidence, so there was nothing to
  evaluate, and the previous result stood.

`docs/faults.md` lists every fault the tests inject and shows that none of
them can produce a pass.

## 4. Make a decision yourself (2 minutes)

Sign out, sign in as `control-owner`. On **Findings**, on the open AWS-04
finding, add a note and request a new exception with an expiry date. The
control still reads *needs attention*: a request changes nothing.

Sign in as `reviewer` and approve it. **Overview** now reads *accepted
risk* for AI usage logging, and AWS-04 still reads *fail*.

Sign in as `control-owner` again and look for an approve button on your own
request: there is none, and the database would refuse it too.

## 5. Every requirement, honestly (1 minute)

Open **Frameworks**, then **Requirements** on Minimum Viable Secure
Product. All 25 MVSP requirements are listed. Seven are
covered in part by a control and show that control's state. The other
eighteen read *not assessed*: nobody has yet written down how Pellwick
tracks them, and the page claims nothing about them. (The lab's own
entries say manually, not implemented or out of scope, each with a
reason.) None is shown as met. Every mapping says whether the maintainer
has reviewed it.

The overview lists more controls than the demo plays a history for. The
access controls are drafts with no check behind them yet, so they read
*not evaluated* or *needs attention*. Two have a record from Pellwick's
staff. *Access granted on recorded approval* holds the month's access
requests, accepted by the reviewer, and reads *supported*, still labelled
a draft. *Access removed when a person leaves* holds a leaver's checklist
that nobody has reviewed, so it reads *needs attention*. Sign in as
`reviewer` and open **Manual evidence** to accept or reject it.

## 6. The review package (1 minute)

Open **Review package**, keep the offered dates, and download. Unzip it and
open `index.html`: the same history, as it stood at the end of that period,
with the evidence files beside it. Then:

```sh
go run ./cmd/cca package verify review-package-*.zip    # needs Go; no database
```

It recomputes every hash and re-runs every evaluation from the evidence in the
package. Download the same period again and the manifest hash is the same.

## What the demo cannot show

The synthetic sources exist only while the demo is being seeded, so
"Queue collection now" queues runs that no worker will pick up. Live
collection needs a lab; `docs/operations.md` covers that.
