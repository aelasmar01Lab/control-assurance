# Operations notes

How to run the application against a real lab, keep it running, and recover
it. For the seeded demo, see the README; none of this is needed for it.

## Processes

| Process | Command | Holds | Notes |
| --- | --- | --- | --- |
| Database | `make db-up` | All history | PostgreSQL 18 on `127.0.0.1:5433`. |
| Site | `cca serve` | A database connection | No GitHub or AWS credentials. Listens on `127.0.0.1:8080`. |
| Worker | `cca worker` | Source credentials, evidence store credentials | Collects each job daily, retries failures, evaluates new evidence. |

The site and the worker are separate so that the process listening on a port
can read nothing from GitHub or AWS. `cca worker --once` makes one pass and
exits, for cron.

The site is plain HTTP and has no sign-in lockout or rate limit. Keep it on
the loopback interface. Putting it on a network needs TLS and rate limiting
in front of it, and `CCA_COOKIE_SECURE=1`.

## First run against a lab

```sh
make db-up && make migrate && make build
export DATABASE_URL='postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable'
bin/cca users seed                 # prints four passwords once
export CCA_USER=operator
bin/cca packs load
bin/cca collect github owner/name  # registers the repository as in scope
AWS_PROFILE=cca-collector bin/cca collect aws
bin/cca evaluate
AWS_PROFILE=cca-collector bin/cca worker &
bin/cca serve
```

A repository or account becomes in scope the first time it is collected.
After that the worker collects it on schedule.

## Credentials

| Credential | Used by | Needs | Rotation |
| --- | --- | --- | --- |
| `DATABASE_URL` | Everything | Read and write on the database | The strongest credential here: whoever holds it can read all history. |
| `GITHUB_TOKEN`, or the GitHub CLI login | `collect`, `worker` | Read on metadata, contents and Dependabot alerts | An expired token shows as failed runs with class `auth` on the integration health page; replace it and queue collection. |
| `AWS_PROFILE` (collector role) | `collect aws`, `worker` | The seven read actions in `deploy/aws/collector-policy.json` | Assumed-role credentials are short-lived and refreshed by the SDK. |
| `CCA_EVIDENCE_AWS_PROFILE` (evidence role) | Anything that reads or writes evidence, when S3 is used | `deploy/aws/evidence-policy.json` | Must be a different profile from `AWS_PROFILE`; the binary refuses to start otherwise. |
| Lab user passwords | People signing in | | `cca users reset-password <username>` prints a new one once. |

`CCA_USER` is not a credential. It names the user whose role applies to a
CLI command and whose name goes in the decision log.

## Health

Open **Integration health** in the site. Each job is one kind of evidence
from one resource.

| What you see | What it means | What to do |
| --- | --- | --- |
| healthy | The last attempt succeeded | Nothing. |
| retrying | The last attempt failed and a retry is waiting | Usually nothing. The fault table (`docs/faults.md`) says how each class is retried. |
| failing | The last attempt failed and nothing more is queued | Read the error class. `auth`: replace the credential. `permission`: fix the grant. `not_found`: the resource is gone or hidden. Then queue collection. |
| stale | No new evidence for 48 hours | The controls resting on it are stale too. Check that a worker is running. |
| pending, with nothing finishing | No worker has the credentials for that source | Start a worker with them. |

A collection problem never changes a check result. The last result stays,
and its evidence ages.

## Backup and recovery

Nothing in the application backs itself up. Two things hold state:

- **The database.** `docker compose exec postgres pg_dump -U cca cca > cca.sql`
  to back up; restore into an empty database with `psql`.
- **The evidence store.** `data/evidence` locally, or the S3 bucket. Files
  are named by the SHA-256 of their content and never change, so copying the
  directory is a complete backup, and copying it twice is harmless.

Back up both, database first. Evidence without the database is only files;
the database without the evidence cannot reproduce an evaluation, and
`cca reproduce` will say which ones.

After a restore, run `cca reproduce`. It re-runs every stored evaluation
from the stored evidence and reports any that no longer gives the recorded
result.

A recovery from backup has not been exercised for this project.

## Upgrades

`cca migrate up` applies new migrations and is safe to run again. Migrations
only add; history tables reject updates and deletes whoever asks.

Changing what a check asserts means adding a new version beside the old one,
never editing it. The old version must stay in the binary: stored
evaluations name it, and reproduction needs it. After adding a version,
`cca evaluate` applies it to all stored evidence of its kind, which adds
evaluations and moves no finding.

## Data handled

| Data | Where it comes from | Where it is kept | Sensitive? |
| --- | --- | --- | --- |
| Branch rules, Dependabot alert summaries, security policy file metadata | GitHub REST API | Evidence store, as normalized JSON | Low for public repositories. Alert summaries name vulnerable packages. |
| IAM user names, MFA state, password and access key last-use dates | AWS IAM credential report | Evidence store | Yes: user names and access patterns. No secret keys or passwords are in the report. |
| CloudTrail trail names and status; Bedrock logging destination names | AWS | Evidence store | Low: resource names. |
| Manual evidence files | Uploaded by a control owner | Evidence store | Whatever the uploader puts in them. Up to 10 MiB each. |
| Usernames, display names, roles, argon2id password hashes | `cca users seed` | Database | Yes. |
| Session identifiers | Sign-in | Database, and an `HttpOnly` cookie | Yes, for the life of the session (8 hours, 1 hour idle). |
| Notes, justifications, decisions and the decision log | People using the site or CLI | Database | Whatever people write. |
| GitHub and AWS credentials | The environment of `collect` and `worker` | Never stored | Yes. They are not written to the database, the evidence store or logs. |

A review package contains the evidence files for its period, including
IAM user names and any manual evidence. Treat it as you would the evidence.

## Limits worth knowing

- One organization, one database. There is no tenant separation.
- "As of" history for review packages is computed in memory over all
  history. That is fine for months of daily collection from a handful of
  resources, and not designed for more.
- Nothing deletes evidence or history, so both only grow.
- Review packages are not signed. Record the manifest hash when one is made;
  it is also written to the decision log.
