# Decision records

One paragraph per decision: what was chosen, and what was given up.

## 1. A collection failure is not a result

A check result is `pass`, `fail` or `not_evaluated`, and each one is an
evaluation of a stored observation. A failed collection (bad token, rate
limit, outage) is recorded on the collection run with an error class and
produces no observation, so there is nothing to evaluate and the previous
result stands. Given up: a single "status" per check that would be simpler to
display. In exchange, an expired token can never look like a control failing,
or like one passing.

## 2. "Not found" needs a complete listing

A missing rule is a `fail` only when the rule listing was read to the end.
When the collector stops at its page cap with pages remaining, the run is
marked incomplete and a check that did not find its rule returns
`not_evaluated` with "incomplete coverage". A rule that *was* found in a
partial listing still passes, because its presence is established. Given up:
nothing but a few lines of code; the alternative reports absence it never saw.

## 3. Insert-only history is enforced by triggers, for now

Observations, evaluations, evidence payload rows, check versions and framework
content reject `UPDATE` and `DELETE` through database triggers. The plan calls
for database grants on a separate application role; triggers were chosen first
because they hold even for the table owner, which is the only role a
single-user local setup has. Given up: the cleaner "property of grants"
story. A separate, less-privileged database role for the application is
still not in place; it belongs with a hosted deployment.

## 4. Findings move only on newer evidence

A finding opens on a failing evaluation and closes on a later passing one, but
only when the observation is newer than any that check has already evaluated
for the resource. Re-evaluating old evidence under a new check version adds
evaluations and leaves findings alone. Given up: automatic correction of
findings when a check's logic is fixed; that will be an explicit, logged
action rather than a side effect.

## 5. Evidence is the normalized payload, stored once per distinct state

The collector stores a normalized JSON document (rules sorted, object keys
sorted) under its SHA-256, and each observation references it. Two
collections of an unchanged branch share one payload while both observations
are kept. Given up: the raw API responses, which are not stored in this
release; the normalizer version on each observation records which shaping
produced the bytes.

## 6. SQL is hand-written against pgx, without sqlc

The plan's default was `sqlc`. The first loop has about fifteen queries, and
writing them directly avoided a code-generation step and a second tool in CI.
Given up: compile-time checking of SQL against the schema; the database
scenario tests are what catch a wrong query. Worth revisiting when the query
count grows in M2.

## 7. The collector uses the operator's existing GitHub login

`cca collect` reads `GITHUB_TOKEN`, and falls back to the GitHub CLI's current
login. That login is far broader than the collector needs: it can write to
every repository the account can reach, where the collector only requires
read access to repository metadata on two lab repositories. Given up: a
least-privilege credential, the ability to observe what a read-only token
sees of ruleset bypass lists, and a real expiring token as the
expired-credential test (an invalid token is used instead). Switching to a
fine-grained token later needs no code change, only `GITHUB_TOKEN`.

## 8. One permission function, called in the service layer

Every action goes through `authz.Can(actor, action, resource)`, and it is
called by the service layer rather than by web middleware. The web handlers,
the CLI, the export and the collection and evaluation jobs all call the same
service methods, so none of them can skip it. Given up: the convenience of
per-route middleware. The permission matrix in `docs/permissions.md` is
generated from the same table the function reads.

## 9. The CLI names a user; it does not authenticate one

CLI commands act as the user named in `CCA_USER`, with that user's role and
name in the decision log. There is no password prompt: anyone who can run the
CLI already holds `DATABASE_URL`, which is the stronger credential. Given up:
any claim that the CLI proves who ran it. `migrate` and `users` are setup
commands and take no user. The worker is no exception: `cca worker` runs as
`CCA_USER`, and its scheduled collections and evaluations are checked against
that user's role like anyone else's.

## 10. Separation of duties is enforced twice

A reviewer cannot review their own submission or decide their own exception
request. `authz.Can` refuses it, and so do `CHECK` constraints on the tables,
for anything that reaches the database without the service. Given up: nothing;
the constraint is one line each.

## 11. Expiry is a comparison made on read

An approved exception is never rewritten when it expires. Its row keeps
`approved` and its expiry time; the control state and the displayed status
compare that time with the clock when they are read. The same holds for
accepted manual evidence and its validity date. Given up: an "expired" status
you can query for directly, and any notification at the moment of expiry.
In exchange, expiry needs no job, cannot be missed by one, and cannot touch
an evaluation.

## 12. Controls are defined in code

The eight internal controls, their owners, checks and framework mappings are Go
values in `internal/control`. The plan stores them as database rows with
revisions; here a revision is a reviewed commit. Given up: editing a control
without a release, and a queryable history of control changes inside the
product. Mappings carry no reviewer yet and are labelled "mapping not
reviewed" wherever they appear.

## 13. Local accounts, with the limits stated

Sign-in uses local accounts with argon2id hashes and server-side sessions
(`alexedwards/scs`, stored in PostgreSQL). There is no single sign-on, no
second factor, no lockout or rate limit on sign-in, and no self-service
password change. MVSP 2.1 expects single sign-on, so this project's own
self-assessment will record 2.1 as not met.

## 14. The job queue is the collection_runs table

Collection attempts are queued, claimed and finished as rows of
`collection_runs`, claimed with `FOR UPDATE SKIP LOCKED`. There is no queue
library and no broker. A partial unique index allows one unfinished attempt
per job, which is what makes "ask twice, collect once" hold. Given up:
throughput and anything like priorities or fan-out, none of which a daily
collection of a few dozen jobs needs. In exchange every attempt, retry and
error class is a row a page can show, in the same database as the results.

## 15. One row per attempt, retried by error class

A retry is a new run that names the attempt it follows; a finished run is
never reopened, and a trigger refuses to change one. Whether and when to
retry is a table keyed by error class (`docs/faults.md`). Classes that need a
person, such as an expired credential or a refused read, are not retried at
all: retrying them only adds noise, and the next scheduled collection tries
again. The AWS SDK's own retries are turned off so that every attempt is
recorded. Given up: the quick, invisible recovery an SDK retry gives for a
single dropped request; here that costs a recorded failure and a one minute
wait.

## 16. A killed worker is detected by lease, not by heartbeat

A claimed run carries a five minute lease, and one attempt is cut off after
ninety seconds, so a live worker always finishes inside its lease. A run
still marked running after its lease belongs to a worker that stopped; the
next worker pass records it as `interrupted` and queues the retry. Given up:
prompt recovery. An abandoned run waits out the rest of its lease, up to
five minutes, which is nothing against a 48 hour freshness window.

## 17. Ages are measured to the evidence, not to the clock

GH-03 (alert age) and AWS-02 (credential idle time) measure to the moment the
evidence describes: the credential report's generation time, or the time of
collection. That moment is stored on the observation, so re-running a check
on a stored observation a year later gives the same result and the same
words. Given up: a result that worsens on its own as time passes without
new evidence. That is what staleness is for; an old pass becomes a stale
control, not a silent fail. The thresholds (30 and 90 days) are constants of
the check version, so changing one means a new version.

## 18. "Turned off" and "could not read" are evidence

When Dependabot alerts are turned off, GitHub answers 403 with a specific
message (confirmed on a lab repository on 2026-11-12). The collector stores
that as an observation with `alerts_enabled: false`, and GH-03 returns
`not_evaluated`. The same holds for a trail whose status the role is refused.
Given up: treating every 403 alike. In exchange, "nobody is looking" can
never read as "nothing is wrong", and any other 403 is still a permission
failure on the run.

## 19. The site holds no source credentials

Only `cca collect` and `cca worker` hold GitHub and AWS credentials. The
operator's "queue collection" button on the integration health page adds
queue rows; a worker must be running to act on them. Given up: collection
with one click and no second process. In exchange the process that listens
on a port can read nothing from GitHub or AWS, whatever is wrong with it.

## 20. The AWS collector uses the official SDK behind a narrow interface

The four AWS checks need seven read calls. They go through
`aws-sdk-go-v2`, wrapped in an interface of seven methods that return plain
values, so the tests use a synthetic account and the normalizer never sees
an SDK type. Given up: a small dependency tree; the SDK brings about twenty
modules. Signing requests and assuming roles by hand was the alternative,
and is not something to own.

## 21. A review package's manifest says nothing about its making

`manifest.json` holds the period, the scope and the hash of every file, and
nothing about who generated the package or when. Those facts go to the
decision log, with the manifest hash. Given up: a package that is
self-describing about its own origin. In exchange, the same period yields
the same manifest byte for byte, so two people can compare one hash to know
they hold the same package. A package is refused for a period that is not
over, because only the past is certain to read the same tomorrow.

## 22. A package shows the period as it stood at its end

An exception approved after the period reads as a bare request in that
period's package; a finding closed after it reads as open. This works
because the only rows that ever change (a finding's closing, an exception's
decision, a submission's review) each carry the time of the change, and
everything else is insert-only. Given up: nothing in storage; the cost is
that "as of" filtering is done in Go over full history, which will need
SQL once history is large.

## 23. The package is unsigned

Verification proves a package is internally consistent and that its
evaluations reproduce. It cannot prove the package came from this system:
someone who edits a file and rewrites the manifest produces a package that
verifies, with a different manifest hash. The defence in this release is
the hash recorded in the decision log at generation. Given up: signatures
and the key management they need.

## 24. Old check versions stay in the binary

An evaluation records its check key and version, and reproduction needs
that version's code. So versions are never removed, and `cca reproduce`
reports a missing version as a mismatch, not as a pass. Re-evaluating
stored evidence under a new version adds rows and, as decision 4 says,
moves no finding. Given up: deleting dead code. A version that never
produced an evaluation anywhere is the only kind safe to remove.

## 25. The evidence store's role can create and read, nothing else

In S3, evidence is written with `If-None-Match: *` and the role's policy
allows `PutObject` only when that header is present, so an existing payload
cannot be replaced, and the role has no delete. It is a different role from
the collector's, and the binary refuses to start if both are given the same
profile. Bucket versioning is on as a second line. Given up: garbage
collection of payloads nothing references; nothing deletes evidence in
this release. Not used: S3 Object Lock, which would also stop the account
owner deleting objects, at the price of a bucket that cannot be emptied.

## 26. The case study measures a documented assumption

The deduplication study's dataset is synthetic, and the gap it shows
between raw-byte and normalized hashing comes from an assumption that the
source sometimes reorders the same rules. That assumption is stated in the
report beside the numbers, with what happens when it is zero. Given up: a
more impressive, unqualified ratio. Counts and bytes are fixed by the seed
and checked by a test; read times are machine-dependent and labelled so.

## 27. Every requirement is tracked, and "partly evidenced" is the ceiling

All 25 MVSP requirements appear. Seven take the worst state among the
controls mapped to them; the other eighteen have a tracking entry: manual,
not implemented or out of scope, with a rationale. A test fails if a
requirement has neither or both. The best state a requirement can show is
*partly evidenced*, because every mapping here is partial or supporting.
Given up: a coverage percentage, which would count partial mappings as
coverage. "Tracked manually" is not a positive state either: it says the
judgement is made elsewhere and no evidence of it is held here.

## 28. Upstream's text is kept even where it is wrong

The pinned MVSP catalog file gives requirement 2.1 the statement text of
requirement 1.1. The pack reproduces upstream byte for byte, so the error is
reproduced too, and a note beside 2.1 says so wherever it is shown. Given
up: a correct text for 2.1 in the product. In exchange the pack's claim,
"upstream's text, unmodified, at this commit and hash", stays true and
checkable. The fix belongs upstream, or in a later pinned version.

## 29. The demo replays history against synthetic sources

`cca demo` does not load a dump. It runs the real service, with a clock set
twelve days back, against the same synthetic GitHub and AWS the tests use,
and plays the loop forward: failures, exceptions, a rejected token, an
outage, the fix. So the demo data is produced by the code a visitor is
about to read, and a test asserts what it leaves behind. It refuses a
database holding anything else, and the compose profile gives it a
throwaway one. Given up: live collection in the demo; once seeding ends the
synthetic sources are gone, so queued collection has no worker. Demo
passwords are published, which is acceptable only because the data is
synthetic and the port is bound to loopback.

## 30. The self-assessment is about the software, and says what it lacks

`docs/self-assessment.md` assesses this application against MVSP and is
generated from a table in code, with a test that every requirement has
exactly one row. It is separate from what the application reports about the
lab. It records two requirements as met, and that there is no single
sign-on, no TLS, no vulnerability disclosure policy and no backup. Given
up: nothing but a more flattering page. It is the author's own judgement;
nobody independent has reviewed it.

## 31. The interface is styled entirely by one stylesheet, with no script

The pages follow the "Nocturne" design: a dark ground, a sidebar, summary
cards, status pills and tables whose rules fade at the ends. The design
reference used inline styles and a script runtime; the product uses
neither. Every rule is a class in `internal/web/style.css`, the content
security policy still allows no inline style and no script, and the things
the reference did with script are done with links: the selected finding and
the control detail panel are query parameters, rendered by the server.
Proportion bars are inline SVG, because their widths cannot be set by an
inline style. Given up: transitions, and opening a panel without a page
load. The Inter and Phosphor fonts are served from the binary
(`internal/web/static`, with their licences), so the site still makes no
request to anyone else.

## 32. Controls move out of code into reviewed content files (reverses 12)

Decision 12 kept the eight controls and their mappings as Go values. The
revised plan widens the product to many frameworks and a common control
set of roughly 150 controls, drafted by an AI agent and reviewed by the
maintainer. That cannot work if a wording change needs a Go edit, or if
"reviewed" means only "was in a commit". So controls, mappings and tracking
entries become YAML files under `controls/`, `mappings/` and `tracking/`,
validated against schemas, embedded in the binary and loaded into the
database, where each control's content is recorded as an insert-only
revision. Every entry carries a review block: it is a draft until the
maintainer signs it, the signature covers a hash of the entry's content,
and an entry edited after signing fails CI. Given up: the compiler
checking a control's shape, and a single place to read all controls as
code. Decision 12's label "mapping not reviewed" stays, now driven by the
review block instead of an empty field.

## 33. Workspaces are in the schema before they are in the interface

A workspace is one separately tracked part of the organization. Every table
that holds what was collected or decided (resources, runs, payloads,
observations, evaluations, findings, submissions, exceptions, notes and the
decision log) now has a `workspace_id`, and there is one workspace,
`default`. A resource is unique within a workspace, and a payload is
recorded once per workspace. Frameworks, check versions, control revisions,
users and sessions are shared. The column goes in now because every later
table would otherwise need the same migration. Given up for now: anything
that uses it. The column has a default of the first workspace and the store
neither sets nor filters by it, so a second workspace's rows would be mixed
into every page. Creating a second workspace is not offered anywhere, and
the default comes off when the store takes a workspace.

## 34. A pack records what it may carry, and carries no more

Pack files are now schema version 2. Each states its rights over the
framework's text: `full` (upstream's titles and text, under a licence
recorded in the header), `identifiers_only` (identifiers, hierarchy and a
label of at most twelve words in the project's own words) or
`own_composition` (requirements the project wrote). The loader refuses an
`identifiers_only` pack that has a title or text. A source may be a git
commit, a URL or a document. A baseline that selects from another catalog
is a profile: it lists identifiers and takes everything else from its
parent, so the text exists once. Given up: showing the official wording of
any standard whose publisher does not allow it, which is most commercial
ones; a reader needs their own copy beside the product. The MVSP pack's
header was rewritten in the new form with its requirement text unchanged,
and the migration updates the recorded file hash of the row already
imported, which is the only update a framework row has ever had.

## 35. A review is of specific content, and the file is the record

Each control, mapping and tracking entry ends in a review block. `cca
review sign` writes the reviewer's name, the date and a SHA-256 of the
entry's content, taken from the parsed entry with its texts trimmed and
its review block left out, so reflowing the YAML does not break a
signature and changing a word does. `cca review verify` recomputes every
hash and runs in CI. Signing edits only the four values in the block and
keeps every other byte of the file. A draft `direct` mapping counts as
partial, and every page, the export and the review package show whether an
entry is a draft. Given up: a signature that proves who signed. It is a
name in a file in git, not a cryptographic signature; the commit history
is the evidence of who wrote it, and anyone with push access can write any
name. Also given up: reviewing in the browser. Review happens in an editor
and a terminal, and the review-queue page only lists what is waiting.

## 36. Control revisions are recorded on load and applied by time

`cca content load` writes one row to `control_revisions` for each control
whose content hash or review differs from its newest row; the table is
insert-only. Evaluations are of a check on a resource, not of a control,
so they do not carry a revision. The revision in force for an evaluation
is the newest one loaded at or before it, and the review package lists
every revision loaded before the period ended and names, for each control,
the one in force at the period's end. Given up: deriving a past period's
control states with that period's wording. A package is still derived with
the wording built into the binary that makes it, and says so for any
control reworded since. Also given up: revisions for mappings and tracking
entries, whose history is in git only.

## 37. Not assessed is its own tracking status, and is not reviewed

A tracking entry may say `status: not_assessed`, and then says nothing
else: no owner, applicability, evidence or rationale, and no review block.
It means nobody has looked at the requirement yet. The rule that every
requirement is mapped or tracked still holds, so a pack can be imported
whole before its requirements are worked through, but the entry is not a
draft of anything. It is left out of the review queue and the count of
drafts waiting, `cca review sign` refuses it by name and skips it under
`--all`, and the pages and the review package read "not assessed" with no
review label, counted apart from requirements tracked with a reason. The
100 NIST CSF subcategories outside PR.AA, first written as *not
implemented* with a placeholder rationale, now use it. Given up: nothing
stops a framework staying not assessed indefinitely; the count is shown on
every framework page instead. The review package keeps format 3 although
its requirement list can now carry the state `not_assessed` and the basis
`none`, which a reader written against the earlier packages has not seen.

## 38. Controls are generic; each organization has its own scope file

Controls describe a generic small company, and a control file no longer
says whether it applies to the lab. There are two organizations, kept
apart. The lab is real: one person, two repositories, one AWS account,
live collection. The demo is a fictional company of about 25 people, fully
synthetic and labelled so on every page, in its own database. Each has a
file, `scope/lab.yaml` and `scope/demo.yaml`, that lists the controls that
do not apply to it, each with a reason and a review block. A control not
listed applies. A process shows one organization: the lab unless
`CCA_ORGANIZATION` says otherwise, and `cca demo` is always the demo.

A reviewed exclusion makes the control read *not applicable* in that
organization, with the reason, and a requirement whose every mapped
control is excluded reads not applicable too. A draft exclusion changes
nothing: the control keeps the state its evidence gives it and the draft
is shown beside it. This is the same rule as a draft `direct` mapping
counting as partial; a draft must not be able to take a failing control
out of view. Exclusions are signed with `cca review sign scope/<file>
--control <key>` and sit in the review queue.

The review package names its organization in the manifest and carries each
control's exclusion, and is now format 4. That also covers the
`not_assessed` state from decision 37.

Given up, and still open:

- Tracking entries are not per organization. `tracking/<framework>.yaml`
  says how the lab tracks a requirement no control covers ("the lab has no
  premises"), and the demo shows the same entries. For a 25-person company
  some of them are wrong.
- An exclusion is all or nothing. The old `partly` value has no
  equivalent.
- Exclusions have no history in the database. As with wording, a package
  for a past period is derived with the scope files built into the binary
  that makes it.
- The demo company has no name yet and the demo's seeded history is
  unchanged: it is still two synthetic repositories and one account, not
  25 people.

## 39. Tracking is per organization

How a requirement that no control covers is tracked is a fact about one
organization, so tracking files moved from `tracking/<framework>.yaml` to
`tracking/<organization>/<framework>.yaml`. The lab keeps its entries
unchanged. The demo company's entries all start as `not_assessed`: nothing
is copied from the lab, and each is written with its framework's wave. An
entry's organization is part of what a signature covers. Every
organization with a scope file must map or track every requirement, and an
organization with tracking files must have a scope file. A process shows
the tracking of the organization it shows.

This closes the first open point of decision 38. Its last point is closed
by the demo company, Pellwick, in the same unit of work.

Given up:

- The demo shows most requirements as *not assessed* until Wave 1,
  including the MVSP requirements the walkthrough used to show as tracked
  with a reason.
- Mappings are still shared: a control maps to a requirement for every
  organization alike. Only a reviewed exclusion makes that differ.
- The review queue counts not-assessed entries per organization, so the
  same requirement counts once for each.

## 40. The demo company is Pellwick

The maintainer chose the name and the business: Pellwick sells scheduling
software to outpatient clinics, has an AI scheduling assistant built on
Amazon Bedrock, has customers in the United States and the European Union,
and takes card payments through a processor. It has 25 invented people,
listed in `internal/demo/company.go`, with addresses at `pellwick.example`,
a domain reserved for examples. Its repository is
`pellwick-example/scheduling-api`; the owner carries "example" so it cannot
be taken for a real GitHub organization. Its AWS account is the all-zero
test account. Every page names the company and says it is fictional.

The seeded history is the same loop as before, told with Pellwick's
people. Two records were added so the company shows as one with staff: the
month's access requests, accepted, and a leaver's checklist that is still
waiting for review.

Given up:

- *Access granted on recorded approval* reads *supported* in the demo
  while the control is still a draft. It carries the draft label wherever
  it appears, but a visitor sees a positive state on unreviewed wording.
- The business is described, not modelled. Nothing in the demo yet shows
  the EU customers, the card payments or the clinics' data; those matter
  when the privacy and payment frameworks arrive.
- One web search found no company called Pellwick. That is not a
  trademark check.

## 41. A draft control never reads supported

A control whose evidence all passes reads *supported* only once the
maintainer has reviewed it. While it is a draft it reads *passing, not
reviewed*, with a reason that says so. A requirement reads *partly
evidenced* only when every control mapped to it is reviewed and supported;
with a draft among them it reads *passing, not reviewed* at best. Every
other state is unchanged: a draft that fails still needs attention.

This replaces the first "given up" point of decision 40. The draft label
beside a positive state was not enough: the state itself was the claim.
It applies to all 27 controls, which are all drafts today, so nothing in
the lab or the demo reads supported or partly evidenced until a control is
signed. The demo's two seeded records stay as they are.

The review package is now format 5, because the same history gives a
different state than under format 4.

Given up:

- A draft control under an approved exception still reads *accepted
  risk*, and a requirement resting on it reads the same. The exception is
  a reviewed decision about a failure; the control's wording is not part
  of it.
- Signing a control changes what the pages show for history already
  recorded, since state is derived on read.

## 42. The research register overrides the plan's licence tiers

The maintainer keeps a research register of the 38 frameworks outside the
repository: publisher, current version, how the source is obtained, the
licence terms and whether text may be republished here. The plan sorted
the frameworks into tiers from memory and said so. Where the two
disagree, the register wins. It does not replace the sourcing steps: for
each framework, in its own unit, the agent still opens the publisher's
source itself and records the licence statement, URL, date and hash in
the drafting log. If what it finds disagrees with the register, the
stricter reading is used and the difference is recorded.

Where the register changes what the plan assumed:

| Framework | The plan assumed | The register found | Consequence |
| --- | --- | --- | --- |
| FedRAMP | Full text; a profile over NIST 800-53 from GSA's OSCAL baselines | The current source is the 2026 consolidated rules, published as JSON; the baselines are legacy. No redistribution licence found | Import from the consolidated JSON, not as a profile of 800-53. Identifiers only unless a licence is found at the source |
| FedRAMP 20x | Full text | Part of the same 2026 consolidated rules. No licence found | Identifiers only unless a licence is found |
| CMMC 2.0 | Full text; a profile over NIST 800-171 | Regulation text in the eCFR; no reuse statement found. Level 2 cites 800-171 revision 2, not the current revision | Identifiers only unless a licence is found; keep the revision it cites |
| HIPAA | Full text | No reuse statement found; the publisher's combined PDF is an unofficial 2013 copy | Use the current CFR. Identifiers only unless a licence is found |
| Cyber Essentials | Full text under the Open Government Licence | Crown copyright notice; no reuse grant found | Identifiers only unless the grant is found |
| CJIS | Full text | No republication terms found | Identifiers only unless found |
| 23 NYCRR 500 | Full text | Reuse is non-commercial and unaltered only | Identifiers only |
| CIS Controls v8.1 | Identifiers only; non-commercial share-alike | Non-commercial, no derivatives | Identifiers only, as planned; the licence named in the plan was wrong |
| CRI Profile | Unknown | Non-commercial, no derivatives | Identifiers only |
| OFDSS | Unknown | The consortium's site could not be opened | Identifiers only if a source can be opened; otherwise `BLOCKED.md` |
| BSI C5 | Identifiers only | The publisher's page could not be opened | `BLOCKED.md` if the agent cannot open it either |
| Agentic Trust Controls | Own composition, written fresh | The publisher calls it open source; no licence was verified and the catalogue could not be opened | Check the licence at the source first. Own composition only if the catalogue cannot be used under its licence |
| SOX ITGC | Own composition | No canonical catalogue exists | Own composition, as planned |
| ISO standards | Identifiers only | Confirmed; several have newer editions than the plan named | Identifiers only; use the edition current at the source |

The NIST catalogues, the EU acts, Essential Eight, CPS 234 and MVSP are
confirmed as redistributable, each under its own licence, which the pack
records and keeps.

None of this starts Wave 1. Nothing further is drafted until the pilot is
reviewed (Gate 1).

Given up: where a licence is unclear the pack is identifiers only, so
several frameworks the plan expected to show with full text will show
labels instead.
