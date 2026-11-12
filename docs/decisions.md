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
commands and take no user.

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

The two internal controls, their owners, checks and framework mappings are Go
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
