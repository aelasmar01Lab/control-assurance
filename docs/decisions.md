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
story until roles arrive with accounts in M2, when grants will be added on top.

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
