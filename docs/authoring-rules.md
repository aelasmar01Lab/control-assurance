# Authoring rules

The maintainer's rules for sourcing framework packs and for writing
controls and mappings. They come from section 4 of his plan, which is kept
outside the repository, and are in his wording. Four of his standing rules
from `CLAUDE.md` are repeated where they belong and marked; the last
section is the agent's and says so. The agent reads this file before drafting each unit.

`docs/authoring-notes.md`, once it exists, records what the maintainer
changed in the agent's drafts. Where the two disagree, the notes are newer
and win.

## Sourcing

### Rules

- Identifiers, counts and hierarchy are checked against the source after
  import: the importer prints the requirement count, and the drafting log
  records the count the publisher states. A mismatch stops the unit.
- A framework whose official document sits behind a purchase or a
  registration the agent cannot complete goes in `BLOCKED.md`. Ali supplies
  the identifier list from his own copy.
- The agent does not use a third-party website's copy of a standard as the
  source.
- No requirement identifier, title or text is written from memory. It comes
  from a source the agent opened in the session, recorded in the pack
  header. (Standing rule 5.)
- No framework text is committed unless the pack records a licence that
  permits redistribution, checked at the source. When unsure, identifiers
  only. (Standing rule 6.)

- The maintainer's research register, kept outside the repository, wins
  over the plan's licence tiers where they disagree. The agent still opens
  and records each source itself (decision 42). (Added by the maintainer
  on 2026-11-12.)

### Steps for each framework, in order

1. **Find the official source and its licence.** Open the publisher's page.
   Record the licence statement and its URL in the drafting log. If the
   licence cannot be found or is unclear, use `identifiers_only`.
2. **Prefer machine-readable sources.** OSCAL catalogs and publisher JSON
   or CSV exports are imported by a script committed under
   `tools/import/<framework>/`, so the import can be re-run. Do not retype
   a catalog.
3. **Pin it.** Retrieval date, URL, and SHA-256 of the retrieved file, as
   MVSP does now.
4. **`full` packs** keep upstream's text byte for byte. Errors upstream are
   kept and noted beside the requirement (decision 28).
5. **`identifiers_only` packs** carry the identifier, the hierarchy, and a
   `label` in the agent's own words that describes the topic without
   paraphrasing the requirement sentence by sentence. No official title, no
   official text. The identifier list comes from the official document or
   the publisher's public table of contents.
6. **`own_composition` packs** (SOX ITGC, US Data Privacy, agentic
   controls) are requirement lists the project writes itself. The header
   says so, and names the public sources each requirement draws on. The
   agentic controls pack is written fresh from public sources; it does not
   reproduce Vanta's control text or any employer's internal standard.
7. **Profiles.** A baseline that selects from another catalog is a profile,
   not a copy: FedRAMP baselines over NIST 800-53, CMMC levels over NIST
   800-171. A profile lists identifiers and inherits text and mappings
   from its parent.
8. **Large catalogs** are imported whole but scoped by profile. NIST 800-53
   has over a thousand controls and enhancements; the lab's working scope
   is the moderate baseline, and the rest shows as "not in selected
   baseline".
9. **Versions.** A new release is a new file. Old versions stay.

## Controls

One file per control, at `controls/<domain>/<key>.yaml`:

```yaml
key: access-mfa-console          # kebab-case, starts with the domain, never renamed
title: MFA on console access     # at most 8 words
statement: >-
  Every human identity that can sign in to the cloud console has
  multi-factor authentication enabled.
risk: An attacker with a stolen password signs in to the console.
owner_role: control-owner
type: automated                  # automated | manual | policy | hybrid
checks: [AWS-01]                 # may be empty until the test exists
manual_evidence:                 # omit when none
  expectation: ""
  validity_months: 12
evidence_expectation: IAM credential report, collected at least every 48 hours.
freshness_hours: 48
reviewer_note: ""                # the agent's doubt, if any; blocks signing until cleared
review:
  status: draft
  drafted_by: agent
  reviewed_by: ""
  reviewed_on: ""
  content_sha256: ""
```

A control describes a generic small company and does not say which
organization it applies to. A control that does not apply to the lab or to
the demo company is listed in `scope/lab.yaml` or `scope/demo.yaml`, with
a reason (decision 38; the plan's `applies_to_lab` field is gone).

### Writing rules

- **One observable thing per control.** If the statement needs "and" to
  join two activities, it is two controls.
- **The organization is the actor, in the present tense.** Write what is
  true when the control works, not what someone should do.
- **Own words.** A statement is never a framework requirement with the
  wording changed. Write it from the activity, then map it.
- **Testable.** For an automated control, a reader can tell from the
  statement what the check will read. For a manual one, the evidence
  expectation names a document with a date and an author.
- **Banned words:** compliant, ensures, guarantees, robust, appropriate, as
  needed.
- **No orphans and no duplicates.** Before adding a control, search
  `controls/` for one that describes the same activity. A control with no
  mapping after its wave is removed.
- **A control with no check yet** has `checks: []` and reads *not
  evaluated*. Do not point it at a check that tests something adjacent.

Good: "Changes to the default branch require an approving review from
someone other than the author."

Bad: "The organization ensures appropriate change management controls are
in place and reviewed as needed."

### Building the common control set

Draft it from the Wave 1 frameworks together. For each requirement, ask
what the lab organization would observably do, write that as a candidate,
then merge candidates that describe the same activity. Expect roughly 150
controls after Wave 1. Later waves add a control only when a requirement
has no home, which will mostly happen in privacy, AI governance, continuity
and sector-specific rules. The number is an expectation, not a quota.

A control is never invented just to give a requirement a mapping.
(Standing rule 8.)

## Mappings

One file per framework, at `mappings/<framework>.yaml`, one entry per
control-to-requirement tie:

```yaml
framework: soc2
version: "2017-tsc-2022-pof"
mappings:
  - control: access-mfa-console
    requirement: CC6.1
    strength: partial            # direct | partial | supporting
    rationale: MFA on console sign-in is one of the logical access measures CC6.1 covers.
    limitation: CC6.1 also covers provisioning, network access and encryption, which this control does not show.
    basis: own_analysis          # own_analysis | published_crosswalk | derived
    basis_source: ""             # URL for a crosswalk; "via nist-800-53:IA-2(1)" for derived
    reviewer_note: ""
    review: {status: draft, drafted_by: agent, reviewed_by: "", reviewed_on: "", content_sha256: ""}
```

### Rules

- **Strength.** `direct` only when the control statement covers every
  clause of the requirement. `partial` when it covers some. `supporting`
  when it is related evidence that does not establish any clause. When in
  doubt, the weaker one.
- **Limitation is required** for `partial` and `supporting`, and says what
  the requirement asks for that the control does not show.
- **Rationale is about this pair.** A sentence that could be pasted onto
  another mapping is rewritten.
- **A draft `direct` mapping counts as `partial`** in every derived state
  until it is reviewed.
- **Public crosswalks** (NIST's own mappings between its publications and
  to ISO 27001, framework publishers' informative references) may seed
  mappings with `basis: published_crosswalk` and the URL.
- **Derived mappings** go through an intermediate framework (control to
  NIST 800-53 to something else). They are capped at `supporting`, marked
  `derived`, and name the path.
- **Many-to-many is normal.** A requirement usually needs several
  controls. Do not stop at the first match.
- **No mapping is copied** from Vanta's product, another vendor's product
  or a proprietary crosswalk. Public crosswalks may be used with the source
  named. (Standing rule 7.)

## What the tooling checks, and what it does not

This section is the agent's note, not the maintainer's wording.

`cca content validate`, which runs in CI, refuses: a banned word in a
draft control's title, statement, risk or evidence expectation (a control
the maintainer has signed may use one, since he chose it); a title over eight words; a label over twelve; a key that does not
start with its domain (the first release's eight keys are exempt by name,
because keys are never renamed); a `partial` or `supporting` mapping
without a limitation; a `derived` mapping stronger than `supporting` or
without its path; a `published_crosswalk` mapping without a URL; a mapping
or tracking entry that names a control, requirement or framework version
that does not exist; and a requirement that is neither mapped nor tracked
for an organization (tracking is kept per organization, decision 39).
A draft `direct` mapping is counted as `partial` by the code, not by
convention.

Nothing checks the rest. One observable thing per control, own words, a
rationale that is about its pair, the choice of strength, and whether a
source was really the publisher's are matters of reading, which is what
the maintainer's review is for.
