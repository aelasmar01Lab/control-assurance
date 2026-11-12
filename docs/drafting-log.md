# Drafting log

One entry for each unit of content the agent commits: what was added, the
counts, every source opened, the publisher's stated requirement count
against the imported count, and the entries the agent is least sure of.
Newest last.

## 2026-11-12: the first release's content, moved into files

**What.** No new framework and no new control. The eight controls, eight
MVSP mappings and eighteen MVSP tracking entries that were Go values in
`internal/control` are now files under `controls/`, `mappings/` and
`tracking/`, with their keys, wording, strengths and limitations
unchanged. All 34 entries are `draft`: the agent wrote them during the
first release and nobody has signed them.

**New text.** Controls had no `statement` field before. The agent wrote
eight, each from the assertion of the checks the control rests on
(`docs/checks.md`). It also wrote one manual-evidence expectation, for
`backup-recovery`.

**Counts.** MVSP v3.0-20231109: 25 requirements in the pack, 25 stated by
the pinned upstream catalog. Seven are mapped by a control and eighteen
are tracked; none is both and none is neither.

**Sources opened.** None beyond the pinned MVSP pack already in the
repository. The pack's requirement text was not changed; only its header
moved to schema version 2.

**Least sure of.** Each of these also carries a `reviewer_note` in its
file, which blocks signing until it is cleared.

1. `change-management` joins two activities, an approving review and
   required status checks. The writing rules say one observable thing per
   control. It is kept whole because a key is never renamed.
2. `credential-lifecycle` joins unused credentials and root access keys,
   for the same reason.
3. `human-access` will overlap the narrower access controls the pilot
   drafts.
4. `ai-usage-logging` has no mapping. The writing rules remove a control
   with no mapping after its wave; the AI frameworks arrive in Wave 1.
5. The six first-release keys that do not start with their domain
   (`human-access`, `credential-lifecycle`, `dependency-remediation`,
   `audit-logging`, `ai-usage-logging`, `backup-recovery`) are allowed by
   name in the validator. Every new key must start with its domain.
