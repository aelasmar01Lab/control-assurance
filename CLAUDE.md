# Standing rules for the build agent

This repository's framework packs, controls, mappings, tracking entries and
policies are drafted by an AI agent and reviewed by the maintainer, Ali.
These rules bind every agent session. They come from the maintainer's
revised plan, which is kept outside the repository.

1. Content the agent writes is `status: draft`. The agent never sets `status: reviewed`, never fills `reviewed_by` or `reviewed_on`, and never runs `cca review sign`.
2. The agent never changes a reviewed entry. If it believes one is wrong, or a new framework version affects it, it writes a proposal file under `proposals/` and moves on.
3. The agent changes an existing draft file only when the last commit that touched the file is its own. If Ali has touched it, changes go to `proposals/`.
4. Ali's edits are never reverted, reworded or "tidied". When they contradict these rules, Ali's edit wins and the agent records the pattern in `docs/authoring-notes.md`.
5. No requirement identifier, title or text is written from memory. It comes from a source the agent opened in this session, recorded in the pack header. If the source cannot be opened, the framework goes in `BLOCKED.md` with what is needed, and the agent continues with the next one.
6. No framework text is committed unless the pack records a licence that permits redistribution, checked at the source. When unsure, identifiers only.
7. No mapping is copied from Vanta's product, another vendor's product or a proprietary crosswalk. Public crosswalks may be used with the source named.
8. Every requirement in every pack is either mapped by at least one control or has a tracking entry. A test fails otherwise. A control is never invented just to give a requirement a mapping.
9. The engine's invariants hold: a collection failure is not a result, history is insert-only, state is derived on read, nothing is called compliant, and the README states only what is implemented.
10. The interface never presents a draft as established. Draft controls and mappings carry a "draft, not reviewed" label wherever they appear, including exports and the review package.
11. Work goes straight to `main`, one commit per unit (one pack, one control domain, one framework's mappings). `git pull --rebase` before each unit. Commit trailers that name the agent stay.
12. Anything changed in the lab for a test (a rule disabled, alerts turned off) is restored before the unit is committed, and the restore is noted in the commit message.
13. Stop and ask only at the two gates below, or when a rule here would have to be broken to continue.

## Gates

1. **After the pilot.** The content model, then the SOC 2 and NIST CSF 2.0
   packs, about 20 controls in the `access` domain, and their mappings to
   SOC 2 CC6 and CSF PR.AA. Ali edits and signs the pilot, and the agent
   writes the first `docs/authoring-notes.md` from his edits. Nothing else
   is drafted until then.
2. **After Wave 1.** Ali confirms the common control set is the right shape
   before later waves are mapped to it.
