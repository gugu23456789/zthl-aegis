# Stage Guide (0–5)

<!-- DOC-META
title: Stage Guide (0–5)
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

One page for the execution path. Each stage is entered only through the CLI
(`gatekeeper-cli.sh advance`); editing outside the active stage is refused by the hook.

| Stage | Goal | Entry | Exit gate |
|:--|:--|:--|:--|
| STAGE 0 | create an isolated worktree, restore the plan | `discover` + `advance STAGE_0` | worktree + plan backup present |
| STAGE 1 | implement under edit gates | `guard-edit` / `pre-tool-check` | edits committed, `pre-tool-check` green |
| STAGE 2 | push and drive CI to green | `git-workflow` push | CI all-green, `ci-diagnose` clean |
| STAGE 3 | cross-review before merge | `advance STAGE_3` | L1–L10 review recorded, plan backed up |
| STAGE 4 | PR, merge, align local | `git-workflow` PR | PR merged, local branch aligned |
| STAGE 5 | retire the branch and clean up | `advance STAGE_5` | worktree removed, state closed |
| STAGE 5b | retrospective | `reflect` | lessons written back |

## STAGE 0 — START

- Build the feature worktree from the main branch; never code on `master`.
- Restore the plan from `docs/plan-backup/` when the working copy is missing.
- Verify: `bash gatekeeper-cli.sh state` shows the expected branch and worktree.
- Exit: `advance STAGE_1` returns `{"allowed":true,...}`.

## STAGE 1 — CODE

- All writes go through `guard-edit` and `pre-tool-check`; a blocked edit is final until the
  missing gate is satisfied.
- Commit messages state the intent, not a file list; one logical change per commit.
- Tests: red-first for defects, regression for behavior changes. Run the project's acceptance
  entry point, not an ad-hoc subset.
- Exit: `pre-tool-check` green and the diff is committed.

## STAGE 2 — CI

- Push through the git workflow skill; never force-push a protected branch.
- On red: run `ci-diagnose <run-id>` first. Fix the root cause; do not rerun blindly.
- Same failure three times: stop and start a review (L4) instead of another patch.
- Exit: CI all-green and no skipped mandatory job.

## STAGE 3 — REVIEW

- Review layers L1–L10 are defined in one place; do not fork a second list.
- Deterministic evidence first (git, PDG, supply-chain, security scans), then the constrained
  sub-agent review channel for semantic checks.
- Plan backup and sprint contract are written before review starts.
- Exit: findings recorded with an id and a closure oracle; blocking findings closed.

## STAGE 4 — MERGE

- Open the PR with the review evidence attached; plans never go into the PR.
- Merge only after CI and review gates are green; prefer a merge commit over history rewrite.
- Exit: PR merged and the local branch aligned with the remote.

## STAGE 5 — RETIRE

- Remove the worktree, delete the merged branch, close the state record.
- Keep the plan backup; never delete evidence that a finding cites.
- Exit: `state` reports DONE and no orphan worktree remains.

## STAGE 5b — RETROSPECTIVE

- Record what the gates caught and what they missed.
- Turn every missed defect into a rule or a check, not a note.
- Update this guide and the index when a stage's contract changes.

## Invariants

- State transitions are CLI-only; the hook refuses out-of-stage edits.
- Signed, replayable records are written for transitions, dispatches and verdicts.
- Plans are not versioned in the public tree; only the code and these guides are.
