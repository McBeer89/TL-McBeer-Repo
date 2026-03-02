---
description: Show current TRR work state — what's in progress, what's complete, git status, and any open questions.
---

# Status

Show the current state of all TRR research work.

### Step 1: Repository Scan

Read the repository structure:
- List all folders in `WIP TRRs\` (in-progress TRRs)
- List all folders in `Completed TRR Reports\` (finished TRRs)
- For each WIP TRR, check what files exist in `ddms\` and `Supporting Docs\`

### Step 2: Git Status

Run:
```bash
git status
git log --oneline -10
```

### Step 3: Open Questions

Scan all files in `WIP TRRs\` for any `[?]` markers indicating unresolved questions.

### Step 4: Present Summary

```markdown
## TIRED Labs Repository Status

### In-Progress TRRs (WIP TRRs\)
| TRR ID | Technique | Platform | Phase | DDMs Present | Open [?] |
|--------|-----------|----------|-------|--------------|----------|
| TRR#### | [name] | win | [phase] | [files] | [count] |

### Completed TRRs (Completed TRR Reports\)
[List with TRR ID and technique name]

### Uncommitted Changes
[From git status]

### Recent Commits
[Last 10 commits]

### Open Questions [?]
[Unresolved markers found, with file location]
```
