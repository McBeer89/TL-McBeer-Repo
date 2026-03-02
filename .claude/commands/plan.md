---
description: Break a goal into a researched, actionable plan using parallel subagents
---

# Plan: $ARGUMENTS

## Instructions

You've been asked to create a plan for the following goal:

> **$ARGUMENTS**

Follow this process:

### Step 1: Decompose the Goal

Break the goal into 3-6 concrete subtasks. For each subtask, identify:
- What needs to be done
- What information is needed first
- What depends on what
- What can be done in parallel

### Step 2: Parallel Research

Spawn **multiple trr-researcher subagents in parallel** to investigate the unknowns. Each researcher should focus on a different aspect of the goal. For example:
- One researches the existing repo for relevant context
- One researches external sources, documentation, or best practices
- One identifies potential risks or blockers

Wait for all researchers to return before proceeding.

### Step 3: Synthesize into a Plan

Based on the research, create a concrete plan:

```
## Plan: [Goal Title]

### Phase 1: [Name]
- [ ] Task 1 (agent: trr-researcher / ddm-builder / trr-writer / coder) — description
- [ ] Task 2 (agent: ...) — description

### Phase 2: [Name] (depends on Phase 1)
- [ ] Task 3 (agent: ...) — description
- [ ] Task 4 (agent: reviewer) — review Phase 1+2
```

### Step 4: Save the Plan

Save the plan to `WIP TRRs\TRR####\win\Supporting Docs\plan.md` if TRR-related, or to `tools\` if tooling-related. Then present it to the user for approval before execution.
