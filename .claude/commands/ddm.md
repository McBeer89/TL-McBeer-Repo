---
description: Phases 2-3 only — DDM construction, procedure identification, and per-procedure exports. Run after /scope is confirmed.
argument-hint: "<TRR ID> <technique name> [platform - default: win]"
---

# DDM: $ARGUMENTS

Build and validate the Detection Data Model for:

> **$ARGUMENTS**

Assumes Phase 1 scoping is complete. Read `WIP TRRs\TRR####\win\Supporting Docs\phase1_research.md` before starting.

---

### Step 1: Initial Operation Mapping

Spawn **ddm-builder** to:

1. Read Phase 1 research notes
2. Map all essential operations — apply inclusion test to each
3. Build Arrows.app JSON with:
   - "Action Object" verb phrase naming on every node
   - Prerequisites as prerequisite nodes (not inline steps)
   - Branch conditions labeled on arrows
   - Telemetry labels descriptive and on correct operations
4. Save to: `WIP TRRs\TRR####\win\ddms\ddm_trr####_win.json`

**STOP. Review the DDM. For every operation ask:**
- Is this truly essential — can the technique succeed without it?
- Is this truly immutable — can the attacker avoid or change it?
- Am I modeling the operation, or a tool that performs it?

---

### Step 2: Alternate Path Discovery

Spawn **trr-researcher** to investigate:
- Alternate APIs or mechanisms that accomplish the same essential operation
- Variants that introduce a new essential operation → different procedure
- Variants that only change attacker-controlled elements → same procedure, tangential

For each alternate path found:
- **Different essential operations** → add branch to DDM, new procedure
- **Same essential operations, different implementation** → do not branch, note as tangential

---

### Step 3: Parallel Procedure Export + Validation

Spawn **2 subagents in parallel**:

1. **ddm-builder**:
   - Trace every distinct procedure start to finish
   - Assign IDs: `TRR####.WIN.A`, `.B`, `.C`
   - Produce procedure table
   - Create per-procedure JSON exports with active path in red (`#f44e3b`)
   - Save to: `WIP TRRs\TRR####\win\ddms\trr####_win_[a/b/c].json`
   - Save procedure table to: `WIP TRRs\TRR####\win\Supporting Docs\procedures.md`

2. **reviewer**:
   - Apply full DDM review checklist to master DDM
   - Check inclusion test on every operation
   - Check telemetry label format and placement
   - Check procedure distinctness

---

### Step 4: Resolve and Confirm

Resolve all reviewer findings. Re-run reviewer if significant changes were made.

Present:
- Procedure table
- List of files created in `ddms\`
- Any remaining open questions

Confirm before proceeding to `/trr` document phase.
