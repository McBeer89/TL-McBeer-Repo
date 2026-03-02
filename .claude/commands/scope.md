---
description: Phase 1 only — produce scoping document and essential constraints table before DDM work begins.
argument-hint: "<ATT&CK technique ID or technique name> [platform]"
---

# Scope: $ARGUMENTS

Produce the Phase 1 scoping document for:

> **$ARGUMENTS**

Research only. No DDM work yet.

---

### Step 1: Parallel Research

Spawn **3 trr-researcher subagents in parallel**:

1. **ATT&CK researcher**: Pull the technique entry — tactic, platforms, description, procedure examples, related sub-techniques. What distinguishes this from adjacent techniques?

2. **Technology researcher**: Research the underlying technology this technique depends on — OS internals, APIs, protocols, services, compilation behavior, security contexts. How does the technology work normally (benign use)?

3. **Boundary researcher**: Look for variants, edge cases, and related techniques. What does this TRR explicitly *not* cover? What would be a separate TRR? What is tangential (attacker-controlled) vs. essential (fixed by the technology)?

---

### Step 2: Synthesize Scoping Document

```markdown
# Phase 1 Scoping: [Technique Name]

## Scope Statement
[One precise sentence — platform, variant, boundaries. Example:
"File-based web shell execution via IIS on Windows."]

## Exclusion Table
| Excluded Item | Rationale |
|---|---|
| [Item] | Tangential — attacker-controlled |
| [Item] | Different essential operations — warrants separate TRR |
| [Item] | Same essential operations — covered by existing procedure |

## Essential Constraints Table
| # | Constraint | Essential? | Immutable? | Observable? | Telemetry |
|---|-----------|------------|------------|-------------|-----------|
| 1 | [What must be true] | ✅/❌ | ✅/❌ | ✅/❌ | [Source] |

## Technical Background Notes
[Detailed notes on underlying technology — architecture, APIs, execution models,
security controls. These feed into the TRR's Technical Background section.]

## Open Questions [?]
[Unresolved items that must be answered before Phase 2]

## Sources
```

---

### Step 3: Save and Present

Save to: `WIP TRRs\TRR####\win\Supporting Docs\phase1_research.md`

Present the scoping document and ask:
- Is the scope statement specific and defensible?
- Are all major exclusions captured with correct rationale?
- Are there `[?]` items that must be resolved before DDM work?

Do not proceed to DDM work until scope is confirmed.
