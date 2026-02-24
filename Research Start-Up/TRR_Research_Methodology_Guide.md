# TRR Research Methodology — A Practical Guide

**Based on:** VanVleet's Threat Detection Engineering Methodology (TIRED Labs)
**Purpose:** A step-by-step process for researching any attack technique and
producing a submission-quality Technique Research Report (TRR) with Detection
Data Models (DDMs).
**Audience:** Anyone new to the methodology — detection engineers, threat
hunters, red teamers, intelligence analysts, or incident responders.

---

## Why TRRs?

Attack techniques abuse complex technical systems, and understanding exactly how
they work requires deep research. But that research is rarely captured in a
reusable way. Detection queries, hunt hypotheses, emulation scripts, and IR
runbooks each capture a fraction of the underlying analysis — and all are
environment-specific.

**A TRR is the lossless, discipline-neutral capture.** It preserves the complete
research, analysis, DDM, and procedure identification so that any security team
in any environment can use it as the foundation for their own work. A TRR
documents the technique; teams document their response.

TIRED stands for **T**hreat **I**ntelligence, **R**esponse, **E**mulation, and
**D**etection. A TRR serves all four disciplines equally:

- **Threat Intelligence** — Understand technique mechanics for reporting
- **Red Team / Emulation** — Know what to execute and how procedures differ
- **Detection Engineering** — Identify what to monitor and where blind spots
  exist
- **Incident Response** — Know what artifacts to look for and what the
  execution chain looks like

This is why TRR completeness and accuracy matter. The TRR is the authoritative
source of truth about a technique. Everything downstream derives from it.

---

## Before You Start

### What You Need

- A MITRE ATT&CK technique or sub-technique to research (additional mappings
  to other matrices like the Azure Threat Research Matrix can be noted in the
  TRR metadata)
- Access to the [TIRED Labs TRR spec] for format requirements
- Access to the [Arrows App] for building DDMs
- A text editor for your research notes and TRR draft
- Time and patience — depth matters more than speed

### Mindset

The single most important thing to remember: **you are not trying to catalog
tools or commands. You are trying to understand the essential operations that
MUST happen for a technique to work.** Tools change. Commands change. File
names change. The underlying operations do not.

Every time you're about to write something down, ask: "Is this something the
attacker MUST do, or is this something the attacker CHOSE to do?" If they
chose it, it's tangential. If they must do it, it might belong in your model.

### The DDM Inclusion Test

This is the single most important filter in the entire methodology. An
operation belongs in your DDM **only** if it passes all three parts:

```
ESSENTIAL:   The operation MUST be executed for the procedure to work.
             If you can skip it and still succeed, it doesn't belong.

IMMUTABLE:   The attacker CANNOT change or avoid this operation.
             It is a fixed requirement of the underlying technology.

OBSERVABLE:  The operation CAN theoretically be detected through some
             telemetry source, even if that source isn't deployed everywhere.
```

**Classification rules:**

```
ESSENTIAL + IMMUTABLE + OBSERVABLE     = Include in DDM
ESSENTIAL + IMMUTABLE + NOT Observable = Include (and note the detection gap)
OPTIONAL  (any combination)            = Exclude from DDM
TANGENTIAL (attacker-controlled)       = Exclude from DDM
```

Operations that fail the filter typically fall into two categories:

- **Optional:** Can be skipped without breaking the procedure. Fails the
  "essential" test. Example: enumerating running processes before injection.
- **Tangential (Attacker-Controlled):** The attacker chooses these elements
  and can change them at will. Fails the "immutable" test. Examples: specific
  tools or frameworks, command-line parameters, file names and paths chosen by
  the attacker, delivery methods, encoding or obfuscation techniques,
  programming language or script variant.

Apply this filter relentlessly. At every operation, ask: "Is this essential?
Is this immutable? Is this observable?" If you can't answer yes to all three,
the operation doesn't belong — or it needs to be decomposed further until you
find the essential/immutable/observable core underneath.

### Procedures vs. Instances

One more foundational concept before you start:

- A **procedure** is a recipe — a unique pattern of essential operations
- An **instance** is a specific execution — one cake made from that recipe

Different tools executing the same essential operations = **same procedure.**
Different essential operation paths = **different procedures.**

The key question: "Does this change the *essential operations*, or just the
implementation details?" If only implementation details change (different tool,
different handler, different file extension), it's the same procedure. If the
essential operations themselves change (a new operation is introduced, an
operation is eliminated, or the operation chain fundamentally diverges), it's
a new procedure.

---

## Phase 1: Build Your Understanding

**Goal:** Understand the technique well enough to explain it simply and
accurately. Do NOT touch the DDM yet.

### Step 1: Answer the Basic Questions

Write down answers to these questions. If you can't answer one, that's your
first research task.

```
□ What is this technique called?
□ What tactic does it accomplish? (Persistence? Credential Access? etc.)
□ What platform(s) does it affect?
□ What is the attacker trying to achieve?
□ Why do attackers use this technique instead of alternatives?
□ What are the prerequisites? (What must already be true for this to work?)
```

**Checkpoint:** Can you explain this technique to a non-technical person in
2-3 sentences? If not, keep researching.

### Step 2: Understand the Underlying Technology

Before you can model an attack, you need to understand the system being
attacked. This is the part most people skip, and it's why their models have
gaps.

```
□ What system components does this technique interact with?
□ What processes, services, or protocols are involved?
□ How does the legitimate version of this activity work?
□ What security controls exist that this technique exploits or bypasses?
□ What permissions or access does the attacker need?
```

**How to research this (by platform):**

| Platform | Primary Documentation | Key Resources |
|----------|----------------------|---------------|
| **Windows** | Microsoft Learn, Sysinternals docs | Mark Russinovich's resources, Windows Internals book, MSDN API documentation |
| **Linux** | man pages, kernel.org docs | Linux source (elixir.bootlin.com), distro-specific docs (RHEL, Ubuntu) |
| **macOS** | Apple Developer docs | Apple Platform Security Guide, Jonathan Levin's resources |
| **Azure / Entra ID** | Microsoft Learn (Azure docs) | Azure Threat Research Matrix (ATRM), ROADtools documentation |
| **AWS** | AWS Documentation | Rhino Security Labs, Stratus Red Team docs |
| **GCP** | Google Cloud docs | GCP-specific threat research from community |
| **Containers / K8s** | Kubernetes.io docs | OWASP Kubernetes Security, Aqua Security research |
| **Network Devices** | Vendor-specific docs | MITRE ATT&CK ICS matrix, vendor security guides |

**Cross-platform research sources (all platforms):**

1. The MITRE ATT&CK page for the technique
2. Conference talks and blog posts from researchers (SpecterOps, Red Canary,
   CrowdStrike, Elastic, Microsoft Threat Intelligence, Mandiant, SentinelOne,
   Wiz, Aqua Security, etc.)
3. Academic papers when the technique involves novel mechanisms
4. The TIRED Labs TRR Library — check if someone has already researched a
   related technique

**Checkpoint:** Do you understand WHY the technique works, not just WHAT it
does? Can you trace the path from the attacker's action to the effect on the
system?

### Step 3: Define Your Scope

Before building the DDM, lock down your scope. This prevents scope creep and
forces you to make deliberate decisions about what's in and what's out.

**3a. Write a Scope Statement**

One sentence describing exactly what this TRR covers. Be specific about
platform, variant, and boundaries.

Good: "File-based web shell execution via IIS on Windows"
Bad: "Web shells"

Good: "WMI Event Subscription persistence on Windows"
Bad: "WMI attacks"

Good: "Disabling or modifying system firewalls on Linux via iptables/nftables"
Bad: "Firewall tampering"

**3b. Build an Exclusion Table**

What is explicitly out of scope, and why? Every exclusion should reference the
DDM inclusion test.

| Excluded Item | Rationale |
|---|---|
| *Example: Fileless/memory web shells* | *Different essential operations; separate TRR* |
| *Example: Specific tools (China Chopper, etc.)* | *Tangential — same operations regardless of tool* |
| *Example: Linux/macOS web servers* | *Different platform with different architecture; separate TRR* |
| *Example: Encoding/obfuscation techniques* | *Tangential — doesn't change essential operations* |

Use these standard rationale categories:
- **"Tangential"** = Attacker-controlled, fails the immutability test
- **"Different essential operations"** = Warrants a separate TRR
- **"Same essential operations"** = Same procedure, not a new entry
- **"Different platform"** = Different architecture may mean different operations

**3c. Build an Essential Constraints Table**

What MUST be true for this technique to work? This feeds directly into your DDM.

| # | Constraint | Essential? | Immutable? | Observable? | Telemetry |
|---|-----------|------------|------------|-------------|-----------|
| 1 | *Example: Web server must be running and accepting HTTP requests* | ✅ | ✅ | ✅ | *Network logs* |
| 2 | *Example: Malicious file must exist in web-accessible directory* | ✅ | ✅ | ✅ | *File monitoring* |

**3d. When to Split vs. Combine TRRs**

A single TRR should cover a single, specific technique for a specific platform
or set of similar platforms. Split into separate TRRs when:

- The technique works fundamentally differently on different platforms (e.g.,
  IIS web shells vs. Apache web shells — different architectures)
- A variant introduces entirely new essential operations (e.g., file-based vs.
  fileless web shells)
- The combined TRR would be unwieldy and lose focus

Combine into a single TRR when:
- The technique works the same way across platforms (rare, but possible)
- Variants share most essential operations and differ only at branch points

**Checkpoint:** Is your scope clear and defensible? Have you documented what's
in and what's out, with rationale for each?

---

## Phase 2: Build the Detection Data Model

**Goal:** Map out every essential operation in the technique and identify where
those operations can be observed.

### Step 4: Map Your Initial Understanding

Open the [Arrows App] and start placing operations.

**Rules for operations:**
- Each operation is a **circle**
- Name them using **"Action Object"** format (verb + noun):

| Good (Action Object) | Bad (Vague/Tool-Focused) |
|---|---|
| Write File | Upload web shell |
| Send Request | Connect to server |
| Spawn Process | Use cmd.exe |
| Match Handler | Process file |
| Execute Code | Run web shell |
| Create Registry Key | Modify system |
| Queue APC | Inject code |
| Compile ASPX | ASP.NET processing |
| Authenticate Session | Log in to Azure |
| Invoke API Call | Use kubectl |

- Use **arrows** to show flow from one operation to the next
- Use **downward arrows** for lower layers of abstraction (implementation
  details of the operation above)
- For multi-machine techniques, you can optionally use color to distinguish
  source vs. target operations (e.g., green for attacker, blue for target),
  but most DDMs use plain black circles
- Add **tags** for specific details (process names, APIs, file paths, ports)

**Structural conventions:**

- **Prerequisites vs. pipeline operations:** Some operations are prerequisites
  that must happen *before* the main execution flow but are not inline with
  the sequential pipeline. For example, writing a file to disk may happen days
  before the HTTP request that triggers execution. Model prerequisites as
  feeding into the appropriate pipeline operation, not as the first step in a
  linear chain.

- **Sub-operations (lower abstraction layers):** When an operation contains a
  notable sub-step that produces its own telemetry, model it as a sub-operation
  with a downward arrow from the parent. Example: "Compile ASPX" is a
  sub-operation of "Execute Code."

- **Branch points and conditional labels:** When the DDM branches, label each
  arrow with a conditional description:
  - Execute Code → Process Spawn: "If shell calls OS command"
  - Execute Code → Call .NET API: "If in-process API"

**Don't worry about getting it perfect.** The whole point of the next step is
to refine it.

**Checkpoint:** Does your diagram have at least the major operations you
currently understand? Are there any you're unsure about? Mark those with "??".

### Step 5: Iterative Deepening (The Most Important Step)

For EVERY operation in your DDM, ask yourself these questions:

```
1. Do I understand what's actually happening here?
   → If no: research deeper, break it into sub-operations

2. What specific processes, APIs, or network connections are involved?
   → If you don't know: add tags with "?" and research

3. Is this ONE operation, or am I summarizing MULTIPLE operations?
   → If summarizing: split it into its component operations

4. Is this operation ESSENTIAL? Could the attacker skip it?
   → If optional: REMOVE IT from the DDM

5. Is this operation IMMUTABLE? Can the attacker change how it works?
   → If attacker-controlled: mark it as tangential or remove it

6. How does this operation cause or lead to the next operation?
   → If you can't explain the connection: there's a gap in your
     understanding. Research it.
```

**Repeat this for every operation until there are no more "??" marks.**

This is where most of your research time will be spent. It's normal for this
step to take hours or even days for a complex technique. Don't rush it.

**Checkpoint:** Can you explain every operation in your DDM in detail? Are
there any question marks left? If yes, keep going.

### Step 6: Add Telemetry

For each remaining operation, identify what could observe it. The available
telemetry depends on the platform:

**Windows:**
```
□ Windows Event Log entries (Security, System, Application, etc.)
□ Sysmon events (Event IDs 1-29 — check the Sysmon schema for your version)
□ ETW (Event Tracing for Windows) providers
□ EDR telemetry (process, file, registry, network)
□ Application-specific logs (IIS W3C, SQL Server, Exchange, etc.)
□ WMI event traces
□ File system artifacts (prefetch, shimcache, amcache)
□ Registry artifacts
```

**Linux:**
```
□ auditd logs (syscall auditing)
□ syslog / journald entries
□ eBPF-based telemetry
□ EDR telemetry
□ Application-specific logs (Apache/Nginx access logs, auth.log, etc.)
□ File integrity monitoring (AIDE, OSSEC, etc.)
□ Network connection logs (conntrack, netfilter)
□ Process accounting (pacct)
```

**macOS:**
```
□ Unified Logging (log stream/log show)
□ Endpoint Security Framework events
□ EDR telemetry
□ Application-specific logs
□ TCC (Transparency, Consent, and Control) database
□ Launch daemon/agent plist monitoring
```

**Cloud (Azure, AWS, GCP):**
```
□ Cloud audit logs (Azure Activity Log, AWS CloudTrail, GCP Cloud Audit)
□ Identity provider logs (Entra ID Sign-in/Audit, AWS IAM Access Analyzer)
□ Resource-specific logs (storage access logs, network flow logs)
□ CSPM/CNAPP telemetry
□ API call logging
```

Add telemetry as tags on the relevant operation nodes. If an operation has NO
known telemetry, tag it "No direct telemetry" — that's a gap worth documenting.

**Telemetry label convention:** Use descriptive labels that include both the
event ID and event name:

| ✅ Good | ❌ Bad |
|---------|--------|
| Sysmon 1 (ProcessCreate) | Sysmon 1 |
| Sysmon 11 (FileCreate) | Sysmon EID 11 |
| Win 4688 (ProcessCreate) | Event 4688 |
| Win 4663 (SACL) | Windows Security 4663 |
| IIS W3C | IIS Logs |

**Important:** Put telemetry on the operation it DIRECTLY observes, not on a
nearby operation. Sysmon 1 (Process Create) goes on the "Spawn Process" node,
not on the "Execute Code" node.

### Step 7: Find Alternate Paths

For EVERY operation, ask: **"Is there another way to do this?"**

```
□ Can this operation be accomplished via a different API?
□ Can this operation be accomplished via a different protocol?
□ Can this operation be skipped entirely while still achieving the technique?
□ Can the attacker reach the same outcome through a completely different
  chain of operations?
```

If you find an alternate path, apply the procedure-defining question:

- Does the alternate path change the **essential operations**?
  → **Yes:** This is a different procedure. Add the branch to the DDM.
  → **No:** This is the same procedure with different implementation details
    (tangential). Note it but don't create a new path.

If new paths are discovered:
- Add alternate paths to the DDM
- Use branching to show different options
- Label branches with conditions
- Apply Steps 5-6 to the new operations

**Checkpoint:** Have you explored every realistic alternate path? Have you
asked "is there another way?" for every single operation?

---

## Phase 3: Identify Procedures

**Goal:** Determine how many distinct execution paths exist in your DDM.

### Step 8: Assign Procedure IDs

For each distinct procedure:

```
Format: TRR####.PLATFORM.LETTER
Example: TRR0000.WIN.A

Where:
  TRR#### = TRR ID (placeholder until assigned by the repository)
  PLATFORM = WIN, LNX, MAC, AD, AZR, AWS, GCP, K8S, NET, etc.
  LETTER = A, B, C, etc. (one per procedure)
```

Create a procedure table:

```markdown
| ID | Name | Summary | Distinguishing Operations |
|----|------|---------|--------------------------|
| TRR0000.WIN.A | Descriptive Name | One-sentence summary | What makes this path unique |
| TRR0000.WIN.B | Descriptive Name | One-sentence summary | What makes this path unique |
```

The "Distinguishing Operations" column is important — it forces you to
articulate exactly what essential operation(s) make each procedure unique.

---

## Phase 4: Validate Everything

**Goal:** Make sure your model is complete, accurate, and useful before writing
the TRR.

### Step 9: Run the Checklists

**Completeness Check:**
```
□ All operations in the DDM pass the inclusion test (essential + immutable)
□ All operations are well-understood (no "??" marks remain)
□ All realistic alternate paths have been explored
□ Telemetry has been identified for each operation (or gaps noted)
□ Procedures are distinct (different essential operations, not just different
  tools)
□ Scoping decisions are documented with rationale
```

**Accuracy Check:**
```
□ Technical details are correct (verified against documentation)
□ No assumptions are hiding in the model
□ No tangential elements are in the DDM
□ The model matches real-world implementations
□ References are cited for technical claims
□ DDM follows structural conventions (prerequisites, sub-operations, branches)
```

If any check fails, go back and fix it before proceeding.

### Step 10: Create Per-Procedure DDM Exports

Once the master DDM is validated, create the export set:

1. **Master DDM:** Contains all operations, all paths, all telemetry — the
   complete picture. All arrows in black.

2. **Per-procedure DDM exports:** For each procedure, use the same master
   layout but highlight the active path using **red arrows**. Non-active paths
   remain in black for context.

This convention (from TRR0016) allows readers to see both the complete picture
and each procedure's specific path at a glance.

**Naming convention:**
```
Master:      ddm_trr####_platform.json     (Arrows app JSON, all black arrows)
             ddm_trr####_platform.png      (master image)
Procedure A: trr####_platform_a.json       (Arrows app JSON, red arrows)
             trr####_platform_a.png        (referenced in TRR)
Procedure B: trr####_platform_b.json/.png
Procedure C: trr####_platform_c.json/.png
```

### Step 11: Get a Second Opinion

If possible, have someone else review your DDM and research notes. Fresh eyes
catch things you've become blind to. Ask them:

- "Does this make sense?"
- "Do you see any paths I missed?"
- "Is there anything here that seems wrong or unclear?"

---

## Next: Write the TRR

Your research is complete. Your DDM is validated. Your procedures are
identified. Now write it up using `TECHNIQUE-RESEARCH-REPORT-OUTLINE.md` for
the section-by-section structure and writing guidance.

---

## Quick Reference: DDM Conventions

| Element | Convention |
|---------|-----------|
| Operations | Circles with "Action Object" naming |
| Flow | Horizontal arrows (left to right) |
| Abstraction layers | Downward arrows (higher to lower) |
| Source/target distinction (optional) | Green circles for source, blue for target — only when multi-machine context matters |
| Details | Tags (process names, APIs, file paths, etc.) |
| Telemetry | Tags on the operation they observe, using descriptive labels: `Sysmon 1 (ProcessCreate)` not `Sysmon 1` |
| Unknowns | "??" marks (must be resolved before finalizing) |
| Branch points | Multiple arrows leaving one operation, labeled with conditions |
| Prerequisites | Separate nodes feeding into the pipeline (not inline) |
| Active path (per-procedure) | Red arrows on the procedure's path; black for context |

---

## References

### Methodology

- [Threat Detection Engineering: The Series — VanVleet]:
  https://medium.com/@vanvleet/threat-detection-engineering-the-series-7fe818fdfe62
- [Improving Threat Identification with Detection Modeling — VanVleet]:
  https://medium.com/@vanvleet/improving-threat-identification-with-detection-data-models-1cad2f8ce051
- [Technique Analysis and Modeling — VanVleet]:
  https://medium.com/@vanvleet/technique-analysis-and-modeling-b95f48b0214c
- [Creating Resilient Detections — VanVleet]:
  https://medium.com/@vanvleet/creating-resilient-detections-db648a352854
- [Technique Research Reports: Capturing and Sharing Threat Research — VanVleet]:
  https://medium.com/@vanvleet/technique-research-reports-capturing-and-sharing-threat-research-9512f36dcf5c
- [What is a Procedure? — Jared Atkinson]:
  https://posts.specterops.io/on-detection-tactical-to-function-810c14798f63
- [Thoughts on Detection — Jared Atkinson]:
  https://posts.specterops.io/thoughts-on-detection-3c5cab66f511

### TRR Resources

- [TIRED Labs TRR Library]:
  https://library.tired-labs.org
- [TIRED Labs Contribution Guide]:
  https://github.com/tired-labs/techniques/blob/main/docs/CONTRIBUTING.md
- [TRR Specification]:
  https://github.com/tired-labs/techniques/blob/main/docs/TECHNIQUE-RESEARCH-REPORT.md

### Tools

- [Arrows App] (DDM diagramming):
  https://arrows.app/
- [Atomic Red Team] (emulation tests):
  https://github.com/redcanaryco/atomic-red-team
- [Stratus Red Team] (cloud emulation):
  https://github.com/DataDog/stratus-red-team
- [MITRE ATT&CK]:
  https://attack.mitre.org/
- [Azure Threat Research Matrix]:
  https://microsoft.github.io/Azure-Threat-Research-Matrix/

[TIRED Labs TRR spec]: https://library.tired-labs.org
[Arrows App]: https://arrows.app/
[Atomic Red Team]: https://github.com/redcanaryco/atomic-red-team
