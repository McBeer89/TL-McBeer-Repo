# TRR Research Methodology — A Practical Guide

**Based on:** VanVleet's Detection Engineering Methodology (TIRED Labs)
**Purpose:** A step-by-step process for researching any attack technique and
producing a submission-quality Technique Research Report (TRR) with Detection
Data Models (DDMs).
**Audience:** Entry-level detection engineers or anyone new to the methodology.

---

## Why TRRs?

A detection query captures very little of the reasoning behind it — which
telemetry was chosen and why, which procedures are covered, what noise was tuned
out, what trade-offs were made. These decisions are environment-specific, and the
details that informed them are not preserved in the query itself.

**A TRR is the lossless capture.** It preserves the complete research, analysis,
DDM, and rationale so that any detection engineer in any environment can make
informed decisions for their own deployment. A detection query is lossy — a TRR
is not.

This is why TRR completeness and accuracy matter. The TRR is the authoritative
source of truth about a technique. Everything downstream — detections, emulation
plans, response playbooks — derives from it.

---

## Before You Start

### What You Need

- A technique to research (a MITRE ATT&CK ID, an Azure Threat Research Matrix
  ID, a known attack name, or a behavior you've observed)
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

### Step 4: Write It Down

Create a research notes file (markdown works great). Document everything you've
learned so far, organized by topic. Include:

- Technique summary
- Scope statement and exclusion table
- Essential constraints table
- Architecture of the affected system
- Key components and how they interact
- Security-relevant details (processes, permissions, file paths, APIs)
- References with links for everything you cite

**This file is your working memory.** You'll come back to it constantly. Keep
it updated as you learn more.

**Checkpoint:** Could another researcher read your notes and understand the
technique without needing to do their own research? If not, fill in the gaps.

---

## Phase 2: Build the Detection Data Model

**Goal:** Map out every essential operation in the technique and identify where
those operations can be observed.

### Step 5: Map Your Initial Understanding

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
- Use **green circles** for source/attacker machine operations
- Use **blue circles** for target machine operations
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

### Step 6: Iterative Deepening (The Most Important Step)

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

### Step 7: Classify Every Element

Go through your entire DDM and classify each element using the DDM inclusion
test:

| Classification | Definition | In DDM? |
|---|---|---|
| **Essential + Immutable + Observable** | Must happen, can't be changed, can be seen | ✅ Include |
| **Essential + Immutable + NOT Observable** | Must happen, can't be changed, but no telemetry exists | ✅ Include (note the gap) |
| **Optional** | Can be skipped without breaking the technique | ❌ Remove |
| **Tangential** | Attacker-controlled (tools, filenames, flags) | ❌ Remove |

**Common mistakes at this step:**
- Including specific tool names as operations (tangential)
- Including command-line parameters (tangential)
- Including specific file names the attacker chose (tangential)
- Keeping optional steps because they're "interesting" (remove them — they
  make it harder to identify distinct procedures later)
- Modeling delivery methods as operations (tangential — how the attacker got
  the file there is separate from what the file does)

### Step 8: Add Telemetry

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
known telemetry, tag it "No direct telemetry" — that's a detection gap worth
documenting.

**Important:** Put telemetry on the operation it DIRECTLY observes, not on a
nearby operation. Sysmon 1 (Process Create) goes on the "Spawn Process" node,
not on the "Execute Code" node.

### Step 9: Find Alternate Paths

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

Examples:
- Using a different file extension (.asp vs .aspx) with the same handler type
  → **same procedure** (extension is tangential)
- Modifying web.config to change handler behavior → **different procedure**
  (introduces a new essential operation: Write Config)
- Using a different tool to upload the file → **same procedure** (delivery
  method is tangential)
- Using `iptables` vs `nft` vs `ufw` to disable a firewall → depends on
  whether the essential operations differ (do they call different kernel
  interfaces, or do they converge at the same netfilter operation?)

If new paths are discovered:
- Add alternate paths to the DDM
- Use branching to show different options
- Label branches with conditions
- Apply Steps 6-8 to the new operations

**Checkpoint:** Have you explored every realistic alternate path? Have you
asked "is there another way?" for every single operation?

---

## Phase 3: Identify Procedures

**Goal:** Determine how many distinct execution paths exist in your DDM.

### Step 10: Trace the Paths

Look at your DDM and trace every possible path from start to finish.

**Key principle:** A procedure is a distinct execution path through essential
operations. Two different tools that execute the same operations = SAME
procedure. Two different operation paths = DIFFERENT procedures.

For each path:
1. Trace it from the first operation to the last
2. Write down the sequence of operations
3. Compare it to every other path
4. If two paths share every essential operation, they're the same procedure
5. If two paths diverge at any essential operation, they're different
   procedures

### Step 11: Assign Procedure IDs

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

### Step 12: Run the Checklists

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

**Utility Check:**
```
□ A detection engineer could build detections from this
□ A red teamer could understand how to execute the technique
□ No environment-specific assumptions are baked in
□ Both common and uncommon procedures are covered
□ Detection gaps (operations with no telemetry) are documented
```

If any check fails, go back and fix it before proceeding.

### Step 13: Create Per-Procedure DDM Exports

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
Master:      ddm_trr0000_platform_all.json  (Arrows app JSON)
Procedure A: trr0000_a.png                  (red arrows on Proc A path)
Procedure B: trr0000_b.png                  (red arrows on Proc B path)
Procedure C: trr0000_c.png                  (red arrows on Proc C path)
```

### Step 14: Get a Second Opinion

If possible, have someone else review your DDM and research notes. Fresh eyes
catch things you've become blind to. Ask them:

- "Does this make sense?"
- "Do you see any paths I missed?"
- "Is there anything here that seems wrong or unclear?"

---

## Phase 5: Detection Strategy

**Goal:** Identify optimal detection points before writing the TRR. This
analysis informs the procedure narratives.

### Step 15: Identify Optimal Detection Points

Using the completed DDM, find the best telemetry for detection:

1. **Look for convergence points** — operations shared by multiple or all
   procedures. A detection at a convergence point covers more of the
   technique's attack surface with fewer detections.

2. **Prefer telemetry closer to the END of the operation chain.** Later
   operations are harder for attackers to avoid and often produce
   higher-fidelity signals.

3. **For each candidate detection point, assess:**
   - How many procedures does this cover?
   - What telemetry sources are available here?
   - How noisy will this be? (What does benign activity look like at this
     operation?)
   - Can an attacker realistically avoid this operation?

4. **If no single point covers all procedures,** identify a group of
   detections that collectively cover all procedures.

5. **Document known blind spots** — procedures or operations where no
   practical telemetry exists. Knowing your gaps is as valuable as knowing
   your coverage.

**Checkpoint:** Does your detection strategy cover all identified procedures?
Are blind spots documented?

---

## Phase 6: Write the TRR

**Goal:** Produce a submission-quality TRR that follows the TIRED Labs format.

### Step 16: Write the Metadata

```markdown
# Technique Name

## Metadata

| Key          | Value              |
|--------------|--------------------|
| ID           | TRR0000            |
| Procedures   | TRR0000.WIN.A, TRR0000.WIN.B |
| External IDs | T####.###, AZT###  |
| Tactics      | Tactic Name        |
| Platforms    | Windows            |
| Contributors | Your Name          |
```

**TRR Name guidance:** The name should be specific and descriptive. It does not
have to mirror ATT&CK naming — use the most accurate name possible. Well-known
names can be included in parentheses.

Examples:
- "Roasting Kerberos Service Tickets (Kerberoasting)"
- "DC Synchronization Attack (DCSync)"
- "File-Based Web Shell Execution via IIS"
- "WMI Event Subscription"

Add a **Scope Statement** if your TRR doesn't cover the entire technique
(e.g., only one platform, only one variant). Be explicit about what's in
scope and what's out.

### Step 17: Write the Technique Overview

This is the **leadership-readable summary.** 1-2 paragraphs. No jargon.
Anyone in cybersecurity should be able to understand it.

After reading this section, the reader should know:
- What the technique is
- How it's generally used
- Why adversaries use it

### Step 18: Write the Technical Background

This is the **bulk of the report.** It should contain everything a reader
needs to understand the technique without going to external sources.

Use subheadings. Cover:
- The technology being abused (architecture, components, protocols)
- How the legitimate system works
- What security controls exist
- Why the technique is effective
- Any technical details common to multiple procedures

**Important:** This section does NOT contain execution steps or procedure
specifics. Those go in the procedure narratives. The technical background gives
the reader the foundation to understand ALL procedures.

### Step 19: Write the Procedure Narratives

For each procedure, write a **narrative** (not a step-by-step list). Cover:
- Prerequisites
- How the execution works (trace through the DDM in prose)
- What makes this procedure distinct
- Key detection opportunities
- Any variations or edge cases

After each narrative, include:
- The per-procedure DDM image (with red arrows on the active path)
- A short paragraph describing what the DDM shows, calling out interesting
  nodes, detection opportunities, and gaps

### Step 20: Complete the Remaining Sections

```markdown
## Available Emulation Tests

| ID             | Link             |
|----------------|------------------|
| TRR0000.WIN.A  | [Link if known]  |
| TRR0000.WIN.B  | [Link if known]  |

## References

- [Reference Name]: URL
```

**Emulation tests:** It is not required to search out emulation tests, but if
you are aware of any, include them. The most common sources are:

- **Atomic Red Team** (Red Canary) — the largest open-source library with
  1,700+ tests covering hundreds of ATT&CK techniques across Windows, Linux,
  macOS, and cloud platforms. This is often the first place to check.
  Browse tests at: https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/
- **Stratus Red Team** (DataDog) — focused on cloud attack emulation (AWS,
  Azure, GCP, Kubernetes)
- **DVWA, WebGoat, etc.** — for web application techniques
- **Custom scripts or POCs** from security researchers (often found on GitHub)
- **Vendor-specific test suites** (if available for your platform)

Emulation tests are useful for two purposes in TRR development:
1. **Validating your DDM** — does your model cover the operations performed
   by the test?
2. **Helping detection engineers** — linking tests to specific procedures lets
   them generate telemetry to validate their detections

### Step 21: Final Review

Read the entire TRR from start to finish as if you've never seen it before.
Ask yourself:

```
□ Is the Technique Overview clear enough to email to leadership?
□ Is the Technical Background complete enough to stand alone?
□ Are the procedure narratives accurate and match the DDMs?
□ Does each per-procedure DDM clearly show its active path (red arrows)?
□ Are all references cited?
□ Does the format match existing TRRs in the repository?
□ Would I be confident submitting this?
```

---

## Quick Reference: Common Pitfalls

| Pitfall | How to Avoid It |
|---------|----------------|
| **Tool-focused analysis** | Ask "what operation is this tool performing?" and model the operation, not the tool |
| **Including optional operations** | For every operation ask "can the attacker skip this and still succeed?" If yes, remove it |
| **Tangential elements in DDM** | If the attacker controls it (filenames, flags, tools, delivery methods), it's tangential — don't model it |
| **Incomplete alternate paths** | For every operation ask "is there another way to do this?" |
| **Assumptions hiding as facts** | If you can't cite a source for a technical claim, it might be an assumption. Verify it. |
| **Rushing to the TRR** | The DDM must be solid before you write. A good DDM makes the TRR easy. A bad DDM makes it wrong. |
| **Confusing procedures** | Same operations + different tools = same procedure. Different operations = different procedures. |
| **Skipping the technology research** | You can't model what you don't understand. Phase 1 is the foundation for everything. |
| **Prerequisites as pipeline steps** | File writes and other setup operations may happen days before execution. Model them as prerequisites feeding into the correct node, not as Step 1 in a linear chain. |
| **Grouping telemetry on one node** | Each telemetry source goes on the specific operation it directly observes. Sysmon 1 goes on "Spawn Process," not on "Execute Code." |
| **Skipping the scoping step** | Without explicit scoping, you'll either try to cover too much or leave ambiguity about what's included. Document it before building the DDM. |

---

## Quick Reference: DDM Conventions

| Element | Convention |
|---------|-----------|
| Operations | Circles with "Action Object" naming |
| Flow | Horizontal arrows (left to right) |
| Abstraction layers | Downward arrows (higher to lower) |
| Source machine ops | Green circles |
| Target machine ops | Blue circles |
| Shared ops | Black circles |
| Details | Tags (process names, APIs, file paths, etc.) |
| Telemetry | Tags on the operation they observe |
| Unknowns | "??" marks (must be resolved before finalizing) |
| Branch points | Multiple arrows leaving one operation, labeled with conditions |
| Prerequisites | Separate nodes feeding into the pipeline (not inline) |
| Active path (per-procedure) | Red arrows on the procedure's path; black for context |

---

## Quick Reference: Platform Identifiers

| Platform | ID | Notes |
|----------|----|-------|
| Windows | WIN | Most common; includes server and desktop |
| Linux | LNX | May need to distinguish distros if operations differ |
| macOS | MAC | Apple-specific security framework |
| Active Directory | AD | On-prem AD-specific techniques |
| Azure / Entra ID | AZR | Cloud and identity platform |
| AWS | AWS | Amazon Web Services |
| GCP | GCP | Google Cloud Platform |
| Kubernetes | K8S | Container orchestration |
| Network Devices | NET | Routers, switches, firewalls |
| SaaS / Office 365 | SAS | Cloud application techniques |

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
