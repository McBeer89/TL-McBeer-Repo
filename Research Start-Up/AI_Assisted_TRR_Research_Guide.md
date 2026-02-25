# AI-Assisted Technique Research — A Practical Guide

**Based on:** The workflow used to produce a first TRR — from zero experience
to a reviewed Technique Research Report with validated DDMs and derivative
documents.

**Purpose:** Document exactly how to use a large language model — specifically
Claude — as a research partner for producing TRRs and DDMs following the TIRED
Labs methodology.

**Audience:** Anyone who wants to replicate this workflow. No prior TRR
experience required. Basic security knowledge assumed.

---

## What This Guide Is (and Isn't)

This is not a replacement for the methodology itself. You still need:

- **TRR_Research_Methodology_Guide.md** — The step-by-step analytical process
  (what to do)
- **TRR-DDM-Research-Prompt-Long.md** — The system prompt that teaches the AI
  the methodology (what to tell the AI)
- **This guide** — How to work with the AI effectively across the full
  lifecycle of a TRR (how to do it together)

The methodology guide tells you *what* to do. The research prompt tells the
*AI* what to do. This guide tells you how to orchestrate the collaboration so
the AI amplifies your work rather than leading you astray.

### What You Should Expect

The AI doesn't do the work *for* you; it acts as an always-available subject
matter expert, a sounding board for analytical decisions, and a tireless editor.

This process took weeks, not hours. The AI accelerates research and writing
dramatically, but deep technical analysis still requires time. Expect to
iterate. Expect to be wrong about things. Expect the AI to be wrong about
things too. The methodology's phase gates and validation checkpoints exist
precisely because neither you nor the AI will get it right on the first pass.

---

## Part 1: Setting Up Your Environment

### The Core Platform: Claude Projects

The single most important infrastructure decision is using **Claude Projects**
(available in Claude Pro/Team). A Project gives you:

- **A persistent system prompt** — Load the research prompt once. Every
  conversation in the project inherits it.
- **A project knowledge base** — Upload reference materials that persist across
  conversations. The AI can search these at any time.
- **Conversation history** — The AI builds memory across sessions within a
  project, retaining context about your research progress, decisions, and
  open questions.

This matters because TRR research happens over days or weeks. Without a
Project, you'd need to re-explain the methodology, re-upload references, and
re-establish context every single session. With a Project, you pick up where
you left off.

**Setup steps:**

1. Create a new Claude Project (e.g., "TRR Research")
2. Paste the contents of `TRR-DDM-Research-Prompt-Long.md` as the project's
   system prompt (Project Instructions)
3. Upload reference materials to the project knowledge base (see below)

### What to Put in Project Knowledge

The project knowledge base is your AI's reference library. It determines what
the AI can draw from when answering questions. Curate it deliberately.

**Essential — upload these first:**

- The TIRED Labs methodology articles (VanVleet's Medium series). These are
  the theoretical foundation. If you can get full-text copies, upload them
  directly. The key articles are:
  - *Identifying and Classifying Attack Techniques*
  - *Improving Threat Identification with Detection Modeling*
  - *Technique Analysis and Modeling*
  - *Creating Resilient Detections*
  - *Technique Research Reports: Capturing and Sharing Threat Research*
  - *The Series* overview article
- The TRR Research Methodology Guide (`TRR_Research_Methodology_Guide.md`)
- Any published TRRs you want the AI to use as style references (available at
  https://library.tired-labs.org)

**Add as you go:**

- Research sources relevant to your specific technique (Microsoft Learn pages,
  security blog posts, API documentation)
- Your scoping document and research notes as they develop
- DDM JSON files and procedure drafts for review
- Lab findings and telemetry captures

**Supplemental context (if available):**

- A project overview document explaining the broader TIRED Labs vision,
  particularly the discipline-neutral framing of TRRs vs. derivative documents
- Published DDM JSON files from existing TRRs (gives the AI concrete examples
  of the Arrows.app format)

The AI performs dramatically better when it has concrete examples of finished
work to reference. A single published TRR in the knowledge base does more for
output quality than paragraphs of abstract instruction.

### Model Selection

**Use the strongest reasoning model available for analytical work.** The
recommended models are Claude Opus and Claude Sonnet.

- **Opus** — Best for deep analytical reasoning: DDM construction, procedure
  identification, scoping decisions, validating the inclusion test, catching
  inconsistencies in your logic. Use this for any work that requires the AI to
  push back on your assumptions or identify gaps you've missed.
- **Sonnet** — Excellent for writing, editing, formatting, and execution tasks:
  drafting TRR prose, generating Arrows.app JSON, writing lab scripts, creating
  detection specifications. Also useful for routine research queries.

In practice, the split is roughly: Opus for *thinking* work, Sonnet for
*production* work. When budget or rate limits are a concern, Sonnet handles
most tasks well — but for the critical analytical moments (scoping, DDM
validation, procedure differentiation), Opus's deeper reasoning catches things
Sonnet misses.

### Supporting Tools

The AI is your research partner, not your entire toolkit. You'll also need:

| Tool | Purpose | Notes |
|------|---------|-------|
| **Arrows.app** | DDM diagramming | Free, web-based. The AI generates JSON you paste in. |
| **GitHub repository** | Version control | Track every revision of your TRR, DDM, and supporting docs. |
| **A text editor** | Drafting and notes | VS Code, Obsidian, whatever you prefer. |
| **A lab environment** | Validation | VM or dedicated machine for procedure recreation. |

**Optional but useful:**

| Tool | Purpose | Notes |
|------|---------|-------|
| **Claude Code** | Implementation work | Useful for writing lab scripts, automating file operations, building tooling. Has subagent capabilities for complex multi-step tasks. |
| **Cline (VS Code extension)** | Automated file ops and git | MCP server integration for file system, git, and browser automation. Good for routine execution while keeping Claude.ai free for analysis. |
| **Local LLM (e.g., via LM Studio or Ollama)** | Offline work | Any local model suited for research, code, or security analysis. Good for drafting and routine tasks without burning API credits. |

**Note on Cline + local models:** When using Cline with a local LLM, the
model's system prompt works in tandem with the `.clinerules` file included in
this repository. The system prompt provides the analytical methodology (how to
think), while `.clinerules` provides the workflow and tool usage (what to do
and when). Both are needed for the best results.

The key principle: **use Claude.ai Projects for strategic thinking and
analysis, use other tools for execution.** Don't waste your Opus context
window on tasks that a code agent or local model can handle.

---

## Part 2: The Research Workflow

This section maps the TRR Research Methodology phases to specific AI
interactions. It assumes you've read the methodology guide and have your
Project set up.

### Phase 1: Building Your Understanding

**What you're doing:** Learning the technique well enough to scope it.

**How the AI helps:** It's a patient, knowledgeable tutor who can explain
OS internals, protocols, and APIs at whatever depth you need.

**Session structure:**

Start a conversation in your Project. Begin with something like:

> *"I'm starting research on T1505.003 — Server Software Component: Web Shell.
> My focus is file-based web shells on IIS/Windows. I have basic security
> knowledge but no prior experience with IIS internals. Walk me through what I
> need to understand about how IIS processes requests."*

The key elements of this opening:

1. **Technique ID and name** — anchors the conversation
2. **Your intended scope** — even a rough one, so the AI doesn't go too broad
3. **Your current knowledge level** — lets the AI calibrate its explanations

From here, have a genuine dialogue. Ask follow-up questions. Say "I don't
understand that part" when you don't. The AI will adjust.

**What to ask for specifically:**

- "Explain the IIS request pipeline from the moment an HTTP request arrives to
  when code executes" — forces a sequential walkthrough of the system
- "What's the difference between X and Y?" — clarifies distinctions you'll
  need for procedure identification
- "What would a legitimate version of this activity look like?" — essential
  for understanding what's normal vs. suspicious
- "What prerequisites must be true for this to work?" — feeds directly into
  your constraints table
- "What security controls exist that this technique bypasses?" — contextualizes
  the attacker's challenge

**Critical habit: Verify the AI's claims.** The AI is very good at explaining
systems but occasionally gets specific details wrong — particularly around
exact API names, specific version behaviors, or obscure configuration options.
When the AI makes a specific technical claim that matters for your DDM (e.g.,
"ASP.NET compilation spawns csc.exe as a child of w3wp.exe"), verify it against
official documentation or lab testing before building your model around it.

**When to move on:** You can explain the technique in 2-3 sentences without
mentioning any tools. You understand the underlying system well enough to trace
the path from attacker action to system effect. You have a rough mental model
of the operation chain.

### Phase 1 Continued: Scoping

**What you're doing:** Defining exactly what your TRR covers and what it
excludes.

**How the AI helps:** It challenges your scoping decisions and helps you
articulate rationale using the DDM inclusion test.

**How to use it:**

Present your proposed scope and ask the AI to stress-test it:

> *"Here's my proposed scope: file-based web shell execution via IIS on
> Windows. I'm excluding fileless shells, ASP.NET Core, PHP via FastCGI, and
> non-Windows platforms. Does this make sense? Am I missing anything that should
> be excluded? Is anything I've excluded actually in scope?"*

The AI is particularly good at catching things you haven't thought of. For
example, when researching IIS web shells, the AI might raise the question of
whether Server-Side Includes (SSI) via `ssinc.dll` constitute a separate
procedure or follow the same essential operations as the other procedures. That
kind of discussion can lead to a well-reasoned decision — document SSI in
Technical Background but don't treat it as a separate procedure — with clear
rationale.

**Build your exclusion table collaboratively.** For each exclusion, ask the AI
to confirm whether the rationale is "tangential," "different essential
operations," or "different platform." If the AI disagrees with your
categorization, talk it through. The disagreement usually reveals something
important about the technique.

**Build your constraints table.** Ask the AI: "What MUST be true for this
technique to work on IIS?" Then apply the inclusion test to each constraint
together. This table becomes the skeleton of your DDM.

### Phase 2: DDM Construction

**What you're doing:** Building the Detection Data Model — the visual map of
essential, immutable, observable operations.

**How the AI helps:** It generates Arrows.app JSON, identifies operations you
missed, applies the inclusion test, and maps telemetry.

This is the most iterative phase and the one where AI assistance provides the
most leverage. Building a DDM by hand in Arrows.app, figuring out the JSON
format, and trying to hold the entire operation chain in your head
simultaneously is where most people would get stuck. The AI can generate valid
Arrows.app JSON from a textual description of operations, which you then paste
into the app and refine visually.

**The iterative loop:**

1. **Describe your current understanding** of the operation chain in natural
   language to the AI
2. **Ask the AI to generate Arrows.app JSON** for that chain
3. **Paste the JSON into Arrows.app** and look at it visually
4. **Identify problems** — missing operations, wrong connections, operations
   that are too vague, tangential elements that slipped in
5. **Discuss the problems with the AI** — this is where the deepest learning
   happens
6. **The AI generates updated JSON** incorporating your corrections and its
   suggestions
7. **Repeat** until the model stabilizes

**Specific things to ask the AI during DDM construction:**

- "Is [operation X] essential, or could an attacker skip it?" — Apply the
  inclusion test to every operation
- "Is [operation X] immutable, or could an attacker change how this works?" —
  Catches tangential elements masquerading as essential operations
- "What telemetry could observe [operation X]?" — The AI is very good at
  mapping Windows event IDs, Sysmon events, and EDR telemetry to operations
- "Should [operation X] be a prerequisite feeding into the pipeline, or an
  inline step?" — Structural modeling question
- "Are there any alternate paths through [operation X]?" — Branch discovery

**DDM structural conventions the AI should follow:**

The research prompt includes these conventions, but reinforce them in
conversation if the AI drifts:

- Prerequisites (like file creation) feed into the pipeline; they aren't the
  first step in a linear chain
- Sub-operations (like ASPX compilation within code execution) use downward
  arrows
- Branch points are labeled with conditions ("if OS command," "if in-process")
- Telemetry tags go on the specific operation they observe, not grouped
  elsewhere
- Use descriptive telemetry labels: "Sysmon 1 (ProcessCreate)" not "Sysmon 1"

**The JSON workflow in practice:**

When you ask for Arrows.app JSON, the AI generates a complete JSON blob you
can paste directly into Arrows.app (File → Import → JSON). The first version
will usually need adjustments — node positions may overlap, labels may be
cramped, arrows may cross awkwardly. Rearrange the visual layout in Arrows.app
manually, then export the JSON back out if you need the AI to modify the
content later.

Over time, you'll build a master DDM JSON file in your repository. Each
iteration, you can paste the current JSON back to the AI and ask for specific
modifications rather than regenerating from scratch.

### Phase 2 Continued: Procedure Identification

**What you're doing:** Determining how many distinct execution paths exist in
your DDM.

**How the AI helps:** It traces paths through the model and helps you decide
what constitutes a genuinely different procedure vs. the same procedure with
different implementation details.

The critical question at every branch point: **"Does this change the essential
operations, or just the implementation details?"**

For example, with IIS web shells, this question might yield three procedures:

- **Procedure A vs. B:** After Execute Code, does the shell spawn a child
  process (Process Spawn) or operate through .NET APIs (Call .NET API)? The
  post-execution essential operation is different → different procedures.
- **Procedure A/B vs. C:** Does the attacker need to write a web.config to
  change handler mappings (Write Config)? This introduces a new essential
  operation that also changes what Match Handler operates against → different
  procedure.

Ask the AI to trace each path from start to finish and articulate what makes it
unique. If the AI can't clearly state the distinguishing operations, the
procedures may not actually be distinct.

### Phase 3: Validation and Iteration

**What you're doing:** Stress-testing the model before writing the TRR.

**How the AI helps:** It plays devil's advocate and runs the validation
checklists.

Ask the AI to run the validation questions from the methodology:

> *"Here's my current DDM with three procedures. Run the full validation
> checklist: Can an attacker execute this technique using ONLY these
> operations? Does every operation pass the inclusion test? Are there tangential
> elements that slipped through? Does this cover known tools and methods?"*

The AI is good at this because it can hold the entire model in context and
check each operation systematically. It will often catch things like:

- An operation that's actually optional (fails essential test)
- A specific API name that's really a tangential choice (fails immutable test)
- A missing operation that's needed to connect two steps
- A telemetry source that's tagged on the wrong operation

**Lab validation:** Once your DDM is theoretically sound, validate it in a lab.
The AI can help you write lab recreation scripts (PowerShell for IIS setup,
test web shells for each procedure, Sysmon configuration). But the lab is where
reality challenges theory. Examples of things lab testing can reveal:

- Configuration constraints the AI noted as possible but that only become
  confirmed through actual execution errors (e.g., buildProviders scope
  requirements in IIS web.config)
- Telemetry gaps predicted by the DDM that are empirically validated (e.g.,
  zero Sysmon 1 events for in-process execution)
- Limitations in monitoring approaches that look sound on paper (e.g., SACL
  auditing configured for write access won't fire on read-only operations)

Feed lab findings back to the AI. Some will refine the DDM. Some will refine
the TRR prose. Some will inform the detection methods document.

### Phase 4: Writing the TRR

**What you're doing:** Producing the final document.

**How the AI helps:** It drafts, edits, and refines prose to match the
expected style and structure.

This phase is where the AI saves the most raw time, but it's also where you
need to be most vigilant about the AI's natural tendencies.

**The AI's writing tendencies you'll need to correct:**

1. **Detection-oriented language.** The AI naturally gravitates toward phrases
   like "this is a strong detection opportunity" or "this provides high-fidelity
   alerting." TRRs are discipline-neutral. The AI knows this (it's in the
   prompt), but it slips. Watch for it and correct it.

2. **Verbosity.** The AI's first drafts of procedure narratives will usually
   re-walk the entire shared pipeline for each procedure. The correct approach:
   "This procedure shares the same pipeline as Procedure A through Execute Code.
   It diverges at..." then describe only what's unique.

3. **Over-explaining scope.** The AI tends to write paragraph-length
   justifications for exclusions. The TRR should have a concise list with
   one-line rationale per exclusion.

4. **Technique Overview bloat.** The AI often writes 6-8 sentences when 2-4
   will do. VanVleet's style is brief and direct. Push for conciseness.

**The revision cycle:**

Expect your TRR to go through multiple major revisions. Each revision should
address specific categories of problems. A typical progression:

- **Early revisions:** Remove detection-oriented language from procedure
  narratives
- **Middle revisions:** Condense verbose procedure descriptions, eliminate
  re-walking of the shared pipeline
- **Late revisions:** Tighten scope statement, shorten technique overview,
  refine DDM descriptions

This is normal. Plan for 3-5 revision passes. Each pass, give the AI specific
instructions about what category of problem to fix. Don't try to fix everything
at once.

**Effective revision prompts:**

> *"Review this procedure narrative. Remove any detection-oriented language.
> The TRR documents the technique; teams document their response."*

> *"This procedure narrative re-walks operations already covered in Procedure A.
> Rewrite it to state what's shared in one sentence, then focus only on what's
> unique."*

> *"The technique overview is 8 sentences. Condense it to 3-4 sentences maximum.
> Match VanVleet's published style: brief and direct."*

### Phase 5: Derivative Documents

**What you're doing:** Producing team-specific outputs from the completed TRR.

**How the AI helps:** It translates DDM operations and telemetry into
detection specifications, lab guides, and other derivative documents.

Derivative documents are written *after* the TRR is complete and reviewed.
They are separate files. They are NOT part of the TRR.

For the Detection Methods document, the AI can:

- Generate detection specifications for each DDM operation with telemetry
- Classify each detection (Inherently Suspicious, Suspicious Here, Suspicious
  in Context)
- Build the procedure coverage matrix
- Document known blind spots with mitigation options
- Incorporate lab evidence

For the Lab Recreation Guide, the AI can:

- Generate environment setup scripts
- Write per-procedure test cases
- Create telemetry capture and validation procedures
- Document expected results

The same principle applies: the AI drafts, you validate, you iterate.

---

## Part 3: Patterns and Anti-Patterns

### Patterns That Work

**1. Phase gates with explicit validation.**

Don't let the AI rush ahead. At the end of each phase, ask it to summarize its
understanding and run the validation checklist before proceeding. This catches
drift and errors early.

> *"Before we move to DDM construction, summarize what we've established so far:
> scope, exclusions, essential constraints, and your understanding of the IIS
> pipeline. I want to make sure we're aligned."*

**2. Asking the AI to argue against itself.**

After the AI proposes something — a scope decision, a DDM operation, a
procedure distinction — ask it to argue the opposite position:

> *"You said SSI should be treated as the same procedure as A and B. Make the
> argument that it should be a separate procedure. Then tell me which argument
> is stronger."*

This surfaces nuance that the AI wouldn't volunteer unprompted.

**3. Showing the AI published examples.**

When the AI's output doesn't match the expected style, don't describe the style
abstractly — show it a concrete example:

> *"Here's how VanVleet's TRR0016 handles procedure narratives: [paste example].
> Match this style for my Procedure B narrative."*

The project knowledge base is ideal for this. Upload published TRRs so the AI
can reference them at any time.

**4. Separating thinking from production.**

Use different conversations for different purposes:

- A long-running "research" conversation for deep analytical discussion,
  scoping debates, and DDM iteration
- Separate conversations for production tasks: "Write the Technical Background
  section," "Generate the Procedure C DDM JSON," "Draft the lab guide for
  Procedure A"

This keeps the research conversation focused and prevents production-oriented
detail from burying the analytical thread.

**5. Capturing decisions in writing.**

When you and the AI make a significant analytical decision (e.g., "SSI follows
the same essential operations as Proc A/B and is not a separate procedure"),
document it in a running research notes file. Upload that file to project
knowledge. This prevents revisiting settled questions in later sessions.

### Anti-Patterns to Avoid

**1. Accepting the AI's first answer without pushback.**

The AI is confident even when wrong. It will present a plausible-sounding
analysis that has a subtle error — a tangential element framed as essential, a
missing operation glossed over, a telemetry source mapped to the wrong node.
Your job is to push back. Ask "why?" Ask "are you sure?" Ask "what would
happen if we removed this operation — would the technique still work?"

**2. Letting the AI lead the analytical process.**

The methodology is structured for a reason. The AI should work within the
phase structure, not skip ahead. If you ask about scoping and the AI starts
suggesting detection strategies, redirect it:

> *"We're still in Phase 1. I need to finish the exclusion table before we
> touch the DDM. Let's focus on what's in scope and what's out."*

**3. Using the AI as a search engine replacement.**

The AI's training knowledge is useful but not current and not always accurate
for specific technical details. For authoritative information about how a
specific Windows API works, read the Microsoft documentation. The AI is best
used to *explain* what you're reading, not to *replace* reading it.

**4. Trying to complete the entire TRR in one session.**

Context windows are large but not infinite. Complex TRR research benefits from
multiple focused sessions over days, not one marathon session. Each session
should have a clear goal: "Today we're finishing the scoping document," "Today
we're building the initial DDM," "Today we're validating Procedure C."

**5. Skipping lab validation because the AI's analysis seems solid.**

The AI can build a theoretically sound model, but theory doesn't always match
reality. Lab testing is where you discover things like Procedure C's
buildProviders constraint, or that SACL auditing doesn't fire on read-only
operations. These discoveries refine both the DDM and the TRR. Do the lab work.

---

## Part 4: The Prompt Is a Living Document

The system prompt (`TRR-DDM-Research-Prompt-Long.md`) is not a static artifact.
It should evolve as you learn.

The current research prompt (v3) is the product of three iterations:

- **v1** was detection-focused — it framed the AI as a "Detection Engineering
  Research Assistant" and included detection strategy as part of the TRR
  workflow
- **v2** began separating detection from the TRR, added structural conventions
  for DDMs, and introduced the per-procedure export workflow
- **v3** completed the reframing: discipline-neutral role, detection methods as
  a derivative document, conciseness guidance, telemetry label conventions,
  file naming standards, two new pitfalls based on actual writing errors

Each version incorporated lessons learned from the previous phase of work. This
is expected and healthy. When you discover a pattern — a mistake the AI keeps
making, a structural convention that needs reinforcing, a new pitfall to watch
for — update the prompt.

**What makes a good prompt update:**

- Based on a real problem encountered during research, not theoretical
- Specific enough to change the AI's behavior (not "be more concise" but "keep
  technique overviews to 2-4 sentences")
- Includes the rationale (the AI follows instructions better when it understands
  why)
- Doesn't contradict existing instructions without resolving the conflict

Track your prompt versions in git alongside your TRR. The prompt's revision
history tells the story of what you learned about working with the AI.

---

## Part 5: Full Workflow Summary

Here is the end-to-end workflow:

**Setup (once):**

1. Create Claude Project with research prompt as system instructions
2. Upload methodology articles, published TRRs, and project overview to
   knowledge base
3. Set up GitHub repository with the standard directory structure

**Per-TRR research cycle:**

1. **Technique selection** — Choose a MITRE ATT&CK technique and platform
2. **Phase 1 conversations** — Research the technique, understand the
   underlying technology, build the scoping document with exclusion and
   constraints tables
3. **Phase 2 conversations** — Build the DDM iteratively (describe → generate
   JSON → paste in Arrows.app → review → discuss → regenerate), map telemetry,
   discover alternate paths, identify procedures
4. **Validation** — Run checklists with the AI, fix gaps, stabilize the DDM
5. **Lab recreation** — Build lab environment, execute each procedure, capture
   telemetry, feed findings back to the AI
6. **TRR writing** — Draft sections with the AI, revise through 3-5 passes
   with specific correction targets per pass
7. **DDM exports** — Generate master DDM (all black arrows) and per-procedure
   exports (red active path) in both JSON and PNG
8. **Derivative documents** — Write detection methods, lab guide, and other
   team-specific documents as separate files
9. **Final review** — Full read-through, prompt the AI to check for
   discipline-neutral language, consistency with DDM, and completeness
10. **Submit** — Package per the repository structure and contribution guide

**Ongoing:**

- Update the system prompt with lessons learned
- Add new reference materials to project knowledge as you encounter them
- Refine your personal workflow based on what's working

---

## Part 6: Honest Assessment — What AI Can and Can't Do Here

### Where AI Excels

- **Explaining unfamiliar systems.** If you've never worked with IIS internals,
  Active Directory, or WMI event subscriptions, the AI can walk you through
  them at whatever depth you need, answering follow-up questions in real time.
  This is the single biggest accelerator for someone new to a technique.

- **Applying the inclusion test systematically.** The AI can hold your entire
  DDM in context and evaluate every operation against the essential/immutable/
  observable criteria in a way that's tedious to do manually.

- **Generating structured output.** Arrows.app JSON, markdown tables, procedure
  summaries, detection specification templates — the AI produces these faster
  and more consistently than manual work.

- **Catching inconsistencies.** "You said this operation was essential in
  Procedure A but optional in Procedure C — which is it?" The AI is good at
  cross-referencing claims across your model.

- **Writing and revision.** First drafts, style matching, conciseness editing,
  removing detection-oriented language — the AI handles all of these well with
  proper direction.

### Where AI Struggles

- **Obscure or version-specific technical details.** The AI may confidently
  state that a specific API behaves a certain way when the reality is more
  nuanced or version-dependent. Always verify against documentation.

- **Knowing when it's wrong.** The AI won't spontaneously say "I'm not sure
  about that." You need to create the conditions for it to express uncertainty
  by asking pointed questions and watching for hedging language.

- **Truly novel analysis.** The AI is synthesizing from its training data. For
  well-studied techniques, this is usually sufficient. For truly novel or
  poorly documented techniques, the AI's analysis will be shallower and you'll
  need to do more primary research yourself.

- **Lab work.** The AI can write lab scripts and predict expected telemetry, but
  it can't execute procedures, observe actual system behavior, or troubleshoot
  environment-specific issues. Lab validation is irreplaceable human work.

- **Maintaining discipline-neutrality.** The AI's training includes far more
  detection-focused content than discipline-neutral TRR content. It will
  naturally drift toward detection language. This is the most persistent
  correction you'll make.

### The Bottom Line

The AI is a force multiplier, not a replacement for analytical thinking. The
methodology provides the structure. You provide the judgment. The AI provides
scale, speed, and tireless patience for the mechanical aspects of research,
writing, and validation. Used this way, someone with foundational security
knowledge but no TRR experience can produce professional-quality output.

---

## References

### Methodology

- [Threat Detection Engineering: The Series — VanVleet](https://medium.com/@vanvleet/threat-detection-engineering-the-series-7fe818fdfe62)
- [TIRED Labs TRR Library](https://library.tired-labs.org)
- [TIRED Labs Contribution Guide](https://github.com/tired-labs/techniques/blob/main/docs/CONTRIBUTING.md)

### Tools

- [Claude (Anthropic)](https://claude.ai) — AI research partner
- [Arrows App](https://arrows.app/) — DDM diagramming
- [MITRE ATT&CK](https://attack.mitre.org/) — Technique taxonomy
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — Emulation tests

### Companion Documents

- `TRR_Research_Methodology_Guide.md` — The analytical process
- `TRR-DDM-Research-Prompt-Long.md` — The AI system prompt
- `TRR_DDM_Prompt_Short.md` — Condensed system prompt for local models
- `.clinerules` — Cline workflow protocol (works in tandem with the local model prompt)
- `TECHNIQUE-RESEARCH-REPORT-OUTLINE.md` — TRR section structure and writing guidance
