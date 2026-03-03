#!/usr/bin/env bash
# PreToolUse hook: Check Write/Edit operations on TRR README.md files
# for detection-oriented language and other methodology violations.
# Exit 0 = allow, Exit 2 = block with feedback

INPUT=$(cat)
FILEPATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // empty')
CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // .tool_input.new_str // empty')

# Only check TRR document files (README.md inside TRR folders, and .md in Supporting Docs)
if ! echo "$FILEPATH" | grep -qiE '(WIP TRRs|Completed TRR).*\.(md|markdown)$'; then
  exit 0
fi

# Skip non-TRR markdown (like plans, research notes tagged appropriately)
# But DO check README.md, procedure docs, and anything in the TRR folder
VIOLATIONS=""

# --- Detection-oriented language ---
# These phrases have no place in a TRR. Telemetry sources stated as facts are fine.
# Prescriptive detection guidance belongs in derivative documents only.

DETECTION_PATTERNS=(
  "primary detection opportunity"
  "high-fidelity signal"
  "high.fidelity detection"
  "defenders should"
  "detection opportunity"
  "best place to detect"
  "provides visibility"
  "detection point"
  "most reliable indicator"
  "key indicator for detection"
  "should alert on"
  "recommended detection"
  "detection strategy"
  "SOC should"
  "analysts should"
  "blue team should"
  "monitor for this"
  "detection recommendation"
)

for PATTERN in "${DETECTION_PATTERNS[@]}"; do
  if echo "$CONTENT" | grep -qiE "$PATTERN"; then
    VIOLATIONS="${VIOLATIONS}\n- Detection-oriented language found: '$PATTERN'. TRRs are discipline-neutral. State technical facts only — let teams draw conclusions in derivative documents."
  fi
done

# --- Tool-focused analysis ---
TOOL_PATTERNS=(
  "Mimikatz\s+(does|performs|executes|dumps|extracts)"
  "CobaltStrike\s+(uses|performs|executes|beacons)"
  "China Chopper\s+(does|performs|executes|sends)"
  "PowerSploit\s+(does|performs|uses)"
  "Metasploit\s+(does|performs|uses|generates)"
  "Rubeus\s+(does|performs|requests|roasts)"
  "Impacket\s+(does|performs|uses)"
  "BloodHound\s+(does|performs|collects|maps)"
)

for PATTERN in "${TOOL_PATTERNS[@]}"; do
  if echo "$CONTENT" | grep -qiE "$PATTERN"; then
    TOOL_NAME=$(echo "$PATTERN" | sed 's/\\s.*//')
    VIOLATIONS="${VIOLATIONS}\n- Tool-focused analysis: '$TOOL_NAME' used as the subject of an operation. Describe the essential operation, not the tool. Tools are tangential."
  fi
done

# --- Numbered step lists in procedure narratives ---
# Check for patterns like "1. The attacker..." or "Step 1:" in procedure sections
if echo "$CONTENT" | grep -qE '^\s*[0-9]+\.\s+(The attacker|The adversary|The operator|First|Next|Then|Finally)'; then
  VIOLATIONS="${VIOLATIONS}\n- Numbered step list detected in what appears to be procedure prose. Procedure narratives must use prose paragraphs, not numbered lists."
fi

# --- Bare telemetry labels (missing descriptive name) ---
if echo "$CONTENT" | grep -qE 'Sysmon [0-9]+[^(]' | head -1; then
  VIOLATIONS="${VIOLATIONS}\n- Bare telemetry label detected (e.g., 'Sysmon 11' without '(FileCreate)'). Always use descriptive format: 'Sysmon 11 (FileCreate)'."
fi

# --- Report violations ---
if [ -n "$VIOLATIONS" ]; then
  echo -e "BLOCKED: TRR prose violations detected in $FILEPATH:\n$VIOLATIONS\n\nFix these before writing. TRRs are discipline-neutral source material — they document the technique, not the defensive response." >&2
  exit 2
fi

exit 0
