#!/usr/bin/env bash
# Stop hook helper: Notification when Claude stops and needs attention
# Uses terminal bell as a cross-platform fallback
# On macOS: uses osascript for native notification
# On Linux: uses notify-send if available
# On Windows Git Bash: terminal bell only

if command -v osascript &>/dev/null; then
    osascript -e 'display notification "Task completed or needs your input" with title "Claude Code"' 2>/dev/null
elif command -v notify-send &>/dev/null; then
    notify-send "Claude Code" "Task completed or needs your input" 2>/dev/null
else
    printf '\a'
fi

exit 0
