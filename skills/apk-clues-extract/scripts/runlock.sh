#!/bin/bash
# runlock.sh <lock-name> <command> [args...]
#
# Run a command as a singleton. Replaces the `ps -eo args | grep -q ...` guards that
# were used before, which were actively harmful: the grep pattern also matched the
# LAUNCHING shell's own command line (the script name appears in it), so the guard
# concluded "already running" and silently skipped the launch while reporting success.
# That happened three separate times in this project.
#
# flock is the right primitive:
#   * atomic          -- no check-then-act race between two launchers
#   * self-immune     -- nothing matches on process names or command lines
#   * crash-safe      -- the kernel drops the lock when the holder dies, so there is
#                        no stale-lock cleanup and no stale-PID false positive
# The .pid file is written for humans/logs only; correctness never depends on it.
#
# Exit codes: 9 = another instance holds the lock; otherwise the command's own status.
set -u
LOCKDIR="${CLUES_LOCKDIR:-/var/tmp/clues_locks}"
mkdir -p "$LOCKDIR"
[ $# -ge 2 ] || { echo "usage: runlock.sh <lock-name> <command> [args...]" >&2; exit 2; }
name=$1; shift
lock="$LOCKDIR/$name.lock"
pidf="$LOCKDIR/$name.pid"

exec 9>"$lock" || { echo "[runlock] cannot open $lock" >&2; exit 2; }
if ! flock -n 9; then
  holder=$(cat "$pidf" 2>/dev/null || echo "")
  if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
    echo "[runlock] '$name' is already running (pid $holder) - refusing a second instance" >&2
  else
    # lock held but pidfile missing/stale: still refuse, just do not name a dead pid
    echo "[runlock] '$name' is already running (holder pid unknown) - refusing a second instance" >&2
  fi
  exit 9
fi

# Deliberately NOT `exec "$@"`: exec replaces this shell, which discards the EXIT
# trap and leaves the pidfile behind forever. Running the command as a child keeps
# cleanup working and lets us forward the usual termination signals, so `kill` on
# the wrapper still stops the real work.
echo $$ > "$pidf"
cleanup() { rm -f "$pidf"; }
trap cleanup EXIT
trap 'kill -TERM "$child" 2>/dev/null' TERM INT HUP
"$@" &
child=$!
wait "$child"
status=$?
exit "$status"
