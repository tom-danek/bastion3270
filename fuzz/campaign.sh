#!/bin/sh
# Long local fuzzing campaign: runs every fuzz target in parallel, then minimises each working
# corpus and reports findings. CI only runs short smoke runs; long runs belong on a developer
# machine (or a timer on one), not on hosted CI minutes.
#
# Usage: fuzz/campaign.sh [seconds per target, default 3600]
#
# Logs go to fuzz/logs/<target>.log, findings (crash-, timeout-, oom-, leak-, slow-unit- files)
# to fuzz/artifacts/<target>/. Exits 1 if any target failed or left a finding.
set -eu

cd "$(dirname "$0")"
seconds=${1:-3600}
targets=$(cargo +nightly fuzz list)

# Build once, so the parallel runs do not race on the same build.
cargo +nightly fuzz build

mkdir -p logs
pids=""
for t in $targets; do
  mkdir -p "corpus/$t"
  cargo +nightly fuzz run "$t" "corpus/$t" "seeds/$t" -- \
    -max_total_time="$seconds" -print_final_stats=1 > "logs/$t.log" 2>&1 &
  pids="$pids $!:$t"
done

status=0
for entry in $pids; do
  pid=${entry%%:*}
  t=${entry#*:}
  if wait "$pid"; then
    echo "ok      $t ($(grep -m1 '^Done' "logs/$t.log" || echo 'no summary'))"
  else
    echo "FAILED  $t (see fuzz/logs/$t.log)"
    status=1
  fi
done

# Keep the working corpus small: only inputs that add coverage.
for t in $targets; do
  cargo +nightly fuzz cmin "$t" "corpus/$t" > "logs/$t.cmin.log" 2>&1 || status=1
done

findings=$(find artifacts -type f 2>/dev/null || true)
if [ -n "$findings" ]; then
  echo "Findings:"
  echo "$findings"
  status=1
fi
exit "$status"
