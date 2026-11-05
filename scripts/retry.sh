#!/usr/bin/env bash
# CI8 (#566): a download of the CI, tried three times — never a test.
#
#   bash scripts/retry.sh <command> [argument…]
#
# Runs the command as given (its arguments untouched: no eval, no shell between). On a failure it
# waits 10 s and runs it again, then 30 s and a last time. Each attempt is said in the log, and each
# failure as a warning of the run (::warning::, in its summary): a retry is never silent. After the
# third failure, an error, and the exit code of that last failure. A command stopped by SIGINT or
# SIGTERM (a cancelled job, its bound) is never run again.
#
# Only the steps that download call it, and only their download (docs/operations.md, « Ce que la
# CI retente ») — never a test, the mutation nor the invariants: a flaky test is never masked
# (tests/unit/test_workflows.py holds the list).
set -u

if [ "$#" -eq 0 ]; then
  echo "usage: bash scripts/retry.sh <command> [argument…]" >&2
  exit 2
fi

waits=(10 30)                    # between the attempts: three in all
attempts=$((${#waits[@]} + 1))

# The command as a workflow command's message reads it: %, CR and LF escaped (GitHub's rule).
said="$*"
said=${said//\%/%25}
said=${said//$'\r'/%0D}
said=${said//$'\n'/%0A}

# A signal received is a stop, whatever the command then returns: pip and Terraform catch SIGINT and
# exit 1, which would read as a failure to try again. Bash runs the trap once the command has exited.
trap 'echo "::error::retry.sh: stopped by SIGINT: never run again"; exit 130' INT
trap 'echo "::error::retry.sh: stopped by SIGTERM: never run again"; exit 143' TERM

n=1
while :; do
  echo "retry.sh: attempt $n/$attempts: $said"
  "$@"
  code=$?
  if [ "$code" -eq 0 ]; then
    [ "$n" -gt 1 ] && echo "retry.sh: passed at attempt $n/$attempts: $said"
    exit 0
  fi
  case "$code" in
    130|143)
      echo "::error::retry.sh: $said stopped by a signal (exit $code): never run again"
      exit "$code" ;;
  esac
  if [ "$n" -ge "$attempts" ]; then
    echo "::error::retry.sh: $said failed $attempts times; exit $code, the last failure's"
    exit "$code"
  fi
  wait=${waits[$((n - 1))]}
  echo "::warning::retry.sh: attempt $n/$attempts of $said failed (exit $code); again in ${wait} s"
  sleep "$wait"
  n=$((n + 1))
done
