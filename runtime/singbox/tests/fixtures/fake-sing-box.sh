#!/bin/sh
set -eu

fixture_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf '%s\n' "$$" > "$fixture_directory/last-pid"
behavior=normal
if [ -f "$fixture_directory/behavior" ]; then
  behavior=$(sed -n '1p' "$fixture_directory/behavior")
fi

printf '%s\n' "$*" >> "$fixture_directory/argv.log"

if [ "$#" -eq 1 ] && [ "$1" = "version" ]; then
  case "$behavior" in
    version_timeout)
      sleep 10 &
      printf '%s\n' "$!" > "$fixture_directory/descendant-pid"
      wait "$!"
      ;;
    version_large)
      index=0
      while [ "$index" -lt 4096 ]; do
        printf x
        index=$((index + 1))
      done
      printf '\n'
      ;;
    version_invalid_utf8)
      printf '\377\n'
      ;;
    version_exit)
      exit 19
      ;;
    *)
      printf 'sing-box version 1.12.0\nEnvironment: deterministic fake\n'
      ;;
  esac
  exit 0
fi

state_directory=
config_path=
subcommand=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -D)
      [ "$#" -ge 2 ] || exit 64
      state_directory=$2
      shift 2
      ;;
    -c)
      [ "$#" -ge 2 ] || exit 64
      config_path=$2
      shift 2
      ;;
    check|run)
      subcommand=$1
      shift
      ;;
    *)
      exit 64
      ;;
  esac
done

[ -n "$state_directory" ] || exit 64
[ -d "$state_directory" ] || exit 65
[ -n "$config_path" ] || exit 64
[ -f "$config_path" ] || exit 66

case "$subcommand" in
  check)
    case "$behavior" in
      check_timeout)
        sleep 10 &
        printf '%s\n' "$!" > "$fixture_directory/descendant-pid"
        wait "$!"
        ;;
      check_reject)
        cat "$config_path" >&2
        exit 23
        ;;
      require_direct)
        grep -q '"type":"direct"' "$config_path" || exit 24
        ;;
      remove_before_run)
        rm -f "$0"
        ;;
      check_signal)
        kill -KILL "$$"
        ;;
    esac
    if grep -q '"reject":true' "$config_path"; then
      cat "$config_path" >&2
      exit 25
    fi
    ;;
  run)
    case "$behavior" in
      run_exit)
        exit 42
        ;;
      run_crash_marker)
        trap 'exit 0' TERM HUP INT
        while [ ! -f "$fixture_directory/crash-now" ]; do
          sleep 0.02
        done
        exit 42
        ;;
      run_ignore_term)
        trap '' TERM HUP INT
        while :; do sleep 1; done
        ;;
      *)
        trap 'exit 0' TERM HUP INT
        while :; do sleep 1; done
        ;;
    esac
    ;;
  *)
    exit 64
    ;;
esac
