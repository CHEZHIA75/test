#!/usr/bin/env bash

set -u

COMMAND='@option.command@'
TARGETS='@option.targets@'
AUTOMATION_PASS='@option.automation_pass@'
DRYRUN='@option.dryrun@'

success_count=0
failure_count=0
skipped_count=0
executed_count=0

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

is_true() {
  case "$1" in
    true|TRUE|True|yes|YES|Yes|1)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

get_os_type() {
  local target="$1"

  case "$target" in
    al*)
      echo "linux"
      ;;
    av[0-9]l*|mv[0-9]l*)
      echo "linux"
      ;;
    av[0-9]w*|mv[0-9]w*)
      echo "windows"
      ;;
    *)
      return 1
      ;;
  esac
}

get_nb_master() {
  local target="$1"

  case "$target" in
    *dev*)
      echo "mv2wdevnbu01.management.health.gov.au"
      ;;
    *prd*)
      echo "mv2wprdnbu01.management.health.gov.au"
      ;;
    *)
      return 1
      ;;
  esac
}

get_exec_command() {
  local os_type="$1"
  local cmd="$2"
  local nb_master="${3:-}"

  case "$os_type" in
    linux)
      case "$cmd" in
        ping|getcrl)
          printf '%s' "/usr/openv/netbackup/bin/nbcertcmd -${cmd}"
          ;;
        getCACertificate)
          printf '%s' "/usr/openv/netbackup/bin/nbcertcmd -${cmd} -server ${nb_master}"
          ;;
        clear_host_cache|pn|"pn -verbose")
          printf '%s' "/usr/openv/netbackup/bin/bpclntcmd -${cmd}"
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    windows)
      case "$cmd" in
        ping|getcrl)
          printf '%s' "& \"C:\\Program Files\\VERITAS\\NetBackup\\bin\\nbcertcmd\" -${cmd} 2>&1; exit \$LASTEXITCODE"
          ;;
        getCACertificate)
          printf '%s' "& \"C:\\Program Files\\VERITAS\\NetBackup\\bin\\nbcertcmd\" -${cmd} -server ${nb_master} 2>&1; exit \$LASTEXITCODE"
          ;;
        clear_host_cache|pn|"pn -verbose")
          printf '%s' "& \"C:\\Program Files\\VERITAS\\NetBackup\\bin\\bpclntcmd\" -${cmd} 2>&1; exit \$LASTEXITCODE"
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

IFS=',' read -r -a target_array <<< "$TARGETS"

for raw_target in "${target_array[@]}"; do
  target="$(trim "$raw_target")"
  [[ -z "$target" ]] && continue

  echo "Target   : $target"

  if ! os_type="$(get_os_type "$target")"; then
    echo "Status   : SKIPPED"
    echo "Reason   : Could not determine OS type"
    skipped_count=$((skipped_count + 1))
    echo "----------------------------------------"
    continue
  fi

  echo "OS       : $os_type"

  nb_master=""
  if [[ "$COMMAND" == "getCACertificate" ]]; then
    if ! nb_master="$(get_nb_master "$target")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Could not determine NetBackup master"
      skipped_count=$((skipped_count + 1))
      echo "----------------------------------------"
      continue
    fi
    echo "NB Master: $nb_master"
  fi

  if ! exec_cmd="$(get_exec_command "$os_type" "$COMMAND" "$nb_master")"; then
    echo "Status   : SKIPPED"
    echo "Reason   : Unsupported command '$COMMAND'"
    skipped_count=$((skipped_count + 1))
    echo "----------------------------------------"
    continue
  fi

  echo "Command  : $exec_cmd"

  if is_true "$DRYRUN"; then
    echo "Status   : DRY RUN"
    echo "[DRY RUN] bolt command run \"$exec_cmd\" --no-host-key-check -u sa_automation_prod -p '********' -t \"$target\""
    echo "----------------------------------------"
    continue
  fi

  executed_count=$((executed_count + 1))

  bolt command run "$exec_cmd" \
    --no-host-key-check \
    -u sa_automation_prod \
    -p "$AUTOMATION_PASS" \
    -t "$target"

  rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "Status   : SUCCESS"
    success_count=$((success_count + 1))
  else
    echo "Status   : FAILED"
    echo "Exit Code: $rc"
    failure_count=$((failure_count + 1))
  fi

  echo "----------------------------------------"
done

echo
echo "========== SUMMARY =========="
echo "Command        : $COMMAND"
echo "Dry Run        : $DRYRUN"
echo "Targets Input  : $TARGETS"
echo "Executed       : $executed_count"
echo "Succeeded      : $success_count"
echo "Failed         : $failure_count"
echo "Skipped        : $skipped_count"
echo "============================="