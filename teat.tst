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
    true|TRUE|True|yes|YES|Yes|1) return 0 ;;
    *) return 1 ;;
  esac
}

get_os_type() {
  local target="$1"
  case "$target" in
    al*) echo "linux" ;;
    av[0-9]l*|mv[0-9]l*) echo "linux" ;;
    av[0-9]w*|mv[0-9]w*) echo "windows" ;;
    *) return 1 ;;
  esac
}

get_nb_master() {
  local target="$1"
  case "$target" in
    *dev*) echo "mv2wprdnbu01.management.health.gov.au" ;;
    *prd*) echo "mv2wprdnbu01.management.health.gov.au" ;;
    *) return 1 ;;
  esac
}

ps_encode() {
  printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0
}

get_linux_exec() {
  local cmd="$1"
  local nb_master="${2:-}"

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
}

get_windows_parts() {
  local cmd="$1"
  local nb_master="${2:-}"

  case "$cmd" in
    ping)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-ping|normal"
      ;;
    getcrl)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-getcrl|normal"
      ;;
    getCACertificate)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-getCACertificate -server ${nb_master}|normal"
      ;;
    clear_host_cache)
      echo "C:\Program Files\VERITAS\NetBackup\bin\bpclntcmd.exe|-clear_host_cache|normal"
      ;;
    pn)
      echo "C:\Program Files\VERITAS\NetBackup\bin\bpclntcmd.exe|-pn|pncheck"
      ;;
    "pn -verbose")
      echo "C:\Program Files\VERITAS\NetBackup\bin\bpclntcmd.exe|-pn -verbose|pncheck"
      ;;
    *)
      return 1
      ;;
  esac
}

build_windows_bolt_command() {
  local exe="$1"
  local args="$2"
  local mode="$3"
  local ps encoded

  ps=$(cat <<EOF
\$exe = '$exe'
\$args = '$args'
\$out = [System.IO.Path]::GetTempFileName()
\$err = [System.IO.Path]::GetTempFileName()

\$p = Start-Process -FilePath \$exe -ArgumentList \$args -RedirectStandardOutput \$out -RedirectStandardError \$err -Wait -PassThru

if (Test-Path \$out) { Get-Content \$out }
if (Test-Path \$err) { Get-Content \$err }

if ('$mode' -eq 'pncheck') {
  \$all = ''
  if (Test-Path \$out) { \$all += (Get-Content \$out -Raw) }
  if (Test-Path \$err) { \$all += (Get-Content \$err -Raw) }

  if (\$all -match 'expecting response from server' -or \$all -match '[A-Za-z0-9._-]+\\s+[A-Za-z0-9._-]+\\s+[0-9]{1,3}(\\.[0-9]{1,3}){3}') {
    exit 0
  }
}

exit \$p.ExitCode
EOF
)

  encoded="$(ps_encode "$ps")"
  printf '%s' "powershell -NoProfile -EncodedCommand $encoded"
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

  if [[ "$os_type" == "linux" ]]; then
    if ! remote_cmd="$(get_linux_exec "$COMMAND" "$nb_master")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Unsupported command '$COMMAND'"
      skipped_count=$((skipped_count + 1))
      echo "----------------------------------------"
      continue
    fi
    display_cmd="$remote_cmd"
  else
    if ! parts="$(get_windows_parts "$COMMAND" "$nb_master")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Unsupported command '$COMMAND'"
      skipped_count=$((skipped_count + 1))
      echo "----------------------------------------"
      continue
    fi

    exe="${parts%%|*}"
    rest="${parts#*|}"
    args="${rest%%|*}"
    mode="${rest##*|}"

    display_cmd="$exe $args"
    remote_cmd="$(build_windows_bolt_command "$exe" "$args" "$mode")"
  fi

  echo "Command  : $display_cmd"

  if is_true "$DRYRUN"; then
    echo "Status   : DRY RUN"
    echo "[DRY RUN] bolt command run \"$display_cmd\" --no-host-key-check -u sa_automation_prod -p '********' -t \"$target\""
    echo "----------------------------------------"
    continue
  fi

  executed_count=$((executed_count + 1))

  output="$(
    bolt command run "$remote_cmd" \
      --no-host-key-check \
      -u sa_automation_prod \
      -p "$AUTOMATION_PASS" \
      -t "$target" 2>&1
  )"
  rc=$?

  echo "$output"

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


if [[ "$os_type" == "linux" ]]; then
  output="$(
    bolt command run "$remote_cmd" \
      --no-host-key-check \
      -u sa_automation_prod \
      -p "$AUTOMATION_PASS" \
      --run-as root \
      -t "$target" 2>&1
  )"
else
  output="$(
    bolt command run "$remote_cmd" \
      --no-host-key-check \
      -u sa_automation_prod \
      -p "$AUTOMATION_PASS" \
      -t "$target" 2>&1
  )"
fi

rc=$?
echo "$output