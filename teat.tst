#!/bin/bash

COMMAND='@option.command@'
TARGETS='@option.targets@'
AUTOMATION_PASS='@option.automation_pass@'
DRYRUN='@option.dryrun@'

success=0
failed=0
skipped=0

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

get_os() {
  case "$1" in
    al*|av[0-9]l*|mv[0-9]l*) echo "linux" ;;
    av[0-9]w*|mv[0-9]w*) echo "windows" ;;
    *) return 1 ;;
  esac
}

get_nb_master() {
  case "$1" in
    *dev*) echo "mv2wdevnbu01.management.health.gov.au" ;;
    *prd*) echo "mv2wprdnbu01.management.health.gov.au" ;;
    *) return 1 ;;
  esac
}

ps_encode() {
  printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0
}

get_linux_cmd() {
  local cmd="$1"
  local server="$2"

  case "$cmd" in
    ping|getcrl)
      echo "/usr/openv/netbackup/bin/nbcertcmd -$cmd"
      ;;
    getCACertificate)
      echo "/usr/openv/netbackup/bin/nbcertcmd -getCACertificate -server $server"
      ;;
    clear_host_cache|pn|"pn -verbose")
      echo "/usr/openv/netbackup/bin/bpclntcmd -$cmd"
      ;;
    *)
      return 1
      ;;
  esac
}

get_windows_parts() {
  local cmd="$1"
  local server="$2"

  case "$cmd" in
    ping)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-ping|normal"
      ;;
    getcrl)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-getcrl|normal"
      ;;
    getCACertificate)
      echo "C:\Program Files\VERITAS\NetBackup\bin\nbcertcmd.exe|-getCACertificate -server $server|normal"
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

build_windows_cmd() {
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

  if (\$all -match 'expecting response from server' -or \$all -match '[A-Za-z0-9._-]+\s+[A-Za-z0-9._-]+\s+[0-9]{1,3}(\.[0-9]{1,3}){3}') {
    exit 0
  }
}

exit \$p.ExitCode
EOF
)

  encoded="$(ps_encode "$ps")"
  echo "powershell -NoProfile -EncodedCommand $encoded"
}

IFS=',' read -r -a target_list <<< "$TARGETS"

for raw in "${target_list[@]}"; do
  target="$(trim "$raw")"
  [[ -z "$target" ]] && continue

  echo "Target   : $target"

  if ! os="$(get_os "$target")"; then
    echo "Status   : SKIPPED"
    echo "Reason   : Unknown hostname pattern"
    skipped=$((skipped + 1))
    echo "----------------------------------------"
    continue
  fi

  echo "OS       : $os"

  nb_master=""
  if [[ "$COMMAND" == "getCACertificate" ]]; then
    if ! nb_master="$(get_nb_master "$target")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Could not determine NetBackup master"
      skipped=$((skipped + 1))
      echo "----------------------------------------"
      continue
    fi
    echo "NB Master: $nb_master"
  fi

  if [[ "$os" == "linux" ]]; then
    if ! remote_cmd="$(get_linux_cmd "$COMMAND" "$nb_master")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Unsupported command"
      skipped=$((skipped + 1))
      echo "----------------------------------------"
      continue
    fi
  else
    if ! parts="$(get_windows_parts "$COMMAND" "$nb_master")"; then
      echo "Status   : SKIPPED"
      echo "Reason   : Unsupported command"
      skipped=$((skipped + 1))
      echo "----------------------------------------"
      continue
    fi

    exe="${parts%%|*}"
    rest="${parts#*|}"
    args="${rest%%|*}"
    mode="${rest##*|}"

    remote_cmd="$(build_windows_cmd "$exe" "$args" "$mode")"
  fi

  echo "Command  : $remote_cmd"

  if is_true "$DRYRUN"; then
    echo "Status   : DRY RUN"
    echo "[DRY RUN] bolt command run \"...\" -t \"$target\""
    echo "----------------------------------------"
    continue
  fi

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
    success=$((success + 1))
  else
    echo "Status   : FAILED"
    echo "Exit Code: $rc"
    failed=$((failed + 1))
  fi

  echo "----------------------------------------"
done

echo
echo "========== SUMMARY =========="
echo "Command   : $COMMAND"
echo "Dry Run   : $DRYRUN"
echo "Success   : $success"
echo "Failed    : $failed"
echo "Skipped   : $skipped"
echo "============================="