<#
sa_password_rotate.ps1  

Rotates AD Service Account passwords using Secret Server Secret IDs.

INPUT:
  -SecretIds "1234,5678"
OPTIONS:
  -DryRun
  -WordListPath ".\eff_wordlist"

BEHAVIOUR:
  - AD password is reset FIRST (source of truth)
  - Secret Server password updated only if AD succeeds
  - No secrets logged
  - Script fails at end if any SecretId fails

Fields used:
  - Username
  - Domain Name
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretIds,

    [switch]$DryRun,

    [ValidateNotNullOrEmpty()]
    [string]$WordListPath = ".\eff_wordlist"
)

$ErrorActionPreference = "Stop"

# ---------------- Logging ----------------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "$ts [$Level] $Message"
}

# ---------------- Utilities ----------------
function Parse-SecretIds {
    param([string]$Value)

    $parts = $Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $parts) { throw "No valid SecretIds provided." }

    $ids = New-Object System.Collections.Generic.List[int]
    $seen = @{}

    foreach ($p in $parts) {
        if ($p -notmatch '^\d+$') {
            throw "Invalid SecretId '$p' (must be numeric)"
        }
        $i = [int]$p
        if (-not $seen.ContainsKey($i)) {
            $seen[$i] = $true
            $ids.Add($i)
        }
    }
    return $ids
}

function Load-WordList {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Wordlist not found at '$Path'"
    }

    $map = @{}
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line) { return }
        $p = $line -split '\s+'
        if ($p.Count -ge 2) { $map[$p[0]] = $p[1] }
    }

    if ($map.Count -lt 1000) {
        Write-Log "Wordlist loaded but unusually small ($($map.Count) entries)" "WARN"
    }

    return $map
}

function Roll-DiceKey {
    ($null = 1..4 | ForEach-Object { Get-Random -Minimum 1 -Maximum 7 })
    return (1..4 | ForEach-Object { Get-Random -Minimum 1 -Maximum 7 }) -join ''
}

function New-DicewarePassword {
    param(
        [hashtable]$WordMap,
        [int]$MinLength = 30
    )

    while ($true) {
        $words = @()
        for ($i=0; $i -lt 4; $i++) {
            $key = Roll-DiceKey
            $word = $WordMap[$key] ?? "UNKNOWN"
            $words += ($word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower())
        }

        $words[-1] += (Get-Random -Minimum 0 -Maximum 10)
        $pw = ($words -join "-")

        if ($pw.Length -ge $MinLength) { return $pw }
    }
}

# ---------------- Environment Checks ----------------
function Ensure-Environment {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw "ActiveDirectory module not available. Run on AD management host."
    }

    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) {
        throw "Secret Server PowerShell module not found."
    }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        throw "Get-Secret cmdlet not found."
    }
}

# ---------------- Secret Server Helpers ----------------
function Get-TssSecretById {
    param([int]$Id)

    $cmd = Get-Command Get-Secret -ErrorAction Stop
    $params = $cmd.Parameters.Keys

    foreach ($p in @('SecretId','SecretID','Id','ID')) {
        if ($params -contains $p) {
            return Get-Secret @{$p = $Id}
        }
    }

    # Positional fallback
    try {
        return Get-Secret $Id
    } catch {
        throw "Secret not found or inaccessible (SecretId=$Id)"
    }
}

function Update-TssPassword {
    param(
        [int]$SecretId,
        [string]$NewPassword
    )

    if (Get-Command Set-SecretField -ErrorAction SilentlyContinue) {
        Set-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    if (Get-Command Update-SecretField -ErrorAction SilentlyContinue) {
        Update-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    throw "No supported Secret Server password update cmdlet found."
}

# ---------------- AD Action ----------------
function Reset-ADPassword {
    param(
        [string]$Username,
        [string]$Domain,
        [string]$Password
    )

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-ADAccountPassword -Identity $Username -Reset -NewPassword $secure -Server $Domain -ErrorAction Stop
    Unlock-ADAccount -Identity $Username -Server $Domain -ErrorAction SilentlyContinue
}

# ===================== MAIN =====================
Write-Log "Starting service account password rotation (DryRun=$DryRun)"

Ensure-Environment

$ids      = Parse-SecretIds $SecretIds
$wordMap = Load-WordList $WordListPath

Write-Log "Connecting to Secret Server..."
Connect-SecretServer -UseDefaultCredentials | Out-Null

$failures = 0

foreach ($sid in $ids) {
    try {
        $secret = Get-TssSecretById -Id $sid

        $username = $secret.fields["Username"]
        $domain   = $secret.fields["Domain Name"]

        if (-not $username -or -not $domain) {
            throw "Required fields missing (Username / Domain Name)"
        }

        if ($DryRun) {
            Write-Log "[DRY-RUN] SecretId=$sid Would rotate $domain\$username"
            continue
        }

        $newPw = New-DicewarePassword -WordMap $wordMap

        Reset-ADPassword -Username $username -Domain $domain -Password $newPw
        Update-TssPassword -SecretId $sid -NewPassword $newPw

        Write-Log "SecretId=$sid SUCCESS ($domain\$username)"
    }
    catch {
        $failures++
        Write-Log "SecretId=$sid FAILED - $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "Rotation complete. Total=$($ids.Count) Failed=$failures"

if ($failures -gt 0) {
    throw "$failures rotation(s) failed."
}
