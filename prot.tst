<#
tss_service_account_password_rotate.ps1  (Sequential, PS 5.1+ compatible)

Rotate AD Service Account passwords using Secret Server Secret IDs.

INPUT:
  -SecretIds "1234,5678"
OPTIONS:
  -DryRun
  -WordListPath "C:\tss_password_rotate\eff_wordlist"

Secret Server module syntax confirmed:
  Get-Secret [-id] <int> [-include-inactive] [-full]

Fields used from secret (PaaS Service Account template):
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

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Output "$ts [$Level] $Message"
}

function Parse-SecretIds {
    param([string]$Value)

    $parts = $Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $parts -or $parts.Count -eq 0) { throw "No valid SecretIds provided." }

    $ids = New-Object System.Collections.Generic.List[int]
    $seen = @{}

    foreach ($p in $parts) {
        if ($p -notmatch '^\d+$') { throw "Invalid SecretId '$p' (must be numeric)" }
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

    if (-not (Test-Path $Path)) { throw "Wordlist not found at '$Path'" }

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
    $digits = @()
    for ($i = 0; $i -lt 4; $i++) {
        $digits += (Get-Random -Minimum 1 -Maximum 7)
    }
    return ($digits -join '')
}

function New-DicewarePassword {
    param(
        [Parameter(Mandatory)][hashtable]$WordMap,
        [int]$MinLength = 30
    )

    while ($true) {
        $words = @()

        for ($i = 0; $i -lt 4; $i++) {
            $key = Roll-DiceKey
            if ($WordMap.ContainsKey($key)) { $word = $WordMap[$key] } else { $word = "UNKNOWN" }

            if ($word.Length -gt 1) {
                $cap = $word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower()
            } else {
                $cap = $word.ToUpper()
            }
            $words += $cap
        }

        $digit = Get-Random -Minimum 0 -Maximum 10
        $words[$words.Count - 1] = $words[$words.Count - 1] + $digit

        $pw = ($words -join "-")
        if ($pw.Length -ge $MinLength) { return $pw }
    }
}

function Ensure-Environment {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw "ActiveDirectory module not available. Run on an AD management host (RSAT installed)."
    }

    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) {
        throw "Secret Server PowerShell module not found (Connect-SecretServer missing)."
    }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        throw "Secret Server module missing Get-Secret cmdlet."
    }
}

function Get-TssSecretById {
    param([Parameter(Mandatory)][int]$Id)

    try {
        # Based on your confirmed syntax
        return Get-Secret -id $Id
    } catch {
        throw "Secret not found or inaccessible in TSS (SecretId=$Id): $($_.Exception.Message)"
    }
}

function Get-SecretFieldValue {
    param(
        [Parameter(Mandatory)]$Secret,
        [Parameter(Mandatory)][string]$FieldName
    )

    # Your module exposes fields under .fields (based on earlier objects you showed)
    if ($Secret -and $Secret.PSObject.Properties.Name -contains 'fields' -and $Secret.fields) {
        try { return $Secret.fields[$FieldName] } catch { return $null }
    }

    # Fallback: direct property
    if ($Secret -and ($Secret.PSObject.Properties.Name -contains $FieldName)) {
        try { return $Secret.$FieldName } catch { return $null }
    }

    return $null
}

function Update-TssPassword {
    param(
        [Parameter(Mandatory)][int]$SecretId,
        [Parameter(Mandatory)][string]$NewPassword
    )

    if (Get-Command Set-SecretField -ErrorAction SilentlyContinue) {
        Set-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    if (Get-Command Update-SecretField -ErrorAction SilentlyContinue) {
        Update-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    throw "No supported Secret Server password update cmdlet found (Set-SecretField / Update-SecretField)."
}

function Reset-ADPassword {
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Password
    )

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-ADAccountPassword -Identity $Username -Reset -NewPassword $secure -Server $Domain -ErrorAction Stop
    Unlock-ADAccount -Identity $Username -Server $Domain -ErrorAction SilentlyContinue
}

# ---------------- MAIN ----------------
Write-Log "Starting service account password rotation (DryRun=$DryRun)" "INFO"

Ensure-Environment

$ids = Parse-SecretIds $SecretIds
$wordMap = Load-WordList $WordListPath

Write-Log "Connecting to Secret Server..." "INFO"
Connect-SecretServer -UseDefaultCredentials | Out-Null

$failures = 0

foreach ($sid in $ids) {
    try {
        $secret = Get-TssSecretById -Id $sid

        $username = Get-SecretFieldValue -Secret $secret -FieldName "Username"
        $domain   = Get-SecretFieldValue -Secret $secret -FieldName "Domain Name"

        if (-not $username -or -not $domain) {
            throw "Required fields missing in secret (need: 'Username' and 'Domain Name')."
        }

        if ($DryRun) {
            Write-Log ("[DRY-RUN] SecretId={0} Would rotate {1}\{2} (AD reset + TSS password update)" -f $sid, $domain, $username) "INFO"
            continue
        }

        $newPw = New-DicewarePassword -WordMap $wordMap

        Reset-ADPassword -Username $username -Domain $domain -Password $newPw
        Update-TssPassword -SecretId $sid -NewPassword $newPw

        Write-Log ("SecretId={0} SUCCESS ({1}\{2})" -f $sid, $domain, $username) "INFO"
    }
    catch {
        $failures++
        Write-Log ("SecretId={0} FAILED - {1}" -f $sid, $_.Exception.Message) "ERROR"
    }
}

Write-Log ("Rotation complete. Total={0} Failed={1}" -f $ids.Count, $failures) "INFO"

if ($failures -gt 0) {
    throw ("{0} rotation(s) failed." -f $failures)
}
