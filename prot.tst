<#
sa-password-reset.ps1  (Sequential, PowerShell 5.1+ compatible)

Rotate AD Service Account passwords using Secret Server Secret IDs.

Confirmed module cmdlets available in your environment:
  - Connect-SecretServer
  - Get-Secret        (Syntax: Get-Secret [-id] <int> [-include-inactive] [-full])
  - Invoke-TSSRestMethod (Syntax: Invoke-TSSRestMethod [-request] <object>)

INPUT:
  -SecretIds "1234,5678"
OPTIONS:
  -DryRun
  -WordListPath ".\eff_wordlist"

FIELD SOURCES (your module returns a flat object):
  - Username : $secret.Username
  - Domain   : try Domain-ish properties, else parse from $secret.name formatted like user@domain

FLOW per SecretId:
  1) Get secret from Secret Server (FULL)
  2) Extract Username + Domain
  3) Generate diceware-style password (>= 30 chars, trailing digit)
  4) Reset AD password (Set-ADAccountPassword)
  5) Update Secret Server password item via Invoke-TSSRestMethod (PUT; fallback POST)

NOTES:
  - Never logs passwords
  - Returns non-zero exit if any rotation fails
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

        # Append a digit for complexity
        $digit = Get-Random -Minimum 0 -Maximum 10
        $words[$words.Count - 1] = $words[$words.Count - 1] + $digit

        $pw = ($words -join "-")
        if ($pw.Length -ge $MinLength) { return $pw }
    }
}

# ---------------- Environment Checks ----------------
function Ensure-Environment {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw "ActiveDirectory module not available. Run on an AD management host (RSAT installed)."
    }

    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) {
        throw "Secret Server module cmdlet missing: Connect-SecretServer"
    }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        throw "Secret Server module cmdlet missing: Get-Secret"
    }
    if (-not (Get-Command Invoke-TSSRestMethod -ErrorAction SilentlyContinue)) {
        throw "Secret Server module cmdlet missing: Invoke-TSSRestMethod"
    }
}

# ---------------- Secret Server Helpers ----------------
function Get-TssSecretById {
    param([Parameter(Mandatory)][int]$Id)
    try {
        return Get-Secret -id $Id -full
    } catch {
        throw "Secret not found or inaccessible in TSS (SecretId=$Id): $($_.Exception.Message)"
    }
}

function Get-SecretUsername {
    param([Parameter(Mandatory)]$Secret)

    if ($Secret.PSObject.Properties.Name -contains 'Username' -and $Secret.Username) {
        return [string]$Secret.Username
    }

    # Fallback: try items if Username not present (rare in your env)
    if ($Secret.PSObject.Properties.Name -contains 'items' -and $Secret.items) {
        foreach ($it in $Secret.items) {
            $fname = $null
            if ($it.PSObject.Properties.Name -contains 'fieldName') { $fname = $it.fieldName }
            elseif ($it.PSObject.Properties.Name -contains 'FieldName') { $fname = $it.FieldName }
            elseif ($it.PSObject.Properties.Name -contains 'name') { $fname = $it.name }
            elseif ($it.PSObject.Properties.Name -contains 'Name') { $fname = $it.Name }

            if ($fname -eq 'Username') {
                if ($it.PSObject.Properties.Name -contains 'itemValue') { return [string]$it.itemValue }
                if ($it.PSObject.Properties.Name -contains 'ItemValue') { return [string]$it.ItemValue }
                if ($it.PSObject.Properties.Name -contains 'value') { return [string]$it.value }
                if ($it.PSObject.Properties.Name -contains 'Value') { return [string]$it.Value }
            }
        }
    }

    return $null
}

function Get-SecretDomain {
    param([Parameter(Mandatory)]$Secret)

    # Try likely domain property names (some templates expose these)
    foreach ($prop in @('Domain Name','DomainName','Domain','domain','domainName')) {
        if ($Secret.PSObject.Properties.Name -contains $prop) {
            $v = $Secret.$prop
            if ($v) { return [string]$v }
        }
    }

    # Fallback: parse from secret.name (commonly user@domain)
    if ($Secret.PSObject.Properties.Name -contains 'name' -and $Secret.name) {
        $n = [string]$Secret.name
        if ($n -match '@(.+)$') {
            return $Matches[1]
        }
    }

    return $null
}

function Set-SecretItemValue {
    param(
        [Parameter(Mandatory)]$Item,
        [Parameter(Mandatory)][string]$Value
    )

    if ($Item.PSObject.Properties.Name -contains 'itemValue') { $Item.itemValue = $Value; return $true }
    if ($Item.PSObject.Properties.Name -contains 'ItemValue') { $Item.ItemValue = $Value; return $true }
    if ($Item.PSObject.Properties.Name -contains 'value') { $Item.value = $Value; return $true }
    if ($Item.PSObject.Properties.Name -contains 'Value') { $Item.Value = $Value; return $true }

    return $false
}

function Update-TssPassword {
    param(
        [Parameter(Mandatory)][int]$SecretId,
        [Parameter(Mandatory)][string]$NewPassword
    )

    $sec = Get-Secret -id $SecretId -full

    if (-not ($sec.PSObject.Properties.Name -contains 'items') -or -not $sec.items) {
        throw "SecretId=$SecretId: cannot update because 'items' payload is missing from Get-Secret -full output."
    }

    # Update password item in-place
    $updated = $false
    $pwFieldNames = @('Password','password','Passphrase','passphrase')

    foreach ($it in $sec.items) {

        $fieldName = $null
        if ($it.PSObject.Properties.Name -contains 'fieldName') { $fieldName = $it.fieldName }
        elseif ($it.PSObject.Properties.Name -contains 'FieldName') { $fieldName = $it.FieldName }
        elseif ($it.PSObject.Properties.Name -contains 'name') { $fieldName = $it.name }
        elseif ($it.PSObject.Properties.Name -contains 'Name') { $fieldName = $it.Name }

        if ($fieldName -and ($pwFieldNames -contains $fieldName)) {
            $updated = (Set-SecretItemValue -Item $it -Value $NewPassword)
            if ($updated) { break }
        }
    }

    if (-not $updated) {
        throw "SecretId=$SecretId: password field not found in secret items."
    }

    # Some TSS versions expect additional flags. We keep the body minimal first.
    $body = @{
        id    = $sec.id
        name  = $sec.name
        items = $sec.items
    }

    $path = "/api/v1/secrets/$SecretId"

    # Request object matches: Invoke-TSSRestMethod [-request] <object>
    $req = @{
        Method = 'PUT'
        Path   = $path
        Body   = $body
    }

    try {
        Invoke-TSSRestMethod -request $req | Out-Null
        return
    } catch {
        # Fallback to POST for environments that reject PUT
        $req.Method = 'POST'
        try {
            Invoke-TSSRestMethod -request $req | Out-Null
            return
        } catch {
            throw "SecretId=$SecretId: failed to update password via TSS REST API. $($_.Exception.Message)"
        }
    }
}

# ---------------- AD Action ----------------
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

# ===================== MAIN =====================
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

        $username = Get-SecretUsername -Secret $secret
        if (-not $username) { throw "SecretId=$sid: missing Username." }

        $domain = Get-SecretDomain -Secret $secret
        if (-not $domain) { throw "SecretId=$sid: could not determine domain (no domain field and name not user@domain)." }

        if ($DryRun) {
            Write-Log ("[DRY-RUN] SecretId={0} Would rotate {1}\{2} (AD reset + TSS password update)" -f $sid, $domain, $username) "INFO"
            continue
        }

        $newPw = New-DicewarePassword -WordMap $wordMap

        # AD is source of truth
        Reset-ADPassword -Username $username -Domain $domain -Password $newPw

        # Mirror to TSS after AD succeeds
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
