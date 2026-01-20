<#
sa-password-reset.ps1  (Sequential, PowerShell 5.1+ compatible)

Rotate AD Service Account passwords using Secret Server Secret IDs.

Your environment cmdlets (per your module listing):
  - Connect-SecretServer
  - Get-Secret        (Get-Secret [-id] <int> [-include-inactive] [-full])
  - Invoke-TSSRestMethod (Invoke-TSSRestMethod [-request] <object>)

IMPORTANT (based on your module codebase screenshots):
- Connect-SecretServer sets:
    $env:TSSApiUrl = $api_base_url + "/SecretServer/api/v1"
    $env:TSSUseDefaultCredentials = 'true' (for Windows auth)
- Invoke-TSSRestMethod prepends:
    $request.Uri = $env:TSSApiUrl + $request.Uri
  So request objects MUST use a RELATIVE Uri like "/secrets/29671" (NOT full URL, NOT "/api/v1/...").

Policy:
- Only rotate if secret domain item exists and is in allow-list:
    nonprod.myac.gov.au
    management.health.gov.au
    myac.gov.au
    central.health.gov.au
- Domain item may be fieldName: "Domain Name" OR "Domain"
- If domain missing or not allowed => SKIP (no AD reset, no TSS update)

Flow per SecretId:
1) Get secret (full)
2) Extract Username (top-level property) and Domain (from items)
3) Generate diceware password
4) Reset AD password against discovered DC
5) Update TSS password via Invoke-TSSRestMethod (PUT then POST fallback)
   - Updates itemValue of the password item (fieldName "Password"/slug "password"/isPassword true)
   - Verifies after update by re-fetching and checking password itemValue changed
   - Builds a fresh request object each call (Invoke-TSSRestMethod mutates request by adding UseDefaultCredentials)

No passwords are printed or logged.
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

# Only these domains are eligible for rotation.
$AllowedDomains = @(
    "nonprod.myac.gov.au",
    "Management.health.gov.au",
    "myac.gov.au",
    "central.health"
)

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
        if (-not $seen.ContainsKey($i)) { $seen[$i] = $true; $ids.Add($i) }
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
    return $map
}

function Roll-DiceKey {
    $digits = @()
    for ($i = 0; $i -lt 4; $i++) { $digits += (Get-Random -Minimum 1 -Maximum 7) }
    return ($digits -join '')
}

function New-DicewarePassword {
    param([hashtable]$WordMap, [int]$MinLength = 30)

    while ($true) {
        $words = @()
        for ($i = 0; $i -lt 4; $i++) {
            $key = Roll-DiceKey
            $word = $(if ($WordMap.ContainsKey($key)) { $WordMap[$key] } else { "UNKNOWN" })
            $cap = $(if ($word.Length -gt 1) { $word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower() } else { $word.ToUpper() })
            $words += $cap
        }
        $digit = Get-Random -Minimum 0 -Maximum 10
        $words[$words.Count - 1] = $words[$words.Count - 1] + $digit
        $pw = ($words -join "-")
        if ($pw.Length -ge $MinLength) { return $pw }
    }
}

function Ensure-Environment {
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "ActiveDirectory module not available (RSAT required)." }
    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Connect-SecretServer" }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Get-Secret" }
    if (-not (Get-Command Invoke-TSSRestMethod -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Invoke-TSSRestMethod" }
}

function Get-TssSecretById {
    param([int]$Id)
    try { return Get-Secret -id $Id -full }
    catch { throw "Secret not found or inaccessible in TSS (SecretId=${Id}): $($_.Exception.Message)" }
}

function Get-ItemValueByAnyFieldName {
    param(
        [Parameter(Mandatory)]$Secret,
        [Parameter(Mandatory)][string[]]$FieldNames
    )

    if (-not ($Secret.PSObject.Properties.Name -contains 'items') -or -not $Secret.items) { return $null }

    foreach ($name in $FieldNames) {
        foreach ($it in $Secret.items) {
            if ($it.fieldName -eq $name) {
                return $it.itemValue
            }
        }
    }
    return $null
}

function Is-AllowedDomain {
    param([string]$DomainName)
    if (-not $DomainName) { return $false }
    return ($AllowedDomains -contains $DomainName.ToLower())
}

function Find-PasswordItem {
    param([Parameter(Mandatory)]$Secret)

    if (-not ($Secret.PSObject.Properties.Name -contains 'items') -or -not $Secret.items) { return $null }

    foreach ($it in $Secret.items) { if ($it.fieldName -eq "Password") { return $it } }
    foreach ($it in $Secret.items) { if ($it.slug -eq "password") { return $it } }
    foreach ($it in $Secret.items) { if ($it.PSObject.Properties.Name -contains 'isPassword' -and $it.isPassword -eq $true) { return $it } }

    return $null
}

function Reset-ADPassword {
    param([string]$Username, [string]$Domain, [string]$Password)

    $dc = $null
    try {
        $dc = Get-ADDomainController -Discover -DomainName $Domain -ErrorAction Stop
    } catch {
        throw "Unable to discover a Domain Controller for domain '${Domain}'. $($_.Exception.Message)"
    }

    # In your environment HostName is a collection like {AV1WPRDADS02.myac.gov.au}
    $serverObj = $dc.HostName
    if (-not $serverObj) { $serverObj = $dc.Name }
    if (-not $serverObj) { throw "DC discovery returned no HostName/Name for domain '${Domain}'." }

    if ($serverObj -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) { $serverObj = $serverObj[0] }
    elseif ($serverObj -is [System.Array]) { $serverObj = $serverObj[0] }

    $server = ([string]$serverObj).Trim()
    if ($server -eq "") { throw "Resolved DC hostname is empty for domain '${Domain}'." }

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-ADAccountPassword -Identity $Username -Reset -NewPassword $secure -Server $server -ErrorAction Stop
    Unlock-ADAccount -Identity $Username -Server $server -ErrorAction SilentlyContinue
}

function Update-TssPassword {
    param(
        [Parameter(Mandatory)][int]$SecretId,
        [Parameter(Mandatory)][string]$NewPassword
    )

    if (-not $env:TSSApiUrl) {
        throw "TSSApiUrl environment variable is not set. Ensure Connect-SecretServer ran successfully."
    }

    $sec = Get-Secret -id $SecretId -full
    if (-not $sec.items) { throw "SecretId=${SecretId}: cannot update because items payload is missing." }

    $pwItem = Find-PasswordItem -Secret $sec
    if (-not $pwItem) { throw "SecretId=${SecretId}: could not locate password item." }

    $oldValue = $pwItem.itemValue

    # Update only the password value (do not log it)
    $pwItem.itemValue = $NewPassword

    # These often cause validation problems when echoing a GET object back into PUT
    if ($sec.PSObject.Properties.Name -contains "responseCodes") { $sec.responseCodes = $null }

    # Convert the FULL secret object to JSON
    $json = $sec | ConvertTo-Json -Depth 80

    # Fresh request object (Invoke-TSSRestMethod mutates the hashtable)
    $req = @{
        Method      = "PUT"
        Uri         = "/secrets/$SecretId"
        Body        = $json
        ContentType = "application/json"
    }

    try {
        Invoke-TSSRestMethod -request $req | Out-Null
    }
    catch {
        throw "SecretId=${SecretId}: TSS PUT update failed. $($_.Exception.Message)"
    }

    # Verify it actually changed
    Start-Sleep -Seconds 1
    $sec2 = Get-Secret -id $SecretId -full
    $pw2 = Find-PasswordItem -Secret $sec2
    if (-not $pw2) { throw "SecretId=${SecretId}: verification failed (password item missing after refresh)." }

    if ($pw2.itemValue -eq $oldValue) {
        throw "SecretId=${SecretId}: update call returned OK but password value did not change (verification failed)."
    }
}


# ---------------- MAIN ----------------
Write-Log "Starting service account password rotation (DryRun=$DryRun)" "INFO"
Ensure-Environment

$ids = Parse-SecretIds $SecretIds
$wordMap = Load-WordList $WordListPath

Write-Log "Connecting to Secret Server..." "INFO"
Connect-SecretServer -UseDefaultCredentials | Out-Null

# Optional quick sanity: ensure module env vars exist after connect
if (-not $env:TSSApiUrl) {
    Write-Log "WARNING: env:TSSApiUrl not set after Connect-SecretServer; REST updates may fail." "WARN"
}

$failures = 0

foreach ($sid in $ids) {
    try {
        $secret = Get-TssSecretById -Id $sid

        # Username is a top-level property in your module output
        if (-not ($secret.PSObject.Properties.Name -contains 'Username') -or -not $secret.Username) {
            throw "SecretId=${sid}: missing Username."
        }
        $username = [string]$secret.Username

        # Domain can be either "Domain Name" or "Domain"
        $domainName = Get-ItemValueByAnyFieldName -Secret $secret -FieldNames @("Domain Name","Domain")
        if ($domainName) { $domainName = ([string]$domainName).ToLower() }

        if (-not (Is-AllowedDomain -DomainName $domainName)) {
            Write-Log ("SecretId={0} SKIPPED - Domain '{1}' not in allowed list. No AD/TSS rotation performed." -f $sid, $domainName) "WARN"
            continue
        }

        if ($DryRun) {
            Write-Log ("[DRY-RUN] SecretId={0} Would rotate {1}\{2} (AD reset + TSS password update)" -f $sid, $domainName, $username) "INFO"
            continue
        }

        $newPw = New-DicewarePassword -WordMap $wordMap

        # AD is source of truth
        Reset-ADPassword -Username $username -Domain $domainName -Password $newPw

        # Mirror into TSS and verify
        Update-TssPassword -SecretId $sid -NewPassword $newPw

        Write-Log ("SecretId={0} SUCCESS ({1}\{2})" -f $sid, $domainName, $username) "INFO"
    }
    catch {
        $failures++
        Write-Log ("SecretId={0} FAILED - {1}" -f $sid, $_.Exception.Message) "ERROR"
    }
}

Write-Log ("Rotation complete. Total={0} Failed={1}" -f $ids.Count, $failures) "INFO"
if ($failures -gt 0) { throw ("{0} rotation(s) failed." -f $failures) }
