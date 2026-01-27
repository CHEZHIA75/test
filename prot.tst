<#
sa-password-reset.ps1  (Single-file deployable: diceware wordlist embedded as Base64, decoded in-memory)

What this script does
- Takes Secret Server Secret IDs (comma-separated)
- For each SecretId:
  - Reads secret from Secret Server (Get-Secret -full)
  - Extracts:
      Username  (top-level property)
      Domain    (items fieldName: "Domain Name" OR "Domain")
  - Only proceeds if Domain is one of the allowed domains (below). Otherwise SKIP.
  - Generates a diceware password using an embedded Base64 wordlist (decoded to a map in-memory)
  - Resets AD password (targets a discovered Domain Controller for that domain)
  - Updates Secret Server password via winauthwebservices API:
      PUT /secrets/{id} with the FULL secret object (only password itemValue changed)
  - Verifies Secret Server password itemValue changed after update

Environment assumptions (based on your module codebase)
- Connect-SecretServer -UseDefaultCredentials sets $env:TSSApiUrl to:
    https://safe.myac.gov.au/SecretServer/winauthwebservices/api/v1
- Invoke-TSSRestMethod expects request hashtable with Invoke-RestMethod-style keys, and it prepends $env:TSSApiUrl to request.Uri.
- So request.Uri is RELATIVE like "/secrets/29671".

NOTE
- No passwords are printed/logged.
- Uses PowerShell 5.1 compatible syntax (no ??, no parallel).
- You will paste the Base64 string into $EffWordlistBase64.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretIds,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ---- Allowed AD domains ----
$AllowedDomains = @(
    "nonprod.myac.gov.au",
    "management.health.gov.au",
    "myac.gov.au",
    "central.health.gov.au"
)

# =============================================================================
# Embedded eff_wordlist (Base64) - YOU will paste the Base64 string here
# =============================================================================
$EffWordlistBase64 = @"
__PASTE_BASE64_HERE__
"@

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

function Ensure-Environment {
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "ActiveDirectory module not available (RSAT required)." }
    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Connect-SecretServer" }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Get-Secret" }
    if (-not (Get-Command Invoke-TSSRestMethod -ErrorAction SilentlyContinue)) { throw "Missing cmdlet: Invoke-TSSRestMethod" }
}

function Get-DicewareWordMapFromBase64 {
    if (-not $EffWordlistBase64 -or $EffWordlistBase64 -match '__PASTE_BASE64_HERE__') {
        throw "Embedded eff_wordlist Base64 is missing. Paste your Base64 into `$EffWordlistBase64."
    }

    $bytes = [Convert]::FromBase64String(($EffWordlistBase64 -replace '\s',''))
    $text  = [System.Text.Encoding]::UTF8.GetString($bytes)

    $map = @{}
    foreach ($line in $text -split "`n") {
        $line = $line.Trim()
        if (-not $line) { continue }

        $parts = $line -split '\s+'
        if ($parts.Count -ge 2) {
            $map[$parts[0]] = $parts[1]
        }
    }

    if ($map.Count -lt 1000) {
        throw "Decoded diceware map unexpectedly small ($($map.Count) entries). Check embedded Base64."
    }

    return $map
}

function Roll-DiceKey {
    $digits = @()
    for ($i = 0; $i -lt 4; $i++) { $digits += (Get-Random -Minimum 1 -Maximum 7) }
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
            $word = $(if ($WordMap.ContainsKey($key)) { $WordMap[$key] } else { "UNKNOWN" })

            if ($word.Length -gt 1) {
                $cap = $word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower()
            } else {
                $cap = $word.ToUpper()
            }
            $words += $cap
        }

        # trailing digit for typical complexity
        $digit = Get-Random -Minimum 0 -Maximum 10
        $words[$words.Count - 1] = $words[$words.Count - 1] + $digit

        $pw = ($words -join "-")
        if ($pw.Length -ge $MinLength) { return $pw }
    }
}

function Get-TssSecretById {
    param([Parameter(Mandatory)][int]$Id)
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
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Password
    )

    $dc = $null
    try { $dc = Get-ADDomainController -Discover -DomainName $Domain -ErrorAction Stop }
    catch { throw "Unable to discover a Domain Controller for domain '${Domain}'. $($_.Exception.Message)" }

    # In your env HostName is a collection like {AV1WPRDADS02.myac.gov.au}
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

    # Old value for verification (do not print)
    $oldValue = $pwItem.itemValue

    # Update only the password itemValue
    $pwItem.itemValue = $NewPassword

    # Some responses include responseCodes which can break PUT validation.
    if ($sec.PSObject.Properties.Name -contains "responseCodes") { $sec.responseCodes = $null }

    # PUT expects the FULL secret object (your test proved this works)
    $json = $sec | ConvertTo-Json -Depth 80

    # Fresh request object (Invoke-TSSRestMethod mutates hashtable)
    $req = @{
        Method      = "PUT"
        Uri         = "/secrets/$SecretId"
        Body        = $json
        ContentType = "application/json"
    }

    try {
        Invoke-TSSRestMethod -request $req | Out-Null
    } catch {
        throw "SecretId=${SecretId}: TSS PUT update failed. $($_.Exception.Message)"
    }

    # Verify changed
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

# Decode embedded wordlist ONCE into a map (memory only)
$wordMap = Get-DicewareWordMapFromBase64

$ids = Parse-SecretIds $SecretIds

Write-Log "Connecting to Secret Server..." "INFO"
Connect-SecretServer -UseDefaultCredentials | Out-Null

if (-not $env:TSSApiUrl) {
    Write-Log "WARNING: env:TSSApiUrl not set after Connect-SecretServer; REST updates may fail." "WARN"
} else {
    Write-Log ("TSSApiUrl: {0}" -f $env:TSSApiUrl) "DEBUG"
}

$failures = 0

foreach ($sid in $ids) {
    try {
        $secret = Get-TssSecretById -Id $sid

        # Username is top-level property in your module output
        if (-not ($secret.PSObject.Properties.Name -contains 'Username') -or -not $secret.Username) {
            throw "SecretId=${sid}: missing Username."
        }
        $username = [string]$secret.Username

        # Domain may be "Domain Name" or "Domain" (items-based)
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
