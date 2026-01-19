<#
tss_service_account_password_rotate.ps1 (Sequential)

Rotate AD Service Account passwords based on Secret Server Secret IDs.

Input:
  -SecretIds "1234,5678"  (comma-separated)
Options:
  -DryRun
  -WordListPath "C:\tss_password_rotate\eff_wordlist"

Flow per SecretId:
  1) Get secret from Secret Server
  2) Read fields: "Username" and "Domain Name" (per your PaaS Service Account template)
  3) Generate a diceware-style passphrase (>= 30 chars, add trailing digit)
  4) Reset AD password (Set-ADAccountPassword)
  5) Update Secret Server "password" field

Notes:
  - Does not print passwords.
  - Returns non-zero exit if any rotation fails.
  - Designed for Secret Server template "PaaS Service Account".
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretIds,

    [switch]$DryRun,

    # Path to diceware wordlist (format: "11111 word")
    [ValidateNotNullOrEmpty()]
    [string]$WordListPath = "C:\tss_password_rotate\eff_wordlist"
)

$ErrorActionPreference = "Stop"

function Write-LogStd {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    $ts = (Get-Date).ToString("s")
    Write-Output "$ts [$Level] $Message"
}

function Parse-SecretIds {
    param([string]$Value)
    $parts = $Value.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $parts -or $parts.Count -eq 0) { throw "No valid secret IDs provided." }

    $ids = New-Object System.Collections.Generic.List[int]
    $seen = @{}
    foreach ($p in $parts) {
        if ($p -notmatch '^\d+$') { throw "Invalid secret id '$p' (must be integer)" }
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

    # wordlist format: "11111 word"
    $map = @{}
    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line) { return }
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2) {
            $map[$parts[0]] = $parts[1]
        }
    }
    if ($map.Count -lt 1000) {
        Write-LogStd "Wordlist loaded but seems small ($($map.Count) entries). Check file." "WARN"
    }
    return $map
}

function Roll-DiceKey {
    # 4 dice rolls -> 4 digits 1-6, e.g., 1436
    $digits = for ($i=0; $i -lt 4; $i++) { Get-Random -Minimum 1 -Maximum 7 }
    return ($digits -join '')
}

function New-DicewarePassphrase {
    param(
        [Parameter(Mandatory)][hashtable]$WordMap,
        [int]$Words = 4,
        [string]$Delimiter = "-",
        [int]$MinLength = 30
    )

    while ($true) {
        $out = New-Object System.Collections.Generic.List[string]
        for ($i=0; $i -lt $Words; $i++) {
            $key = Roll-DiceKey
            $word = $WordMap[$key]
            if (-not $word) { $word = "UNKNOWN" }
            $out.Add( ($word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower()) )
        }

        # Add a digit to last word to satisfy typical complexity requirements
        $digit = Get-Random -Minimum 0 -Maximum 10
        $out[$out.Count-1] = $out[$out.Count-1] + $digit

        $phrase = ($out -join $Delimiter)
        if ($phrase.Length -lt $MinLength) { continue }
        return $phrase
    }
}

function Ensure-ModulesAndCmdlets {
    # AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        throw "ActiveDirectory module not available. Run on a host with RSAT/AD tools installed."
    }

    # Secret Server cmdlets (your env already has Connect-SecretServer/Get-Secret)
    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) {
        throw "Secret Server cmdlets not found: Connect-SecretServer. Ensure the Secret Server module is installed."
    }
    if (-not (Get-Command Get-Secret -ErrorAction SilentlyContinue)) {
        throw "Secret Server cmdlets not found: Get-Secret. Ensure the Secret Server module is installed."
    }
}

function Reset-ADPassword {
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$NewPassword
    )

    # Import is cheap; keep it here for safety when run from Rundeck nodes
    Import-Module ActiveDirectory -ErrorAction Stop

    $secure = ConvertTo-SecureString $NewPassword -AsPlainText -Force

    Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure -Server $DomainName -ErrorAction Stop
    Unlock-ADAccount -Identity $SamAccountName -Server $DomainName -ErrorAction SilentlyContinue
}

function Update-TssPassword {
    param(
        [Parameter(Mandatory)][int]$SecretId,
        [Parameter(Mandatory)][string]$NewPassword
    )

    # Different Secret Server modules have different cmdlets.
    # We try common options; adjust this function if your module uses a specific command.
    if (Get-Command Set-SecretField -ErrorAction SilentlyContinue) {
        Set-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    if (Get-Command Update-SecretField -ErrorAction SilentlyContinue) {
        Update-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
        return
    }

    # Last-resort: update whole secret if module supports Set-Secret
    if (Get-Command Set-Secret -ErrorAction SilentlyContinue) {
        $s = Get-Secret -SecretId $SecretId
        # Attempt common property names (module-dependent)
        if ($s.PSObject.Properties.Name -contains 'Password') {
            $s.Password = $NewPassword
        } elseif ($s.PSObject.Properties.Name -contains 'password') {
            $s.password = $NewPassword
        } else {
            throw "Set-Secret exists but secret object has no obvious Password property. Use Set-SecretField/Update-SecretField instead."
        }
        Set-Secret -Secret $s | Out-Null
        return
    }

    throw "No known Secret Server update cmdlet found (Set-SecretField / Update-SecretField / Set-Secret)."
}

# ---- Start ----
Write-LogStd "Starting service account password rotation. DryRun=$DryRun" "INFO"

Ensure-ModulesAndCmdlets

$ids = Parse-SecretIds -Value $SecretIds
$wordMap = Load-WordList -Path $WordListPath

Write-LogStd "Connecting to Secret Server using default credentials..." "INFO"
Connect-SecretServer -UseDefaultCredentials | Out-Null

$results = @()
$failCount = 0

foreach ($sid in $ids) {
    try {
        $secret = Get-Secret -SecretId $sid

        # Field names from your screenshot (PaaS Service Account template)
        # Depending on your Secret Server module, these may be direct properties or within Fields.
        $username = $null
        $domain   = $null

        if ($secret.PSObject.Properties.Name -contains 'Username') {
            $username = $secret.Username
        } elseif ($secret.PSObject.Properties.Name -contains 'fields' -and $secret.fields) {
            $username = $secret.fields["Username"]
        }

        if ($secret.PSObject.Properties.Name -contains 'Domain Name') {
            $domain = $secret.'Domain Name'
        } elseif ($secret.PSObject.Properties.Name -contains 'fields' -and $secret.fields) {
            $domain = $secret.fields["Domain Name"]
        }

        if (-not $username -or -not $domain) {
            throw "Missing required fields (Username / Domain Name) in secret."
        }

        $newPw = New-DicewarePassphrase -WordMap $wordMap

        if ($DryRun) {
            Write-LogStd "[DRY-RUN] SecretId=$sid Would reset AD password for $domain\$username and update TSS password" "INFO"
            $results += [pscustomobject]@{ SecretId=$sid; Status="DRY-RUN"; Username=$username; Domain=$domain; Message="Would reset AD + update TSS" }
            continue
        }

        Reset-ADPassword -SamAccountName $username -DomainName $domain -NewPassword $newPw
        Update-TssPassword -SecretId $sid -NewPassword $newPw

        Write-LogStd "SecretId=$sid SUCCESS ($domain\$username) AD reset + TSS updated" "INFO"
        $results += [pscustomobject]@{ SecretId=$sid; Status="SUCCESS"; Username=$username; Domain=$domain; Message="AD reset + TSS updated" }
    }
    catch {
        $failCount++
        $msg = $_.Exception.Message
        Write-LogStd "SecretId=$sid FAILED - $msg" "ERROR"
        $results += [pscustomobject]@{ SecretId=$sid; Status="FAILED"; Username=$null; Domain=$null; Message=$msg }
    }
}

Write-LogStd "Rotation complete. Total=$($results.Count) Failed=$failCount" "INFO"

if ($failCount -gt 0) {
    throw "$failCount rotation(s) failed."
}
