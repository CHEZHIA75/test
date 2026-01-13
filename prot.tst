<#
tss_service_account_password_rotate.ps1

Rotate AD Service Account passwords based on Secret Server Secret IDs.

Input:
  -SecretIds "1234,5678"  (comma-separated)
Options:
  -DryRun
  -ThrottleLimit (for parallel execution)

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

    [ValidateRange(1,50)]
    [int]$ThrottleLimit = 10,

    # Path to diceware wordlist (same one your python used)
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
    if ($map.Count -lt 1000) { Write-LogStd "Wordlist loaded but seems small ($($map.Count) entries). Check file." "WARN" }
    return $map
}

function Roll-DiceKey {
    # 4 dice rolls -> 4 digits 1-6, e.g., 1436
    $digits = for ($i=0; $i -lt 4; $i++) { Get-Random -Minimum 1 -Maximum 7 }
    return ($digits -join '')
}

function New-DicewarePassphrase {
    param(
        [hashtable]$WordMap,
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

function Reset-ADPassword {
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$DomainName,
        [Parameter(Mandatory)][string]$NewPassword
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $secure = ConvertTo-SecureString $NewPassword -AsPlainText -Force

    # Use -Server with the domain FQDN (works in most environments; adjust to a specific DC if needed)
    Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure -Server $DomainName -ErrorAction Stop
    Unlock-ADAccount -Identity $SamAccountName -Server $DomainName -ErrorAction SilentlyContinue
}

# ---- Start ----
Write-LogStd "Starting service account password rotation. DryRun=$DryRun ThrottleLimit=$ThrottleLimit" "INFO"

# Modules (match your existing environment style)
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-LogStd "ActiveDirectory module not available. Run on a host with RSAT/AD tools installed." "ERROR"
    throw
}

try {
    # Secret Server module (your other scripts use these)
    if (-not (Get-Command Connect-SecretServer -ErrorAction SilentlyContinue)) {
        throw "Secret Server cmdlets not found (Connect-SecretServer/Get-Secret). Ensure the Secret Server module is installed."
    }
} catch {
    Write-LogStd $_.Exception.Message "ERROR"
    throw
}

$ids = Parse-SecretIds -Value $SecretIds
$wordMap = Load-WordList -Path $WordListPath

Write-LogStd "Connecting to Secret Server using default credentials..." "INFO"
Connect-SecretServer -UseDefaultCredentials | Out-Null

# Process in parallel (PowerShell 7+). If you’re on Windows PowerShell 5.1, remove -Parallel and loop normally.
$results = $ids | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    param($DryRun, $wordMap)

    function Roll-DiceKey {
        $digits = for ($i=0; $i -lt 4; $i++) { Get-Random -Minimum 1 -Maximum 7 }
        return ($digits -join '')
    }

    function New-DicewarePassphrase {
        param([hashtable]$WordMap,[int]$Words=4,[string]$Delimiter="-",[int]$MinLength=30)
        while ($true) {
            $out = New-Object System.Collections.Generic.List[string]
            for ($i=0; $i -lt $Words; $i++) {
                $key = Roll-DiceKey
                $word = $WordMap[$key]
                if (-not $word) { $word = "UNKNOWN" }
                $out.Add( ($word.Substring(0,1).ToUpper() + $word.Substring(1).ToLower()) )
            }
            $digit = Get-Random -Minimum 0 -Maximum 10
            $out[$out.Count-1] = $out[$out.Count-1] + $digit
            $phrase = ($out -join $Delimiter)
            if ($phrase.Length -lt $MinLength) { continue }
            return $phrase
        }
    }

    function Reset-ADPasswordInner {
        param([string]$SamAccountName,[string]$DomainName,[string]$NewPassword)
        Import-Module ActiveDirectory -ErrorAction Stop
        $secure = ConvertTo-SecureString $NewPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $secure -Server $DomainName -ErrorAction Stop
        Unlock-ADAccount -Identity $SamAccountName -Server $DomainName -ErrorAction SilentlyContinue
    }

    function Update-TssPassword {
        param([int]$SecretId,[string]$NewPassword)
        # Secret Server module commonly supports Set-SecretField or Update-Secret.
        # We try the most likely cmdlets first.
        if (Get-Command Set-SecretField -ErrorAction SilentlyContinue) {
            Set-SecretField -SecretId $SecretId -FieldName "Password" -Value $NewPassword | Out-Null
            return
        }
        if (Get-Command Set-Secret -ErrorAction SilentlyContinue) {
            # Fallback: some environments require updating the whole secret object; keep it simple.
            $s = Get-Secret -SecretId $SecretId
            $s.Password = $NewPassword
            Set-Secret -Secret $s | Out-Null
            return
        }
        throw "No known Secret Server update cmdlet found (Set-SecretField / Set-Secret)."
    }

    $sid = $_
    try {
        $secret = Get-Secret -SecretId $sid

        # Field names from your screenshot (PaaS Service Account template)
        $username = $secret.Username
        $domain   = $secret.'Domain Name'

        if (-not $username -or -not $domain) {
            throw "Missing required fields (Username / Domain Name) in secret."
        }

        $newPw = New-DicewarePassphrase -WordMap $wordMap

        if ($DryRun) {
            [pscustomobject]@{
                SecretId   = $sid
                Status     = "DRY-RUN"
                Username   = $username
                Domain     = $domain
                Message    = "Would reset AD password and update TSS password"
            }
        }
        else {
            Reset-ADPasswordInner -SamAccountName $username -DomainName $domain -NewPassword $newPw
            Update-TssPassword -SecretId $sid -NewPassword $newPw

            [pscustomobject]@{
                SecretId   = $sid
                Status     = "SUCCESS"
                Username   = $username
                Domain     = $domain
                Message    = "AD password reset + TSS updated"
            }
        }
    }
    catch {
        [pscustomobject]@{
            SecretId   = $sid
            Status     = "FAILED"
            Username   = $null
            Domain     = $null
            Message    = $_.Exception.Message
        }
    }
} -ArgumentList $DryRun, $wordMap

# Summarize
$failed = $results | Where-Object { $_.Status -eq "FAILED" }
$ok     = $results | Where-Object { $_.Status -ne "FAILED" }

Write-LogStd "Rotation complete. Success/DRY-RUN=$($ok.Count) Failed=$($failed.Count)" "INFO"

$results | ForEach-Object {
    $lvl = if ($_.Status -eq "FAILED") { "ERROR" } else { "INFO" }
    Write-LogStd "SecretId=$($_.SecretId) Status=$($_.Status) User=$($_.Username) Domain=$($_.Domain) Msg=$($_.Message)" $lvl
}

if ($failed.Count -gt 0) {
    throw "$($failed.Count) rotation(s) failed."
}
