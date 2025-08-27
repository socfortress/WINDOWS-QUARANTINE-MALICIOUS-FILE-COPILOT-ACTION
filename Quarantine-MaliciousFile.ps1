[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$TargetPath,
  [string]$LogPath = "$env:TEMP\QuarantineFile-script.log",
  [string]$ARLog  = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log',
  [string]$Arg1
)

# Arg1 override for Velociraptor/Copilot actions
if ($Arg1 -and -not $TargetPath) { $TargetPath = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName   = $env:COMPUTERNAME
$LogMaxKB   = 100
$LogKeep    = 5
$QuarantineDir = "C:\Quarantine"
$runStart   = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function NowZ { (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz') }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Get-FileHashSafe {
  param([string]$Path,[ValidateSet('SHA256')]$Algorithm='SHA256')
  try {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      return (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash.ToLower()
    }
  } catch {
    Write-Log ("Hash error for {0}: {1}" -f $Path, $_.Exception.Message) 'WARN'
  }
  return $null
}

Rotate-Log
Write-Log "=== SCRIPT START : Quarantine File [$TargetPath] ==="

$ts = NowZ
$lines = @()

try {
  if (-not $TargetPath) { throw "TargetPath is required (or use -Arg1)" }
  if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
    throw "Target file not found: $TargetPath"
  }

  # Collect pre-move facts
  $preItem   = Get-Item -LiteralPath $TargetPath -ErrorAction Stop
  $preSize   = $preItem.Length
  $preHash   = Get-FileHashSafe -Path $TargetPath
  $preOwner  = (Get-Acl -LiteralPath $TargetPath).Owner

  if (-not (Test-Path -LiteralPath $QuarantineDir -PathType Container)) {
    New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null
  }

  # Build destination path (timestamp + GUID to avoid collisions)
  $stamp   = Get-Date -Format "yyyyMMddHHmmss"
  $guid    = [guid]::NewGuid().ToString("N").Substring(0,8)
  $base    = [IO.Path]::GetFileNameWithoutExtension($TargetPath)
  $newName = "{0}_{1}_{2}.quarantined" -f $base,$stamp,$guid
  $dest    = Join-Path $QuarantineDir $newName

  # Move to quarantine
  Move-Item -LiteralPath $TargetPath -Destination $dest -Force
  Write-Log "Moved file to quarantine: $dest" 'INFO'

  # Lock down ACL to Administrators only
  $admins = New-Object System.Security.Principal.NTAccount("BUILTIN","Administrators")
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $acl.SetOwner($admins)
  $acl.SetAccessRuleProtection($true,$false)  # disable inheritance
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admins, "FullControl", "Allow")
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $dest -AclObject $acl
  Write-Log "Stripped file permissions and restricted to Administrators" 'INFO'

  # Post-move facts for verification
  $postExists     = Test-Path -LiteralPath $dest -PathType Leaf
  $postHash       = if ($postExists) { Get-FileHashSafe -Path $dest } else { $null }
  $postAcl        = if ($postExists) { Get-Acl -LiteralPath $dest } else { $null }
  $postOwner      = if ($postAcl) { $postAcl.Owner } else { $null }
  $inheritDisabled= if ($postAcl) { -not $postAcl.AreAccessRulesInherited } else { $false }

  # Detail: quarantine action
  $lines += ([pscustomobject]@{
    timestamp        = $ts
    host             = $HostName
    action           = 'quarantine_file'
    copilot_action   = $true
    type             = 'detail'
    original_path    = $TargetPath
    quarantined_path = $dest
    size_bytes       = $preSize
    sha256_before    = $preHash
    sha256_after     = $postHash
  } | ConvertTo-Json -Compress -Depth 6)

  # Verification lines
  $lines += ([pscustomobject]@{
    timestamp        = $ts
    host             = $HostName
    action           = 'quarantine_file'
    copilot_action   = $true
    type             = 'verify_move'
    original_exists  = (Test-Path -LiteralPath $TargetPath -PathType Leaf)
    quarantined_exists = $postExists
    hashes_match     = ( ($preHash) -and ($postHash) -and ($preHash -eq $postHash) )
  } | ConvertTo-Json -Compress -Depth 6)

  $lines += ([pscustomobject]@{
    timestamp        = $ts
    host             = $HostName
    action           = 'quarantine_file'
    copilot_action   = $true
    type             = 'verify_acl'
    quarantined_path = $dest
    owner_before     = $preOwner
    owner_after      = $postOwner
    inheritance_disabled = $inheritDisabled
    expected_owner_contains = 'BUILTIN\Administrators'
    owner_is_admins  = ( "$postOwner" -like '*BUILTIN*Administrators*' )
  } | ConvertTo-Json -Compress -Depth 6)

  # Summary (must be first)
  $status =
    if ($postExists -and $preHash -and $postHash -and ($preHash -eq $postHash)) { 'success' }
    elseif ($postExists) { 'moved_but_unverified' }
    else { 'failed' }

  $summary = [pscustomobject]@{
    timestamp        = $ts
    host             = $HostName
    action           = 'quarantine_file'
    copilot_action   = $true
    type             = 'summary'
    original         = $TargetPath
    quarantined_as   = $dest
    status           = $status
    duration_s       = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }
  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 6 )) + $lines

  # Atomic write to ARLog
  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = NowZ
    host           = $HostName
    action         = 'quarantine_file'
    copilot_action = $true
    type           = 'error'
    target         = $TargetPath
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(($err | ConvertTo-Json -Compress -Depth 6)) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
