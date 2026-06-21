[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Identity,
    [ValidateSet('User','Computer')][string]$ObjectType='User',
    [switch]$DisableAccount,
    [switch]$RequirePasswordChange,
    [switch]$ClearPasswordNeverExpires,
    [switch]$DryRun,
    [switch]$Yes,
    [string]$LogDirectory="$env:ProgramData\IAmLegionVaal\ADSecurityPostureRepair"
)

$ErrorActionPreference='Stop'
$ExitInvalidInput=2; $ExitPrerequisite=3; $ExitCancelled=4; $ExitActionFailure=5; $ExitVerificationFailure=6
function Test-Admin {
    $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Write-Log([string]$Message){$line="{0:u} {1}" -f (Get-Date),$Message;Write-Host $line;Add-Content -LiteralPath $script:LogPath -Value $line}
function Invoke-Step([string]$Description,[scriptblock]$Action){if($DryRun){Write-Log "[DRY-RUN] $Description"}else{Write-Log "[ACTION] $Description";& $Action}}

if(-not($DisableAccount -or $RequirePasswordChange -or $ClearPasswordNeverExpires)){Write-Error 'Select at least one repair action.';exit $ExitInvalidInput}
if($ObjectType -eq 'Computer' -and ($RequirePasswordChange -or $ClearPasswordNeverExpires)){Write-Error 'Password-change actions apply only to users.';exit $ExitInvalidInput}
if(-not(Test-Admin)){Write-Error 'Run from an elevated PowerShell session.';exit $ExitPrerequisite}
try{Import-Module ActiveDirectory -ErrorAction Stop}catch{Write-Error "ActiveDirectory module unavailable: $($_.Exception.Message)";exit $ExitPrerequisite}

New-Item -ItemType Directory -Path $LogDirectory -Force|Out-Null
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss';$script:LogPath=Join-Path $LogDirectory "ADSecurityPostureRepair_$stamp.log";$backupPath=Join-Path $LogDirectory "ADObject_$stamp.json"
try{
    if($ObjectType -eq 'User'){$object=Get-ADUser -Identity $Identity -Properties Enabled,AdminCount,PasswordNeverExpires,DistinguishedName,PasswordLastSet}
    else{$object=Get-ADComputer -Identity $Identity -Properties Enabled,AdminCount,PrimaryGroupID,OperatingSystem,DistinguishedName}
}catch{Write-Error "Unable to resolve $ObjectType '$Identity': $($_.Exception.Message)";exit $ExitInvalidInput}

if($object.AdminCount -eq 1){Write-Error 'Protected administrative objects are excluded from automated repair.';exit $ExitInvalidInput}
if($ObjectType -eq 'Computer' -and ($object.PrimaryGroupID -eq 516 -or $object.DistinguishedName -match '(?i)OU=Domain Controllers')){Write-Error 'Domain controllers are excluded from automated disablement.';exit $ExitInvalidInput}
if($ObjectType -eq 'User' -and $object.SamAccountName -ieq $env:USERNAME){Write-Error 'The current signed-in account cannot be disabled by this tool.';exit $ExitInvalidInput}
$object|Select-Object *|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $backupPath -Encoding UTF8
Write-Log "Saved pre-change object evidence to $backupPath"

$actions=@();if($DisableAccount){$actions+='disable account'};if($RequirePasswordChange){$actions+='require password change'};if($ClearPasswordNeverExpires){$actions+='clear password-never-expires'}
if(-not $DryRun -and -not $Yes){$answer=Read-Host ("Proceed for {0} {1}: {2}? [y/N]" -f $ObjectType,$Identity,($actions -join '; '));if($answer -notmatch '^(?i)y(es)?$'){Write-Log '[CANCELLED] No changes were made.';exit $ExitCancelled}}

try{
    if($DisableAccount){Invoke-Step "Disable $ObjectType '$Identity'" {Disable-ADAccount -Identity $object.DistinguishedName}}
    if($RequirePasswordChange){Invoke-Step "Require password change for '$Identity'" {Set-ADUser -Identity $object.DistinguishedName -ChangePasswordAtLogon $true}}
    if($ClearPasswordNeverExpires){Invoke-Step "Clear password-never-expires for '$Identity'" {Set-ADUser -Identity $object.DistinguishedName -PasswordNeverExpires $false}}
}catch{Write-Log "[FAILED] $($_.Exception.Message)";exit $ExitActionFailure}
if($DryRun){Write-Log '[COMPLETE] Dry-run completed.';exit 0}

$verifyFailed=$false
try{
    if($ObjectType -eq 'User'){$after=Get-ADUser -Identity $object.DistinguishedName -Properties Enabled,PasswordNeverExpires}
    else{$after=Get-ADComputer -Identity $object.DistinguishedName -Properties Enabled}
    Write-Log ("[VERIFY] Enabled={0}; PasswordNeverExpires={1}" -f $after.Enabled,$after.PasswordNeverExpires)
    if($DisableAccount -and $after.Enabled){$verifyFailed=$true}
    if($ClearPasswordNeverExpires -and $after.PasswordNeverExpires){$verifyFailed=$true}
}catch{Write-Log "[VERIFY-FAILED] $($_.Exception.Message)";$verifyFailed=$true}
if($verifyFailed){exit $ExitVerificationFailure}
Write-Log '[COMPLETE] Requested repairs completed and verification passed.'
exit 0
