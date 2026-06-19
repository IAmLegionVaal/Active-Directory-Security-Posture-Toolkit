#requires -Version 5.1
[CmdletBinding()]
param([int]$StaleDays=90,[string]$OutputPath)

$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
if([string]::IsNullOrWhiteSpace($OutputPath)){$OutputPath=Join-Path ([Environment]::GetFolderPath('Desktop')) 'AD_Security_Posture_Reports'}
New-Item -Path $OutputPath -ItemType Directory -Force|Out-Null

try{Import-Module ActiveDirectory -ErrorAction Stop}catch{Write-Error 'ActiveDirectory module not found. Install RSAT Active Directory tools.';return}

$domain=Get-ADDomain
$forest=Get-ADForest
$policy=Get-ADDefaultDomainPasswordPolicy
$dcs=Get-ADDomainController -Filter *|Select-Object HostName,Site,IPv4Address,OperatingSystem,IsGlobalCatalog,OperationMasterRoles
$cutoff=(Get-Date).AddDays(-1*$StaleDays)

$users=Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordNeverExpires,PasswordLastSet,AdminCount,DistinguishedName
$computers=Get-ADComputer -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,OperatingSystem,DistinguishedName

$staleUsers=$users|Where-Object{$_.Enabled -and ((-not $_.LastLogonDate) -or $_.LastLogonDate -lt $cutoff)}|Select-Object SamAccountName,Name,LastLogonDate,PasswordLastSet,DistinguishedName
$staleComputers=$computers|Where-Object{$_.Enabled -and ((-not $_.LastLogonDate) -or $_.LastLogonDate -lt $cutoff)}|Select-Object Name,OperatingSystem,LastLogonDate,PasswordLastSet,DistinguishedName
$neverExpires=$users|Where-Object{$_.Enabled -and $_.PasswordNeverExpires}|Select-Object SamAccountName,Name,PasswordLastSet,AdminCount,DistinguishedName

$privilegedGroups='Domain Admins','Enterprise Admins','Schema Admins','Administrators'
$groupSummary=foreach($groupName in $privilegedGroups){
    $group=Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
    if($group){$members=Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue;[PSCustomObject]@{Group=$groupName;MemberCount=@($members).Count}}
}

$replication=Get-ADReplicationPartnerMetadata -Target * -Scope Domain -ErrorAction SilentlyContinue|Select-Object Server,Partner,Partition,LastReplicationSuccess,ConsecutiveReplicationFailures,LastReplicationResult

$findings=@(
    [PSCustomObject]@{Area='Stale enabled users';Status=$(if(@($staleUsers).Count -gt 0){'Review'}else{'Pass'});Count=@($staleUsers).Count;Detail="Threshold: $StaleDays days"},
    [PSCustomObject]@{Area='Stale enabled computers';Status=$(if(@($staleComputers).Count -gt 0){'Review'}else{'Pass'});Count=@($staleComputers).Count;Detail="Threshold: $StaleDays days"},
    [PSCustomObject]@{Area='Password never expires';Status=$(if(@($neverExpires).Count -gt 0){'Review'}else{'Pass'});Count=@($neverExpires).Count;Detail='Enabled user accounts'},
    [PSCustomObject]@{Area='Replication failures';Status=$(if(@($replication|Where-Object ConsecutiveReplicationFailures -gt 0).Count -gt 0){'Review'}else{'Pass'});Count=@($replication|Where-Object ConsecutiveReplicationFailures -gt 0).Count;Detail='Replication partner metadata'}
)

$summary=[PSCustomObject]@{
    Domain=$domain.DNSRoot
    DomainMode=$domain.DomainMode
    ForestMode=$forest.ForestMode
    DomainControllers=@($dcs).Count
    Users=@($users).Count
    Computers=@($computers).Count
    StaleUsers=@($staleUsers).Count
    StaleComputers=@($staleComputers).Count
    PasswordNeverExpires=@($neverExpires).Count
    Generated=Get-Date
}

$summary|Export-Csv (Join-Path $OutputPath "ad_security_summary_$stamp.csv") -NoTypeInformation -Encoding UTF8
$findings|Export-Csv (Join-Path $OutputPath "ad_security_findings_$stamp.csv") -NoTypeInformation -Encoding UTF8
$dcs|Export-Csv (Join-Path $OutputPath "domain_controllers_$stamp.csv") -NoTypeInformation -Encoding UTF8
$groupSummary|Export-Csv (Join-Path $OutputPath "privileged_group_summary_$stamp.csv") -NoTypeInformation -Encoding UTF8
$staleUsers|Export-Csv (Join-Path $OutputPath "stale_users_$stamp.csv") -NoTypeInformation -Encoding UTF8
$staleComputers|Export-Csv (Join-Path $OutputPath "stale_computers_$stamp.csv") -NoTypeInformation -Encoding UTF8
$neverExpires|Export-Csv (Join-Path $OutputPath "password_never_expires_$stamp.csv") -NoTypeInformation -Encoding UTF8
$replication|Export-Csv (Join-Path $OutputPath "replication_summary_$stamp.csv") -NoTypeInformation -Encoding UTF8

@{Summary=$summary;PasswordPolicy=$policy;Findings=$findings;DomainControllers=$dcs;PrivilegedGroups=$groupSummary;StaleUsers=$staleUsers;StaleComputers=$staleComputers;PasswordNeverExpires=$neverExpires;Replication=$replication}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $OutputPath "ad_security_posture_$stamp.json") -Encoding UTF8

$html="<h1>Active Directory Security Posture</h1><p>Generated $(Get-Date)</p><h2>Summary</h2>$(@($summary)|ConvertTo-Html -Fragment)<h2>Findings</h2>$($findings|ConvertTo-Html -Fragment)<h2>Password Policy</h2>$(@($policy)|ConvertTo-Html -Fragment)<h2>Privileged Groups</h2>$($groupSummary|ConvertTo-Html -Fragment)"
$html|ConvertTo-Html -Title 'Active Directory Security Posture'|Set-Content (Join-Path $OutputPath "ad_security_posture_$stamp.html") -Encoding UTF8
$summary|Format-List
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
