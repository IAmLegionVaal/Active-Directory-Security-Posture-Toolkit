# Active Directory Security Posture Toolkit

A PowerShell toolkit for reviewing core Active Directory security indicators and applying selected, explicit account-hygiene repairs.

## Audit

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Active_Directory_Security_Posture_Toolkit.ps1
```

## Repair

Preview a user change:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Active_Directory_Security_Posture_Repair_Toolkit.ps1 -Identity jsmith -ObjectType User -ClearPasswordNeverExpires -DryRun
```

Examples:

```powershell
.\Active_Directory_Security_Posture_Repair_Toolkit.ps1 -Identity jsmith -DisableAccount
.\Active_Directory_Security_Posture_Repair_Toolkit.ps1 -Identity jsmith -RequirePasswordChange
.\Active_Directory_Security_Posture_Repair_Toolkit.ps1 -Identity jsmith -ClearPasswordNeverExpires
.\Active_Directory_Security_Posture_Repair_Toolkit.ps1 -Identity PC-OLD-01 -ObjectType Computer -DisableAccount
```

## Repair behavior

- Requires elevation and the RSAT Active Directory module.
- Works only on explicitly selected users or computers; it does not bulk-disable findings from the report.
- Can disable a selected account, require a selected user to change password at next sign-in, or clear `PasswordNeverExpires`.
- Saves a JSON snapshot of the selected object before modification.
- Refuses protected administrative objects, domain controllers and disabling the current signed-in user.
- Supports `-DryRun`, confirmation or `-Yes`, timestamped logs, verification and clear exit codes.

Exit codes are `0` success, `2` invalid or unsafe input, `3` missing privileges or prerequisites, `4` cancelled, `5` action failure and `6` verification failure.

## Safety

Review dependencies and ownership before disabling any account. The repair script does not delete objects, reset passwords, change domain policy or make automatic bulk changes.

## Author

Dewald Pretorius — L2 IT Support Engineer
