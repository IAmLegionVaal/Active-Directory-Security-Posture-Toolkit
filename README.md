# Active Directory Security Posture Toolkit

A read-only PowerShell toolkit for reviewing core Active Directory security and hygiene indicators.

## Coverage

- Domain and forest functional levels
- Domain controller inventory
- Privileged group membership counts
- Password and lockout policy summary
- Stale user and computer accounts
- Accounts with password-never-expires
- Disabled accounts and inactive objects
- Replication status summary where available

## Run

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Active_Directory_Security_Posture_Toolkit.ps1
```

## Requirements

RSAT Active Directory module and appropriate directory read permissions.

## Safety

Read-only reporting. No directory objects or policies are changed.
