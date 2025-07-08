# Windows PowerShell Reference Card

## Core PowerShell Concepts

### Basic Syntax

- **Cmdlets**: Verb-Noun format (e.g., `Get-Process`, `Set-Location`)
- **Parameters**: `-ParameterName Value` or `-ParameterName:$true`
- **Pipeline**: `|` passes objects between cmdlets
- **Variables**: `$variable = "value"`
- **Comments**: `# Single line` or `<# Multi-line #>`

### Help System

|Command       |Description                   |Example                     |
|--------------|------------------------------|----------------------------|
|`Get-Help`    |Display help for cmdlets      |`Get-Help Get-Process -Full`|
|`Get-Command` |List available cmdlets        |`Get-Command *process*`     |
|`Get-Member`  |Show object properties/methods|`Get-Process                |
|`Show-Command`|GUI for cmdlet parameters     |`Show-Command Get-Process`  |

## File System Operations

|Command                  |Description              |Example                                            |
|-------------------------|-------------------------|---------------------------------------------------|
|`Get-Location` (pwd)     |Show current directory   |`Get-Location`                                     |
|`Set-Location` (cd)      |Change directory         |`Set-Location C:\Users`                            |
|`Get-ChildItem` (ls, dir)|List directory contents  |`Get-ChildItem -Recurse -Filter "*.txt"`           |
|`New-Item`               |Create files/directories |`New-Item -ItemType Directory -Path "C:\NewFolder"`|
|`Copy-Item` (cp)         |Copy files/directories   |`Copy-Item "source.txt" "destination.txt"`         |
|`Move-Item` (mv)         |Move/rename files        |`Move-Item "old.txt" "new.txt"`                    |
|`Remove-Item` (rm, del)  |Delete files/directories |`Remove-Item "file.txt" -Force`                    |
|`Get-Content` (cat)      |Read file content        |`Get-Content "file.txt" -Tail 10`                  |
|`Set-Content`            |Write to file (overwrite)|`Set-Content "file.txt" "Hello World"`             |
|`Add-Content`            |Append to file           |`Add-Content "file.txt" "New line"`                |
|`Test-Path`              |Check if path exists     |`Test-Path "C:\file.txt"`                          |
|`Resolve-Path`           |Get full path            |`Resolve-Path ".\file.txt"`                        |

## Process Management

|Command           |Description               |Example                              |
|------------------|--------------------------|-------------------------------------|
|`Get-Process` (ps)|List running processes    |`Get-Process -Name "notepad"`        |
|`Start-Process`   |Start new process         |`Start-Process notepad.exe`          |
|`Stop-Process`    |Stop process              |`Stop-Process -Name "notepad" -Force`|
|`Wait-Process`    |Wait for process to end   |`Wait-Process -Name "installer"`     |
|`Debug-Process`   |Attach debugger to process|`Debug-Process -Name "app"`          |

## Service Management

|Command          |Description      |Example                                                     |
|-----------------|-----------------|------------------------------------------------------------|
|`Get-Service`    |List services    |`Get-Service -Name "w32time"`                               |
|`Start-Service`  |Start service    |`Start-Service -Name "Spooler"`                             |
|`Stop-Service`   |Stop service     |`Stop-Service -Name "Spooler"`                              |
|`Restart-Service`|Restart service  |`Restart-Service -Name "Spooler"`                           |
|`Set-Service`    |Configure service|`Set-Service -Name "Spooler" -StartupType Automatic`        |
|`New-Service`    |Create service   |`New-Service -Name "MyService" -BinaryPathName "C:\app.exe"`|

## Registry Operations

|Command              |Description              |Example                                                                      |
|---------------------|-------------------------|-----------------------------------------------------------------------------|
|`Get-ItemProperty`   |Read registry values     |`Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"`   |
|`Set-ItemProperty`   |Set registry value       |`Set-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Version" -Value "1.0"` |
|`New-ItemProperty`   |Create registry value    |`New-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting" -Value "True"`|
|`Remove-ItemProperty`|Delete registry value    |`Remove-ItemProperty -Path "HKCU:\Software\MyApp" -Name "Setting"`           |
|`Test-Path`          |Check registry key exists|`Test-Path "HKLM:\SOFTWARE\MyApp"`                                           |

## Network Operations

|Command             |Description              |Example                                                        |
|--------------------|-------------------------|---------------------------------------------------------------|
|`Test-NetConnection`|Test network connectivity|`Test-NetConnection google.com -Port 80`                       |
|`Get-NetAdapter`    |List network adapters    |`Get-NetAdapter                                                |
|`Get-NetIPAddress`  |Get IP addresses         |`Get-NetIPAddress -AddressFamily IPv4`                         |
|`Invoke-WebRequest` |HTTP requests            |`Invoke-WebRequest -Uri "https://api.github.com"`              |
|`Invoke-RestMethod` |REST API calls           |`Invoke-RestMethod -Uri "https://api.github.com/users/octocat"`|
|`Resolve-DnsName`   |DNS lookup               |`Resolve-DnsName google.com`                                   |

## System Information

|Command           |Description            |Example                                           |
|------------------|-----------------------|--------------------------------------------------|
|`Get-ComputerInfo`|System information     |`Get-ComputerInfo                                 |
|`Get-WmiObject`   |WMI queries            |`Get-WmiObject -Class Win32_LogicalDisk`          |
|`Get-CimInstance` |CIM queries (newer)    |`Get-CimInstance -ClassName Win32_OperatingSystem`|
|`Get-EventLog`    |Read event logs        |`Get-EventLog -LogName System -Newest 10`         |
|`Get-WinEvent`    |Read Windows event logs|`Get-WinEvent -LogName Application -MaxEvents 5`  |
|`Get-Hotfix`      |List installed updates |`Get-Hotfix                                       |

## User and Security

|Command               |Description            |Example                                                                                           |
|----------------------|-----------------------|--------------------------------------------------------------------------------------------------|
|`Get-LocalUser`       |List local users       |`Get-LocalUser`                                                                                   |
|`New-LocalUser`       |Create local user      |`New-LocalUser -Name "TestUser" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)`|
|`Get-LocalGroup`      |List local groups      |`Get-LocalGroup`                                                                                  |
|`Add-LocalGroupMember`|Add user to group      |`Add-LocalGroupMember -Group "Administrators" -Member "TestUser"`                                 |
|`Get-Acl`             |Get file permissions   |`Get-Acl "C:\file.txt"`                                                                           |
|`Set-Acl`             |Set file permissions   |`Set-Acl -Path "C:\file.txt" -AclObject $acl`                                                     |
|`Get-ExecutionPolicy` |Check execution policy |`Get-ExecutionPolicy -List`                                                                       |
|`Set-ExecutionPolicy` |Change execution policy|`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`                                             |

## Variables and Data Types

|Command                 |Description         |Example                                                |
|------------------------|--------------------|-------------------------------------------------------|
|`Get-Variable`          |List variables      |`Get-Variable -Name "PSVersionTable"`                  |
|`Set-Variable`          |Set variable value  |`Set-Variable -Name "myVar" -Value "Hello"`            |
|`Remove-Variable`       |Delete variable     |`Remove-Variable -Name "myVar"`                        |
|`Clear-Variable`        |Clear variable value|`Clear-Variable -Name "myVar"`                         |
|`New-Object`            |Create .NET objects |`New-Object System.DateTime(2023,12,25)`               |
|`ConvertTo-SecureString`|Create secure string|`ConvertTo-SecureString "password" -AsPlainText -Force`|

## Text Processing and Formatting

|Command                      |Description         |Example                |
|-----------------------------|--------------------|-----------------------|
|`Select-String`              |Search text patterns|`Get-Content “file.txt”|
|`Where-Object` (where, ?)    |Filter objects      |`Get-Process           |
|`ForEach-Object` (foreach, %)|Process each object |`Get-Process           |
|`Sort-Object`                |Sort objects        |`Get-Process           |
|`Group-Object`               |Group objects       |`Get-Process           |
|`Measure-Object`             |Calculate statistics|`Get-Process           |
|`Select-Object`              |Select properties   |`Get-Process           |
|`Format-Table` (ft)          |Format as table     |`Get-Process           |
|`Format-List` (fl)           |Format as list      |`Get-Process           |
|`Out-GridView`               |Display in GUI grid |`Get-Process           |

## Data Conversion

|Command           |Description         |Example                    |
|------------------|--------------------|---------------------------|
|`ConvertTo-Json`  |Convert to JSON     |`Get-Process               |
|`ConvertFrom-Json`|Parse JSON          |`’{“name”:“John”,“age”:30}’|
|`ConvertTo-Csv`   |Convert to CSV      |`Get-Process               |
|`ConvertFrom-Csv` |Parse CSV           |`Import-Csv "data.csv"`    |
|`ConvertTo-Html`  |Convert to HTML     |`Get-Process               |
|`ConvertTo-Xml`   |Convert to XML      |`Get-Process               |
|`Export-Csv`      |Export to CSV file  |`Get-Process               |
|`Import-Csv`      |Import from CSV file|`Import-Csv "data.csv"`    |

## Control Flow and Scripting

### Conditional Statements

```powershell
# If statement
if ($condition) {
    # code
} elseif ($condition2) {
    # code
} else {
    # code
}

# Switch statement
switch ($variable) {
    "value1" { "Action 1" }
    "value2" { "Action 2" }
    default { "Default action" }
}
```

### Loops

```powershell
# For loop
for ($i = 0; $i -lt 10; $i++) {
    Write-Host $i
}

# ForEach loop
foreach ($item in $collection) {
    Write-Host $item
}

# While loop
while ($condition) {
    # code
}

# Do-While loop
do {
    # code
} while ($condition)
```

### Functions

```powershell
# Simple function
function Get-Square($number) {
    return $number * $number
}

# Advanced function
function Get-ProcessInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProcessName
    )
    
    Get-Process -Name $ProcessName | Select-Object Name, CPU, WorkingSet
}
```

## Error Handling

|Command        |Description             |Example                                                             |
|---------------|------------------------|--------------------------------------------------------------------|
|`Try-Catch`    |Handle errors           |`try { Get-Process "nonexistent" } catch { Write-Host "Error: $_" }`|
|`Write-Error`  |Write error message     |`Write-Error "Something went wrong"`                                |
|`Write-Warning`|Write warning message   |`Write-Warning "This is a warning"`                                 |
|`Write-Verbose`|Write verbose message   |`Write-Verbose "Detailed information"`                              |
|`Write-Debug`  |Write debug message     |`Write-Debug "Debug information"`                                   |
|`$Error`       |Automatic error variable|`$Error[0]                                                          |

## Common Operators

### Comparison Operators

|Operator   |Description          |Example                    |
|-----------|---------------------|---------------------------|
|`-eq`      |Equal                |`$a -eq $b`                |
|`-ne`      |Not equal            |`$a -ne $b`                |
|`-lt`      |Less than            |`$a -lt $b`                |
|`-le`      |Less than or equal   |`$a -le $b`                |
|`-gt`      |Greater than         |`$a -gt $b`                |
|`-ge`      |Greater than or equal|`$a -ge $b`                |
|`-like`    |Wildcard matching    |`$string -like "*test*"`   |
|`-match`   |Regex matching       |`$string -match "^[0-9]+$"`|
|`-contains`|Contains element     |`$array -contains "value"` |
|`-in`      |Element in collection|`"value" -in $array`       |

### Logical Operators

|Operator     |Description|Example                     |
|-------------|-----------|----------------------------|
|`-and`       |Logical AND|`($a -eq 1) -and ($b -eq 2)`|
|`-or`        |Logical OR |`($a -eq 1) -or ($b -eq 2)` |
|`-not` or `!`|Logical NOT|`-not ($a -eq 1)`           |

## Useful One-Liners

### System Administration

```powershell
# Get system uptime
(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

# Find large files
Get-ChildItem -Recurse | Where-Object {$_.Length -gt 100MB} | Sort-Object Length -Descending

# Get installed programs
Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Sort-Object Name

# Check disk space
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}}, @{Name="FreeSpace(GB)";Expression={[math]::Round($_.FreeSpace/1GB,2)}}

# Get network adapter info
Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, InterfaceDescription, LinkSpeed

# Find processes using most CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, WorkingSet

# Get Windows features
Get-WindowsFeature | Where-Object InstallState -eq "Installed" | Select-Object Name, DisplayName
```

### Text Processing

```powershell
# Count lines in file
(Get-Content "file.txt").Count

# Find unique lines
Get-Content "file.txt" | Sort-Object | Get-Unique

# Replace text in file
(Get-Content "file.txt") -replace "old", "new" | Set-Content "file.txt"

# Find files modified in last 7 days
Get-ChildItem -Recurse | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}
```

## Environment Variables

|Command                                  |Description                   |Example                                                          |
|-----------------------------------------|------------------------------|-----------------------------------------------------------------|
|`$env:VARIABLE`                          |Access environment variable   |`$env:PATH`                                                      |
|`Get-ChildItem Env:`                     |List all environment variables|`Get-ChildItem Env:                                              |
|`[Environment]::SetEnvironmentVariable()`|Set environment variable      |`[Environment]::SetEnvironmentVariable("MyVar", "Value", "User")`|

## PowerShell Profiles

|Location                         |Description               |
|---------------------------------|--------------------------|
|`$PROFILE.CurrentUserCurrentHost`|Current user, current host|
|`$PROFILE.CurrentUserAllHosts`   |Current user, all hosts   |
|`$PROFILE.AllUsersCurrentHost`   |All users, current host   |
|`$PROFILE.AllUsersAllHosts`      |All users, all hosts      |

## Common Parameters

|Parameter     |Description             |Example                                                  |
|--------------|------------------------|---------------------------------------------------------|
|`-WhatIf`     |Shows what would happen |`Remove-Item "file.txt" -WhatIf`                         |
|`-Confirm`    |Prompts for confirmation|`Remove-Item "file.txt" -Confirm`                        |
|`-Force`      |Forces the action       |`Remove-Item "file.txt" -Force`                          |
|`-Verbose`    |Shows detailed output   |`Copy-Item "file.txt" "backup.txt" -Verbose`             |
|`-ErrorAction`|Controls error handling |`Get-Process "nonexistent" -ErrorAction SilentlyContinue`|

## Tips and Best Practices

1. **Use Tab Completion**: Press Tab to auto-complete cmdlet names, parameters, and file paths
1. **Use Aliases**: Common aliases like `ls` (Get-ChildItem), `cd` (Set-Location), `pwd` (Get-Location)
1. **Pipeline Philosophy**: Pass objects through the pipeline rather than parsing text
1. **Use -WhatIf**: Always test destructive operations with -WhatIf first
1. **Parameterize Scripts**: Use param() blocks for reusable scripts
1. **Error Handling**: Always include proper error handling in scripts
1. **Use Approved Verbs**: Get-Verb shows approved verb list for functions
1. **Comment Your Code**: Use # for single-line and <# #> for multi-line comments