# HTB Skill Assessment — Windows Event Log Analysis

## Scenario

> "To keep you sharp, your SOC manager has assigned you the task of analyzing older attack logs and providing answers to specific questions."

This document contains my investigation process, commands, findings, and conclusions for each question in the assessment.

---

## Q1 — DLL Hijacking Investigation

**Question:**  
By examining the logs located in the `C:\Logs\DLLHijack` directory, determine the process responsible for executing a DLL hijacking attack.

**Answer format:** `_.exe`

### Objective

The objective was to identify which executable was used in a possible DLL hijacking attack.

### Reasoning

DLL Hijacking occurs when a legitimate process loads a malicious or suspicious DLL.

With this in mind, I focused on:

```text
Sysmon Event ID 7 — Image Loaded
```

This event shows:

| Field | Description |
|---|---|
| Image | Process/executable that loaded the DLL |
| ImageLoaded | DLL that was loaded |
| Signed | Whether the DLL is signed |
| Signature | Digital signature information |

Since there were many legitimate events, I reduced noise by excluding DLLs loaded from normal Windows paths such as:

```text
C:\Windows\
C:\Program Files\
```

Then I focused on suspicious indicators:

- DLLs loaded from `ProgramData`, `Temp`, `Desktop`, `Downloads`, or `Users`
- Unsigned DLLs
- Legitimate executables running outside `System32`

### Command Used

```powershell
Get-ChildItem "C:\Logs\DLLHijack" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=7} -ErrorAction SilentlyContinue
} |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Image       = ($d | Where-Object {$_.Name -eq "Image"}).'#text'
        ImageLoaded = ($d | Where-Object {$_.Name -eq "ImageLoaded"}).'#text'
        Signed      = ($d | Where-Object {$_.Name -eq "Signed"}).'#text'
        Signature   = ($d | Where-Object {$_.Name -eq "Signature"}).'#text'
    }
} |
Where-Object {
    $_.ImageLoaded -like "*.dll" -and
    $_.ImageLoaded -notlike "C:\Windows\*" -and
    $_.ImageLoaded -notlike "C:\Program Files*" -and
    (
        $_.Signed -eq "false" -or
        $_.ImageLoaded -like "C:\Users\*" -or
        $_.ImageLoaded -like "*\Temp\*" -or
        $_.ImageLoaded -like "*\Desktop\*" -or
        $_.ImageLoaded -like "*\Downloads\*" -or
        $_.ImageLoaded -like "*\ProgramData\*"
    )
} |
Sort-Object Time |
Format-List
```

### Findings

```text
Time        : 4/27/2022 6:39:11 PM
Image       : C:\ProgramData\Dism.exe
ImageLoaded : C:\ProgramData\DismCore.dll
Signed      : false
Signature   : -
```

I also found:

```text
Time        : 4/27/2022 6:39:30 PM
Image       : C:\Windows\System32\rundll32.exe
ImageLoaded : C:\ProgramData\DismCore.dll
Signed      : false
Signature   : -
```

### Conclusion

The executable used for the DLL hijacking attack was:

```text
Dism.exe
```

I reached this conclusion because `Dism.exe` should normally be located in:

```text
C:\Windows\System32\
```

However, I found a copy in:

```text
C:\ProgramData\
```

Additionally, the process loaded:

```text
DismCore.dll
```

also located in `ProgramData` and without a valid digital signature.

This is typical DLL hijacking behavior, where an attacker copies a legitimate executable to a controlled folder and places a malicious DLL with the expected name next to it, forcing the executable to load the malicious DLL instead of the original system DLL.

---

## Q2 — Unmanaged PowerShell Execution

**Question:**  
By examining the logs located in the `C:\Logs\PowershellExec` directory, determine the process that executed unmanaged PowerShell code.

**Answer format:** `_.exe`

### Reasoning

Unmanaged PowerShell means PowerShell code is executed inside another process without a visible `powershell.exe` process.

Normally, when PowerShell is used, I would expect to see:

```text
powershell.exe
```

loading .NET DLLs such as:

```text
clr.dll
clrjit.dll
mscoree.dll
```

In unmanaged execution, the attacker injects the .NET runtime and PowerShell components into another seemingly legitimate process to avoid detection.

With this in mind, I searched for:

```text
Sysmon Event ID 7 — Image Loaded
```

and filtered for processes that:

- were not `powershell.exe`
- were not `pwsh.exe`
- were not `powershell_ise.exe`
- loaded .NET-related DLLs

The DLLs used as indicators were:

```text
mscoree.dll
clr.dll
clrjit.dll
System.Management.Automation.dll
```

### Command Used

```powershell
Get-ChildItem "C:\Logs\PowershellExec" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=7} -ErrorAction SilentlyContinue
} |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Image       = ($d | Where-Object {$_.Name -eq "Image"}).'#text'
        ImageLoaded = ($d | Where-Object {$_.Name -eq "ImageLoaded"}).'#text'
        Signed      = ($d | Where-Object {$_.Name -eq "Signed"}).'#text'
        Signature   = ($d | Where-Object {$_.Name -eq "Signature"}).'#text'
    }
} |
Where-Object {
    (
        $_.ImageLoaded -like "*clr.dll" -or
        $_.ImageLoaded -like "*clrjit.dll" -or
        $_.ImageLoaded -like "*mscoree.dll" -or
        $_.ImageLoaded -like "*System.Management.Automation.dll"
    ) -and
    $_.Image -notlike "*powershell.exe" -and
    $_.Image -notlike "*pwsh.exe" -and
    $_.Image -notlike "*powershell_ise.exe"
} |
Sort-Object Time |
Format-List
```

### Findings

```text
Time        : 4/27/2022 6:59:42 PM
Image       : C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
ImageLoaded : C:\Windows\System32\mscoree.dll
```

```text
Time        : 4/27/2022 6:59:42 PM
Image       : C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
ImageLoaded : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
```

```text
Time        : 4/27/2022 6:59:42 PM
Image       : C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
ImageLoaded : C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll
```

### Conclusion

The process responsible for executing unmanaged PowerShell code was:

```text
Calculator.exe
```

---

## Q3 — Process Injection Investigation

**Question:**  
By examining the logs located in the `C:\Logs\PowershellExec` directory, determine the process that injected into the process that executed unmanaged PowerShell code.

**Answer format:** `_.exe`

### Reasoning

After identifying that `Calculator.exe` executed unmanaged PowerShell code, the next goal was to discover which process injected into it.

I first confirmed that `Calculator.exe` was the victim process because it loaded DLLs associated with the .NET runtime:

```text
mscoree.dll
clr.dll
clrjit.dll
```

This indicated that .NET/PowerShell code was running inside a process that normally should not load those components.

To identify the injecting process, I searched for process injection-related events.

The most relevant event was:

```text
Sysmon Event ID 8 — CreateRemoteThread
```

This event is useful because process injection techniques often involve creating a remote thread inside another process.

### Command Used

```powershell
Get-ChildItem "C:\Logs\PowershellExec" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=8} -ErrorAction SilentlyContinue
} |
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time          = $_.TimeCreated
        SourceImage   = ($d | Where-Object {$_.Name -eq "SourceImage"}).'#text'
        TargetImage   = ($d | Where-Object {$_.Name -eq "TargetImage"}).'#text'
        StartModule   = ($d | Where-Object {$_.Name -eq "StartModule"}).'#text'
        StartFunction = ($d | Where-Object {$_.Name -eq "StartFunction"}).'#text'
    }
} |
Where-Object {
    $_.TargetImage -like "*Calculator.exe"
} |
Format-List
```

### Findings

```text
Time          : 4/27/2022 6:59:42 PM
SourceImage   : C:\Windows\System32\rundll32.exe
TargetImage   : C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
StartModule   : -
StartFunction : -
```

Another similar event was also observed:

```text
Time          : 4/27/2022 7:00:13 PM
SourceImage   : C:\Windows\System32\rundll32.exe
TargetImage   : C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe\Calculator.exe
StartModule   : -
StartFunction : -
```

### Conclusion

The process responsible for the injection was:

```text
rundll32.exe
```

This conclusion was based on the `SourceImage` field from Sysmon Event ID 8.

```text
SourceImage = process that initiated the action
TargetImage = target/victim process
```

In this case:

```text
rundll32.exe → Calculator.exe
```

---

## Q4 — LSASS Dump Investigation

**Question:**  
By examining the logs located in the `C:\Logs\Dump` directory, determine the process that performed an LSASS dump.

**Answer format:** `_.exe`

### Objective

The objective was to identify which process performed suspicious access against `lsass.exe`, behavior commonly associated with credential dumping.

### Reasoning

`lsass.exe` stands for Local Security Authority Subsystem Service and is responsible for managing Windows credentials.

It is commonly targeted by tools such as:

- Mimikatz
- Process Hacker
- Dumpert
- `comsvcs.dll` dumping

To investigate this activity, I used:

```text
Sysmon Event ID 10 — Process Access
```

This event records when a process attempts to access the memory of another process.

Important fields:

| Field | Description |
|---|---|
| SourceImage | Process that initiated the access |
| TargetImage | Target process |
| GrantedAccess | Access level requested |

### Investigation Strategy

The main focus was:

```text
TargetImage = lsass.exe
```

Then I removed common system noise such as:

- `svchost.exe`
- `MsMpEng.exe`
- `csrss.exe`
- `wininit.exe`

The objective was to find:

- unusual processes
- suspicious locations
- high access rights

### Command Used

```powershell
Get-ChildItem "C:\Logs\Dump" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=10} -ErrorAction SilentlyContinue
} |
ForEach-Object {

    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time          = $_.TimeCreated
        SourceImage   = ($d | Where-Object {$_.Name -eq "SourceImage"}).'#text'
        TargetImage   = ($d | Where-Object {$_.Name -eq "TargetImage"}).'#text'
        GrantedAccess = ($d | Where-Object {$_.Name -eq "GrantedAccess"}).'#text'
    }
} |
Where-Object {
    $_.TargetImage -like "*lsass.exe"
} |
Format-List
```

### Findings

```text
Time          : 4/27/2022 7:08:56 PM
SourceImage   : C:\Users\waldo\Downloads\processhacker-3.0.4801-bin\64bit\ProcessHacker.exe
TargetImage   : C:\Windows\system32\lsass.exe
GrantedAccess : 0x1fffff
```

Multiple similar accesses from the same executable were also observed.

### Behavior Analysis

The main suspicious indicator was:

```text
GrantedAccess : 0x1fffff
```

This value represents an extremely high level of access to the target process, effectively equivalent to:

```text
PROCESS_ALL_ACCESS
```

Credential dumping tools often require this permission level to:

- read LSASS memory
- extract NTLM hashes
- extract plaintext credentials
- enumerate tokens

Additionally, the executable was running from:

```text
C:\Users\waldo\Downloads\
```

This increased suspicion, since legitimate administrative tools normally should not be executed from this location during sensitive operations against LSASS.

### Conclusion

The process responsible for the LSASS dump was:

```text
ProcessHacker.exe
```

---

## Q5 — Post-LSASS Dump Login Investigation

**Question:**  
By examining the logs located in the `C:\Logs\Dump` directory, determine if an ill-intended login took place after the LSASS dump.

**Answer format:** `Yes` or `No`

### Reasoning

After identifying activity compatible with LSASS dumping, the next objective was to determine whether the potentially stolen credentials were used to perform a malicious login.

The logic was:

```text
LSASS dump
→ possible credential theft
→ possible reuse of stolen credentials
```

The LSASS dump occurred at approximately:

```text
7:08 PM
```

Based on this, I analyzed login events after that time.

### Relevant Events

| Event ID | Meaning |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |

The main focus was:

```text
Event ID 4624 — Successful Logon
```

because this event records successful logins.

### Command Used

```powershell
Get-ChildItem "C:\Logs\Dump" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=4624} -ErrorAction SilentlyContinue
} |
Where-Object {
    $_.TimeCreated -gt (Get-Date "04/27/2022 7:08:00 PM")
} |
ForEach-Object {

    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time        = $_.TimeCreated
        User        = ($d | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
        LogonType   = ($d | Where-Object {$_.Name -eq "LogonType"}).'#text'
        Workstation = ($d | Where-Object {$_.Name -eq "WorkstationName"}).'#text'
        SourceIP    = ($d | Where-Object {$_.Name -eq "IpAddress"}).'#text'
    }
} |
Format-Table -AutoSize
```

### Findings

The events observed after the dump showed:

```text
Logon Type = 5
```

### Behavior Analysis

```text
Logon Type 5
```

corresponds to:

```text
Service Logon
```

This type of authentication is normally associated with:

- Windows Services
- Scheduled Tasks
- Service Accounts

No typical indicators of malicious credential reuse were observed.

### Conclusion

Did an ill-intended login take place after the LSASS dump?

```text
No
```

---

## Q6 — Strange Parent-Child Relationship Investigation

**Question:**  
By examining the logs located in the `C:\Logs\StrangePPID` directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship.

**Answer format:** `_.exe`

### Objective

The objective was to identify a process executed through an abnormal parent-child relationship.

This behavior is commonly associated with:

- PPID Spoofing
- Process Masquerading
- Temporary Code Execution

### Investigation Strategy

I focused on:

```text
Sysmon Event ID 1 — Process Create
```

This event contains important information about:

- Executed process
- Parent process
- Command line
- Parent command line

The approach was to search for unusual parent-child relationships.

I initially removed common Windows parent processes to reduce noise, such as:

- `explorer.exe`
- `cmd.exe`
- `powershell.exe`
- `services.exe`
- `svchost.exe`

After that, I searched for small and temporary processes commonly used for quick command execution, such as:

- `cmd.exe`
- `whoami.exe`
- `powershell.exe`

executed by processes that should not normally spawn them.

### Command Used

```powershell
Get-ChildItem "C:\Logs\StrangePPID" -Filter *.evtx |
ForEach-Object {
    Get-WinEvent -FilterHashtable @{Path=$_.FullName; Id=1} -ErrorAction SilentlyContinue
} |
ForEach-Object {

    $xml = [xml]$_.ToXml()
    $d = $xml.Event.EventData.Data

    [PSCustomObject]@{
        Time              = $_.TimeCreated
        Image             = ($d | Where-Object {$_.Name -eq "Image"}).'#text'
        ParentImage       = ($d | Where-Object {$_.Name -eq "ParentImage"}).'#text'
        CommandLine       = ($d | Where-Object {$_.Name -eq "CommandLine"}).'#text'
        ParentCommandLine = ($d | Where-Object {$_.Name -eq "ParentCommandLine"}).'#text'
    }
} |
Where-Object {

    $_.ParentImage -notlike "*explorer.exe" -and
    $_.ParentImage -notlike "*cmd.exe" -and
    $_.ParentImage -notlike "*powershell.exe" -and
    $_.ParentImage -notlike "*services.exe" -and
    $_.ParentImage -notlike "*svchost.exe"

} |
Format-List
```

### Findings

```text
Time              : 4/27/2022 7:18:06 PM
Image             : C:\Windows\System32\cmd.exe
ParentImage       : C:\Windows\System32\werfault.exe
CommandLine       : cmd.exe /c whoami
ParentCommandLine : "C:\Windows\System32\werfault.exe"
```

### Behavior Analysis

The behavior was suspicious because:

```text
werfault.exe
```

is normally associated with:

```text
Windows Error Reporting
```

and does not usually spawn:

```text
cmd.exe
```

as a child process.

Additionally, the command executed was:

```text
cmd.exe /c whoami
```

This is a very common pattern in:

- quick command execution tests
- privilege validation
- temporary code execution
- post-exploitation activity
- PPID spoofing scenarios

### Conclusion

The process used for temporary code execution was:

```text
cmd.exe
```

---

# Final Answers

| Question | Answer |
|---|---|
| Q1 | `Dism.exe` |
| Q2 | `Calculator.exe` |
| Q3 | `rundll32.exe` |
| Q4 | `ProcessHacker.exe` |
| Q5 | `No` |
| Q6 | `cmd.exe` |
