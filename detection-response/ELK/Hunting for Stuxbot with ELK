# HTB Walkthrough — Hunting for Stuxbot

Welcome back, fellow hunters.

This time, the investigation goes beyond simple event log analysis. The newest iteration of Stuxbot demonstrates a much more mature operational flow, combining persistence, staging, and lateral movement techniques that are commonly observed in real-world intrusions.

Unlike basic malware that simply executes and disappears, Stuxbot behaves more like an organized operator:

- It stages additional tooling inside `C:\Users\Public`
- It establishes persistence through Registry Run Keys
- It abuses PowerShell Remoting for lateral movement and domain access

This assessment simulates what an actual Threat Hunter or SOC Analyst would face during an active compromise investigation inside a modern SIEM environment.

---

# Available Telemetry

| Data Source | Purpose |
|---|---|
| Windows Audit Logs | Authentication, process execution, account activity |
| Sysmon Logs | Deep endpoint telemetry (processes, network connections, file creation, registry modifications) |
| PowerShell Logs | Script execution, remoting activity, command visibility |
| Zeek Logs | Network-level visibility including DNS, HTTP, SSL, and connection metadata |

---

# Q1 — Lateral Tool Transfer

## Task

> Create a KQL query to hunt for "Lateral Tool Transfer" to `C:\Users\Public`.
> Enter the content of the `user.name` field in the document that is related to a transferred tool that starts with `"r"` as your answer.

---

# Initial Analysis

Before even touching the SIEM, I stopped to think about the attacker behavior being described.

The phrase **"Lateral Tool Transfer"** immediately suggested that tools or payloads were being copied onto systems remotely.

Since the briefing specifically mentioned abuse of:

```text
C:\Users\Public
```

this became the primary hunting focus.

The key observation here is:

- Attackers commonly use `C:\Users\Public` as a staging directory
- Lateral movement often involves dropping tools remotely
- File creation telemetry is usually the fastest way to detect this activity

That naturally led me toward:

```text
Sysmon Event ID 11
```

---

# Why Event ID 11?

Sysmon Event ID 11 corresponds to:

```text
FileCreate
```

This event records when files are created on disk, making it perfect for identifying:

- dropped payloads
- transferred tooling
- staging activity
- attacker utilities

Since the task explicitly mentioned a transferred tool starting with `"r"`, I narrowed the hunt to files inside:

```text
C:\Users\Public
```

---

# KQL Hunt Query

```kql
event.code:11 AND file.directory:"C:\Users\Public"
```

This immediately revealed several suspicious tools being staged inside the Public directory.

---

# Observed Payloads

```text
C:\Users\Public\SharpHound.exe
C:\Users\Public\DomainPasswordSpray.ps1
C:\Users\Public\payload.exe
C:\Users\Public\Rubeus.exe
C:\Users\Public\mimikatz.exe
```

---

# Building the Attack Timeline

At this stage, the logs started telling a very clear story.

---

## Phase 1 — Initial Reconnaissance

The first suspicious activity originated from the user:

```text
bob
```

The user executed:

```text
DomainPasswordSpray.ps1
SharpHound.exe
```

This strongly suggested the attacker had already gained access to a workstation and was performing:

- domain password spraying
- Active Directory enumeration
- privilege discovery

The presence of `SharpHound.exe` was especially important because it is heavily associated with:

```text
BloodHound
```

which attackers frequently use for mapping privilege escalation paths inside Active Directory environments.

---

## Phase 2 — Escalation and Lateral Tooling

Shortly after the reconnaissance phase, the logs showed activity tied to:

```text
svc-sql1
```

This account appeared connected to the transfer and execution of more advanced offensive tooling, including:

```text
Rubeus.exe
mimikatz.exe
payload.exe
```

This was a major escalation point in the investigation.

The attacker had progressed from reconnaissance into:

- credential theft
- Kerberos abuse
- post-exploitation
- persistence preparation
- lateral movement operations

---

# Why Rubeus Matters

The task specifically asked for the user tied to the transferred tool starting with `"r"`.

That tool was clearly:

```text
Rubeus.exe
```

Rubeus is an extremely common post-exploitation utility used for:

- Kerberoasting
- ticket extraction
- pass-the-ticket attacks
- Kerberos abuse
- lateral movement

The associated `user.name` field for the Rubeus transfer event was:

```text
svc-sql1
```

---

# Final Answer

```text
svc-sql1
```

---

# Q2 — Registry Run Keys Persistence

## Task

> Create a KQL query to hunt for "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder".
> Enter the content of the `registry.value` field in the document that is related to the first registry-based persistence action as your answer.

---

# Initial Hunting Strategy

The threat briefing already revealed that the newest Stuxbot variants were using:

```text
Registry Run Keys
```

for persistence.

Because of that, my first instinct was to investigate:

```text
Sysmon Event ID 13
```

which corresponds to:

```text
Registry Value Set
```

This event is extremely useful for identifying:

- persistence mechanisms
- autorun modifications
- malware startup entries
- registry-based payload execution

---

# Initial KQL Query

```kql
event.code:13 AND (user.name:"bob" OR user.name:"svc-sql1")
```

The results initially contained a lot of noise, especially legitimate Microsoft and OneDrive autorun activity.

To reduce the noise, I excluded OneDrive-related events.

---

# Noise Reduction Query

```kql
event.code:13 AND (user.name:"bob" OR user.name:"svc-sql1") AND NOT process.name:OneDrive.exe
```

This made the suspicious entries much easier to identify.

---

# Investigation Process

While reviewing the events, I initially focused on suspicious-looking entries such as:

```text
default.exe
```

However, after checking the timestamps and registry values more carefully, I realized this was not the first registry persistence action mentioned in the task.

Continuing the investigation revealed a much more suspicious event tied to:

```text
powershell.exe
```

This stood out immediately because:

- PowerShell is heavily abused for persistence
- the registry value looked randomized/encoded
- the timing aligned with early attacker activity

---

# Suspicious Registry Value

The associated `registry.value` field contained:

```text
LgvHsviAUVTsIN
```

---

# Why This Matters

Registry Run Keys are one of the oldest and most reliable persistence mechanisms used by malware.

Attackers commonly abuse registry paths such as:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Anything stored there may execute automatically during:

- user logon
- system startup

This allows malware to survive:

- reboots
- user logouts
- temporary payload deletion

The fact that PowerShell was responsible for modifying the registry strongly increased the suspicion level because PowerShell is frequently abused for:

- stealth persistence
- fileless malware
- encoded payload execution
- post-exploitation automation

---

# Final Answer

```text
LgvHsviAUVTsIN
```

---

# Q3 — PowerShell Remoting for Lateral Movement

## Task

> Create a KQL query to hunt for "PowerShell Remoting for Lateral Movement".
> Enter the content of the `winlog.user.name` field in the document that is related to PowerShell remoting-based lateral movement towards `DC1`.

---

# Initial Hunting Strategy

I started by investigating PowerShell Script Block Logging events.

---

# Initial KQL Query

```kql
event.code:4104
```

PowerShell Event ID `4104` corresponds to:

```text
PowerShell Script Block Logging
```

This telemetry is extremely valuable because it captures:

- PowerShell commands
- script content
- attacker tooling
- offensive automation
- obfuscated payloads

This often gives defenders visibility into attacker behavior even when malware attempts to hide itself.

---

# Refining the Hunt

After that, I refined the search to identify references to the Domain Controller:

```kql
event.code:4104 AND powershell.file.script_block_text:*DC1*
```

Initially, many of the results were heavily obfuscated or encoded.

This is extremely common in real intrusions because attackers frequently use:

- Base64 encoding
- obfuscation frameworks
- variable randomization
- compressed payloads

to evade detections and make analysis harder.

However, one event stood out immediately:

```powershell
Enter-PSSession dc1
```

This clearly indicated the use of:

```text
PowerShell Remoting
```

---

# Why Enter-PSSession Is Important

`Enter-PSSession` creates an interactive remote PowerShell session over:

```text
WinRM (Windows Remote Management)
```

This allows an attacker to:

- remotely execute commands
- administer systems
- move laterally across the environment
- access servers and Domain Controllers

In this case:

- source system → compromised host
- target → `DC1`

This was a major escalation indicator.

---

# Pivoting on the User

From there, I pivoted into the associated user activity.

---

# User Pivot Query

```kql
winlog.user.name:"svc-sql1" AND event.code:4104
```

This revealed:

- PowerShell Remoting activity toward `DC1`
- execution of `Rubeus.exe`
- Kerberos-related offensive commands
- DCSync activity

At this point, the attacker behavior clearly shifted from:

```text
Reconnaissance → Credential Abuse → Domain-Level Compromise
```

---

# Suspicious Commands Identified

## Rubeus Execution

```powershell
.\Rubeus.exe asktgt /user:Administrator
```

## DCSync Activity

```powershell
Invoke-DCSync -Users Administrator
```

---

# Technical Breakdown

---

## Enter-PSSession

```powershell
Enter-PSSession dc1
```

Creates a remote PowerShell session to another system.

In this case:

- source → `svc-sql1`
- destination → `DC1`

This characterizes:

```text
Lateral Movement via WinRM / PowerShell Remoting
```

### MITRE ATT&CK

```text
T1021.006 — PowerShell Remoting
```

---

## Rubeus

`Rubeus` is an offensive tool commonly used for:

- Kerberos ticket attacks
- Pass-the-ticket
- TGT/TGS abuse
- credential access

The command observed:

```powershell
Rubeus.exe asktgt
```

indicates an attempt to obtain a:

```text
Ticket Granting Ticket (TGT)
```

This is extremely dangerous because TGTs can later be abused for:

- privilege escalation
- lateral movement
- impersonation
- persistence

### MITRE ATT&CK

```text
T1558 — Steal or Forge Kerberos Tickets
```

---

## DCSync

```powershell
Invoke-DCSync -Users Administrator
```

This is one of the most critical Active Directory attack techniques.

The attacker attempts to request NTLM password hashes from the Domain Controller by simulating legitimate Active Directory replication behavior.

In practice, the attacker is essentially asking the DC:

```text
"Send me the password hashes like I am another Domain Controller."
```

If successful, this allows attackers to steal:

- NTLM hashes
- Kerberos secrets
- privileged account credentials

without needing to dump LSASS directly.

---

# Attacker Objectives

The observed activity strongly suggested attempts to:

- steal credentials
- compromise Active Directory
- escalate privileges
- gain Domain Admin-level access
- establish long-term persistence

---

# MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| PowerShell Remoting | T1021.006 |
| Kerberos Ticket Abuse | T1558 |
| DCSync | T1003.006 |
| Registry Run Keys / Startup Folder | T1547.001 |
| File and Tool Transfer | T1105 |

---

# Reconstructed Attack Chain

Based on the telemetry, the likely attacker progression was:

## Stage 1 — Initial Compromise

The attacker gained access to a workstation associated with:

```text
bob
```

---

## Stage 2 — Internal Reconnaissance

Execution of:

```text
SharpHound.exe
DomainPasswordSpray.ps1
```

suggested:

- AD enumeration
- password spraying
- privilege mapping

---

## Stage 3 — Tool Staging

The attacker transferred offensive tooling into:

```text
C:\Users\Public
```

including:

```text
Rubeus.exe
mimikatz.exe
payload.exe
```

---

## Stage 4 — Persistence

Registry Run Keys were modified using:

```text
powershell.exe
```

allowing the malware to survive reboots and maintain access.

---

## Stage 5 — Lateral Movement

The attacker used:

```powershell
Enter-PSSession dc1
```

to remotely access the Domain Controller through WinRM / PowerShell Remoting.

---

## Stage 6 — Credential Abuse

Execution of:

```powershell
Rubeus.exe asktgt
```

indicated Kerberos abuse activity.

---

## Stage 7 — Attempted Domain Compromise

The attacker executed:

```powershell
Invoke-DCSync -Users Administrator
```

which strongly indicated attempted Domain compromise.

---

# Final Answer

```text
svc-sql1
```

---

# Key Hunting Lessons Learned

## 1. Simple Telemetry Can Reveal Entire Intrusions

A few carefully correlated events were enough to reconstruct:

- reconnaissance
- persistence
- lateral movement
- credential theft
- domain compromise attempts

---

## 2. PowerShell Logging Is Extremely Powerful

Event ID `4104` alone exposed:

- remoting activity
- offensive tooling
- Kerberos abuse
- DCSync attempts

Without Script Block Logging, much of this attack would have been significantly harder to investigate.

---

## 3. Sysmon Is Critical for Threat Hunting

Sysmon provided visibility into:

- file creation
- registry modifications
- offensive tooling
- persistence mechanisms

This demonstrates why Sysmon is considered one of the most valuable Windows telemetry sources for defenders.

---

## 4. Attackers Frequently Reuse Common Tools

The intrusion leveraged well-known offensive tools such as:

- Rubeus
- SharpHound
- mimikatz

This reinforces the importance of:

- behavioral detections
- tool-transfer hunting
- PowerShell monitoring
- credential abuse monitoring

---

# Skills Practiced

- Threat Hunting Methodology
- KQL Hunting
- Elastic Discover
- Sysmon Analysis
- Windows Event Analysis
- PowerShell Script Block Logging
- Registry Persistence Detection
- Lateral Movement Detection
- Kerberos Abuse Detection
- Active Directory Threat Hunting
- MITRE ATT&CK Mapping
- SIEM Investigation Workflow
- Timeline Reconstruction
- Event Correlation & Pivoting

---

# Final Thoughts

This lab was an excellent simulation of a real-world post-exploitation investigation.

Instead of isolated alerts, the telemetry revealed a complete attacker progression:

```text
Reconnaissance
→ Tool Staging
→ Persistence
→ Lateral Movement
→ Kerberos Abuse
→ Attempted Domain Compromise
```

The most important lesson from this hunt was understanding how defenders can reconstruct attacker operations by correlating:

- Sysmon telemetry
- PowerShell logs
- registry activity
- file creation events
- authentication artifacts

Even highly capable attackers leave behavioral traces behind.

The job of a Threat Hunter is learning how to connect them together.

---
