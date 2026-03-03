# IIS Components (Malicious IIS Modules and ISAPI Backdoors)

## Metadata

| Key          | Value                                      |
|--------------|--------------------------------------------|
| ID           | TRR0029                                    |
| External IDs | [T1505.004]                                |
| Tactics      | Persistence                                |
| Platforms    | Windows                                    |
| Contributors | John                                       |

## Scope Statement

This TRR covers persistent and in-memory IIS module and ISAPI backdoors on Windows — specifically native module registration via `applicationHost.config`, managed module registration via `web.config`, and reflective in-memory assembly loading into `w3wp.exe` — where the malicious component integrates into the IIS HTTP request pipeline to intercept server-wide traffic rather than responding to requests at a specific URL.

| Excluded Item | Rationale |
|---|---|
| File-based web shells (.aspx, .asp, .ashx, .php) in web root (T1505.003) | Different essential operations — persistence is a script file at a web-accessible URL executed via handler mapping, not a DLL registered in IIS configuration. |
| SQL Stored Procedures (T1505.001) | Different essential operations — database engine execution, not HTTP pipeline. Warrants separate TRR. |
| Transport Agent (T1505.002) | Different essential operations — Exchange mail transport pipeline, not IIS HTTP pipeline. Warrants separate TRR. |
| Terminal Services DLL (T1505.005) | Different essential operations — RDP service context, not IIS. Warrants separate TRR. |
| vSphere Installation Bundles (T1505.006) | Different essential operations — VMware ESXi boot mechanism. Warrants separate TRR. |
| PHP web shells on Linux (Apache/Nginx) | Different essential operations — different process lineage, different telemetry (auditd), different platform. Warrants separate TRR. |
| JSP web shells on Tomcat | Different essential operations — JVM process context, Jasper compilation model. Warrants separate TRR. |
| Web shells on network appliances | Different essential operations — hardened filesystem, appliance-specific persistence. Warrants separate TRR. |
| Delivery mechanism (T1190, T1078) | Tangential — attacker-controlled prerequisite. How the component reaches the server is variable; IIS registration is the essential operation. |
| Post-exploitation commands executed through the module | Tangential — separate techniques using the module as a channel. |
| Specific DLL file names, module names, or registration tool | Tangential — attacker-controlled. All registration methods converge on the same configuration file write. |
| C2 trigger mechanism (cookie, header, URL parameter, POST body) | Tangential — attacker-controlled. The delivery field varies per malware family. |
| C2 encryption or encoding | Tangential — attacker-controlled. Does not change the essential pipeline interception operation. |
| Anti-log tampering via `OnLogRequest` hook | Tangential — optional evasion layer present in only some families. Not essential to the technique. |
| IIS HTTP handlers (`IHttpHandler` in `<handlers>`) | Boundary case — handlers respond only to URL-matched requests, not server-wide interception. Closer to T1505.003 execution model despite DLL implementation. Documented in Technical Background. |
| ASP.NET Core on IIS (Kestrel reverse proxy model) | Different architecture — IIS acts as proxy, not execution engine. Out of platform scope. |

## Technique Overview

An attacker with access to an IIS server can register a malicious component — either a native C++ DLL or a .NET assembly — directly into the IIS HTTP request pipeline, causing that component to execute on every request that the server processes. Because the component runs inside the IIS worker process (`w3wp.exe`) rather than as a separate process, it can intercept, inspect, and manipulate traffic without spawning child processes or producing the process-tree artifacts associated with traditional web shells. Attackers use this technique to establish persistent backdoor access that survives server reboots and is difficult to distinguish from legitimate IIS extensions.

## Technical Background

### IIS Request Pipeline Architecture

IIS 7.0 introduced a unified integrated pipeline that replaced the older ISAPI-only architecture. All HTTP requests traverse this pipeline inside `w3wp.exe`, the IIS worker process. When a request arrives, the kernel-mode driver `HTTP.sys` receives the TCP connection and parses the HTTP request. The Windows Process Activation Service (WAS) then routes the request to the appropriate application pool's `w3wp.exe` instance. Inside the worker process, the request passes sequentially through an ordered list of registered modules at each of the following pipeline stages: `RQ_BEGIN_REQUEST`, `RQ_AUTHENTICATE_REQUEST`, `RQ_AUTHORIZE_REQUEST`, `RQ_RESOLVE_REQUEST_CACHE`, `RQ_MAP_REQUEST_HANDLER`, `RQ_ACQUIRE_REQUEST_STATE`, `RQ_PRE_EXECUTE_REQUEST_HANDLER`, `RQ_EXECUTE_REQUEST_HANDLER`, `RQ_RELEASE_REQUEST_STATE`, `RQ_UPDATE_REQUEST_CACHE`, `RQ_LOG_REQUEST`, and `RQ_END_REQUEST`. At each stage, every registered module that subscribed to that event is invoked in priority order.

A module registered for `RQ_BEGIN_REQUEST` executes on every request before any handler mapping, authentication, or logging. A module registered for `RQ_LOG_REQUEST` can modify or suppress log entries before IIS commits them to the W3C access log — an inherent capability of the pipeline that file-based web shells do not possess.

### Module Types and Registration

IIS supports two categories of HTTP modules.

**Native modules** are compiled C++ DLLs that export a `RegisterModule` function. Registration requires two configuration entries in `applicationHost.config`, which is the global IIS configuration file: a `<globalModules>` entry that installs the DLL server-wide, and a `<modules>` entry that enables it for one or more applications. Both entries require administrator access. When the worker process starts, IIS calls `LoadLibrary` on each registered native DLL and invokes its exported `RegisterModule` function to obtain its event subscriptions. ISAPI filters and ISAPI extensions — the legacy IIS 4–6 API — remain supported in IIS 7+ via `IsapiModule` and `IsapiFilterModule`. Their registration targets a `<isapiFilters>` section rather than `<globalModules>`, but the essential operations — DLL write to disk, configuration file modification, DLL load into the worker process, and request interception — are identical to those of a native module.

**Managed modules** are .NET assemblies that implement the `IHttpModule` interface. Registration requires only a `<modules>` entry in the application's `web.config` file. When ASP.NET is installed, the `<modules>` configuration section is unlocked by default (`overrideMode="Allow"`), meaning application-level operators can add managed modules without administrator rights. The Common Language Runtime (CLR) hosted within `w3wp.exe` loads the assembly on the first HTTP request and calls `IHttpModule.Init()` to register the module's event handlers.

All persistent registration paths — for both native and managed modules — require a write to either `applicationHost.config` or `web.config`. No registry-only or in-memory-only persistent registration path has been identified for IIS 7+.

### Process Context

All IIS module types execute within `w3wp.exe` under the application pool identity, which defaults to `IIS APPPOOL\{PoolName}`, a low-privilege virtual account. This is the same process that executes file-based web shell requests. A critical operational distinction exists, however: a malicious IIS module can execute commands entirely in-process using .NET or Win32 APIs, without spawning a child process. When no `cmd.exe` or `powershell.exe` child appears under `w3wp.exe`, process-tree-based telemetry for the worker process does not fire. Microsoft's DART team has explicitly noted that monitoring for `w3wp.exe` spawning `cmd.exe` is not a reliable basis for analysis of IIS module-based backdoors.

### Log Suppression Capability

Modules registered for the `RQ_LOG_REQUEST` pipeline event can read and modify the IIS log record before IIS writes it to the W3C access log. This allows a malicious module to rewrite the HTTP method, alter the URI, or strip header fields from its own traffic — all before the log entry is committed. This capability is inherent to the pipeline event model and available to any registered module.

### IIS HTTP Handlers — Boundary Case

IIS also supports HTTP handlers (`IHttpHandler`), which respond only to URL-matched requests rather than intercepting all server traffic. A handler registered in the `<handlers>` section executes only when a request matches the configured URL pattern, making its execution model equivalent to that of a file-based web shell — URL-specific, not server-wide. This boundary case falls closer to T1505.003 than T1505.004 and is excluded from this TRR's scope and DDM.

### Telemetry Enablement

| Telemetry Source | Default State | Enablement |
|---|---|---|
| Sysmon 11 (FileCreate) | Requires Sysmon installation | Sysmon configuration with file-create rules |
| Sysmon 7 (ImageLoad) | Requires Sysmon installation | Sysmon configuration with image-load rules targeting `w3wp.exe` |
| Microsoft-IIS-Configuration/Operational EID 29 | Disabled by default | `wevtutil sl /e:true Microsoft-IIS-Configuration/Operational` |
| Windows Security EID 4663 | Requires SACL on target file | SACL on `applicationHost.config` plus Object Access audit policy |
| Windows Security EID 4688 (ProcessCreate) | Requires audit policy | Process Creation audit policy (Advanced Audit Configuration) |
| ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1) | Requires ETW consumer | Not collected by default; requires active ETW session subscribing to the runtime provider with `LoaderKeyword (0x8)` |
| IIS W3C Access Logs | Enabled by default | Default fields log URI, method, and status; Cookie values and POST body are not logged by default |

Two important constraints apply to the IIS configuration change event. Microsoft-IIS-Configuration/Operational EID 29 fires on module additions and removals that flow through the IIS configuration API layer — commands executed via administrative interfaces such as `appcmd` or the IIS Manager. Direct text edits to `applicationHost.config` or `web.config` bypass the API entirely; EID 29 does not fire for direct file edits. Sysmon 11 (FileCreate) fires on file overwrite regardless of how the file was modified, making it the only telemetry source that covers both API-mediated and direct-edit registration paths.

The reflective assembly load path presents a distinct constraint. Sysmon 7 (ImageLoad) hooks via the kernel callback `PsSetLoadImageNotifyRoutine`, which is triggered by `NtMapViewOfSection`. When the CLR loads a disk-backed .NET assembly, it maps the PE file through this kernel path, and Sysmon 7 fires. When an assembly is loaded from a byte array via `Assembly.Load(byte[])`, the CLR allocates from heap memory without calling `NtMapViewOfSection`. Sysmon 7 does not fire for this path. The only telemetry source for reflective in-memory loads is ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1), which requires an active ETW consumer session. ETW events are userland-sourced and can be suppressed by patching `ntdll!EtwEventWrite` (T1562.006).

## Procedures

| ID | Name | Tactic |
|----|------|--------|
| [TRR0029.WIN.A] | Persistent Native Module | Persistence |
| [TRR0029.WIN.B] | Persistent Managed Module | Persistence |
| [TRR0029.WIN.C] | Reflective In-Memory Module | Persistence |

### Procedure A: Persistent Native Module

The attacker writes a compiled native DLL to the IIS server filesystem. This write produces Sysmon 11 (FileCreate) telemetry at the destination path. The DLL implements the IIS native module interface and exports a `RegisterModule` entry point that will be called by IIS at worker process start.

After writing the DLL, the attacker modifies `applicationHost.config` to add the module under both `<globalModules>` and `<modules>`. This configuration file write produces Sysmon 11 (FileCreate) telemetry on the `applicationHost.config` path. If the modification is performed through the IIS configuration API (via an administrative interface), Microsoft-IIS-Configuration/Operational EID 29 also fires. If the attacker edits the file directly — opening and saving it outside the API — EID 29 does not fire; Sysmon 11 remains the sole telemetry source. Administrator access is required for `applicationHost.config` modification. The ISAPI filter and ISAPI extension variants of this path share the same essential operations: DLL write, configuration file modification, DLL load into `w3wp.exe`, and request interception. Only the configuration section name differs (`<isapiFilters>` instead of `<globalModules>`).

When the IIS worker process next starts or recycles, IIS calls `LoadLibrary` on the registered DLL path, loading the native image into `w3wp.exe`. This load produces Sysmon 7 (ImageLoad) telemetry with `w3wp.exe` as the loading process. IIS then calls the exported `RegisterModule` function, which registers the module's `CHttpModule` or `CGlobalModule` event handlers for the desired pipeline stages. Pipeline hook registration has no direct telemetry — its occurrence is inferred from the preceding load event.

On every subsequent HTTP request, `w3wp.exe` invokes the registered handlers at their subscribed pipeline stages. This interception is reflected in IIS W3C access logs, though a module subscribed to `RQ_LOG_REQUEST` can modify those entries before they are written. The backdoor survives worker process recycles and server reboots because its registration is stored in `applicationHost.config`.

#### Detection Data Model

![DDM - Procedure A: Persistent Native Module](ddms/trr0029_win_a.png)

The DDM shows two prerequisite nodes — Write DLL to Disk and Modify applicationHost.config — feeding into the Load Native DLL operation, which in turn flows to Intercept HTTP Request. Both prerequisite operations produce Sysmon 11 (FileCreate) telemetry independently. Load Native DLL produces Sysmon 7 (ImageLoad) telemetry. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

---

### Procedure B: Persistent Managed Module

The attacker writes a .NET assembly to the application's `/bin` directory (or to the Global Assembly Cache). This write produces Sysmon 11 (FileCreate) telemetry at the destination path. The assembly implements the `IHttpModule` interface and contains an `Init()` method that registers the module's event handlers.

After writing the assembly, the attacker modifies `web.config` to add a `<modules>` entry referencing the assembly. This configuration file write produces Sysmon 11 (FileCreate) telemetry on the `web.config` path. If the modification is performed through the IIS configuration API, Microsoft-IIS-Configuration/Operational EID 29 may also fire. Direct file edits bypass the API and do not produce EID 29. Because the `<modules>` section is unlocked by default when ASP.NET is installed, this modification does not require administrator rights in a default IIS configuration — distinguishing this procedure from Procedure A.

The assembly is not loaded at worker process start. Instead, on the first HTTP request to the application after the configuration change, the CLR hosted within `w3wp.exe` locates the assembly via the configured path, maps it from disk through `NtMapViewOfSection`, and loads it into the worker process. This load produces Sysmon 7 (ImageLoad) telemetry. The CLR then calls `IHttpModule.Init()`, which registers the module's event handlers for the desired pipeline stages. As with the native module path, hook registration produces no direct telemetry.

On every subsequent HTTP request, `w3wp.exe` invokes the registered handlers at their subscribed stages. The backdoor survives worker process recycles and server reboots because its registration is stored in `web.config`.

#### Detection Data Model

![DDM - Procedure B: Persistent Managed Module](ddms/trr0029_win_b.png)

The DDM shows two prerequisite nodes — Write Assembly to Bin and Modify web.config — feeding into the Load Managed Assembly operation, which in turn flows to Intercept HTTP Request. Both prerequisite operations produce Sysmon 11 (FileCreate) telemetry independently. Load Managed Assembly produces Sysmon 7 (ImageLoad) telemetry. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

---

### Procedure C: Reflective In-Memory Module

This procedure does not write a file to disk and does not modify any IIS configuration file. Its pipeline is entirely distinct from Procedures A and B.

The attacker has pre-existing code execution within `w3wp.exe`. The mechanism by which this foothold is obtained is a separate technique (delivery is excluded from this TRR's scope) but the initial exploitation request is captured in IIS W3C access logs and may produce EDR behavioral telemetry depending on the instrumentation model deployed.

From within `w3wp.exe`, the attacker calls `Assembly.Load(byte[])`, passing a .NET assembly as a raw byte array. The CLR allocates memory from the heap and loads the assembly without writing any file to disk and without calling `NtMapViewOfSection`. Because `NtMapViewOfSection` is not invoked, Sysmon 7 (ImageLoad) does not fire. The only telemetry source for this load is ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1), produced by the CLR runtime provider. This event requires an active ETW consumer session subscribed to the runtime provider with `LoaderKeyword (0x8)` — it is not captured by default. Because ETW events are generated in user space, an attacker with code execution in `w3wp.exe` can suppress them by patching `ntdll!EtwEventWrite` before loading the assembly.

Once loaded, the assembly registers its event handlers in the live IIS pipeline in memory. The module then intercepts subsequent HTTP requests at its subscribed pipeline stages, producing IIS W3C access log entries that the module can also modify or suppress via `RQ_LOG_REQUEST`. Because no configuration file was modified, the module is not persistent — it is lost when the `w3wp.exe` process terminates or recycles.

#### Detection Data Model

![DDM - Procedure C: Reflective In-Memory Module](ddms/trr0029_win_c.png)

The DDM shows Gain Code Execution flowing into Load Assembly Reflectively, which in turn flows to Intercept HTTP Request. Gain Code Execution produces IIS W3C Access Logs and EDR Behavioral telemetry. Load Assembly Reflectively produces ETW DotNETRuntime EID 154 (AssemblyLoad_V1) telemetry, conditioned on an active ETW consumer. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

## Available Emulation Tests

| ID | Link |
|----|------|
| TRR0029.WIN.A | [T1505.004 Atomic Red Team Tests] |
| TRR0029.WIN.B | — |
| TRR0029.WIN.C | — |

Two Atomic Red Team tests exist for Procedure A, covering the configuration registration operation using a benign existing DLL via two different administrative interfaces. No emulation tests exist for Procedure B (managed module registration via `web.config`) or Procedure C (reflective in-memory assembly loading).

## References

- [T1505.004 — IIS Components — MITRE ATT&CK]
- [T1505.003 — Web Shell — MITRE ATT&CK]
- [T1505.004 Atomic Red Team Tests]
- [IIS Modules Overview — Microsoft Learn]
- [Developing a Module Using .NET — Microsoft Learn]
- [Develop a Native C/C++ Module for IIS 7.0 — Microsoft Learn]
- [Global Modules Configuration — Microsoft Learn]
- [Modules Configuration — Microsoft Learn]
- [ISAPI Filters Configuration — Microsoft Learn]
- [Introduction to applicationHost.config — Microsoft Learn]
- [How to Use Locking in IIS Configuration — Microsoft Learn]
- [CHttpModule Class — Microsoft Learn]
- [CGlobalModule Class — Microsoft Learn]
- [Loader ETW Events — Microsoft Learn]
- [CLR ETW Providers — Microsoft Learn]
- [IIS Modules: The Evolution of Web Shells — Microsoft Security Blog]
- [Malicious IIS Extensions — Microsoft Security Blog]
- [OilRig RGDoor IIS Backdoor — Unit 42]
- [The SessionManager IIS Backdoor — Kaspersky Securelist]
- [Threat Group-3390 Targets Organizations for Cyberespionage (OwaAuth) — Secureworks]
- [Falcon OverWatch Detects Novel IceApple Framework — CrowdStrike]
- [IIS-Raid: Backdooring IIS Using Native Modules — MDSec]
- [Praying Mantis TG1021 — Sygnia]
- [Distribution of IIS Malware: Larva-25003 — AhnLab ASEC]
- [Anatomy of Native IIS Malware — ESET WeLiveSecurity]
- [IISpy Complex Server-Side Backdoor — ESET WeLiveSecurity]
- [Anatomy of Native IIS Malware: Black Hat USA 2021 White Paper — ESET]
- [Sigma: win_iis_module_added — SigmaHQ]
- [IIS Components Analytics Story — Splunk]
- [IIS 7.5 Configuration Auditing — IIS Support Blog]
- [Bypassing Image Load Kernel Callbacks — MDSec]
- [Hiding Your .NET ETW — XPN InfoSec]

[T1505.004]: https://attack.mitre.org/techniques/T1505/004/
[T1505.004 — IIS Components — MITRE ATT&CK]: https://attack.mitre.org/techniques/T1505/004/
[T1505.003 — Web Shell — MITRE ATT&CK]: https://attack.mitre.org/techniques/T1505/003/
[T1505.004 Atomic Red Team Tests]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.004/T1505.004.md
[IIS Modules Overview — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/iis-modules-overview
[Developing a Module Using .NET — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/develop/runtime-extensibility/developing-a-module-using-net
[Develop a Native C/C++ Module for IIS 7.0 — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/develop/runtime-extensibility/develop-a-native-cc-module-for-iis
[Global Modules Configuration — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/globalmodules/
[Modules Configuration — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/modules/
[ISAPI Filters Configuration — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/isapifilters/
[Introduction to applicationHost.config — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/get-started/planning-your-iis-architecture/introduction-to-applicationhostconfig
[How to Use Locking in IIS Configuration — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/get-started/planning-for-security/how-to-use-locking-in-iis-configuration
[CHttpModule Class — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/web-development-reference/native-code-api-reference/chttpmodule-class
[CGlobalModule Class — Microsoft Learn]: https://learn.microsoft.com/en-us/iis/web-development-reference/native-code-api-reference/cglobalmodule-class
[Loader ETW Events — Microsoft Learn]: https://learn.microsoft.com/en-us/dotnet/framework/performance/loader-etw-events
[CLR ETW Providers — Microsoft Learn]: https://learn.microsoft.com/en-us/dotnet/framework/performance/clr-etw-providers
[IIS Modules: The Evolution of Web Shells — Microsoft Security Blog]: https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/
[Malicious IIS Extensions — Microsoft Security Blog]: https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
[OilRig RGDoor IIS Backdoor — Unit 42]: https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
[The SessionManager IIS Backdoor — Kaspersky Securelist]: https://securelist.com/the-sessionmanager-iis-backdoor/106868/
[Threat Group-3390 Targets Organizations for Cyberespionage (OwaAuth) — Secureworks]: https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage
[Falcon OverWatch Detects Novel IceApple Framework — CrowdStrike]: https://www.crowdstrike.com/en-us/blog/falcon-overwatch-detects-iceapple-framework/
[IIS-Raid: Backdooring IIS Using Native Modules — MDSec]: https://www.mdsec.co.uk/2020/02/iis-raid-backdooring-iis-using-native-modules/
[Praying Mantis TG1021 — Sygnia]: https://www.sygnia.co/praying-mantis-detecting-and-hunting
[Distribution of IIS Malware: Larva-25003 — AhnLab ASEC]: https://asec.ahnlab.com/en/87804/
[Anatomy of Native IIS Malware — ESET WeLiveSecurity]: https://www.welivesecurity.com/2021/08/06/anatomy-native-iis-malware/
[IISpy Complex Server-Side Backdoor — ESET WeLiveSecurity]: https://www.welivesecurity.com/2021/08/09/iispy-complex-server-side-backdoor-antiforensic-features/
[Anatomy of Native IIS Malware: Black Hat USA 2021 White Paper — ESET]: https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Anatomy-Of-Native-Iis-Malware-wp.pdf
[Sigma: win_iis_module_added — SigmaHQ]: https://detection.fyi/sigmahq/sigma/windows/builtin/iis-configuration/win_iis_module_added/
[IIS Components Analytics Story — Splunk]: https://research.splunk.com/stories/iis_components/
[IIS 7.5 Configuration Auditing — IIS Support Blog]: https://blogs.iis.net/webtopics/iis-7-5-how-to-enable-iis-configuration-auditing/
[Bypassing Image Load Kernel Callbacks — MDSec]: https://www.mdsec.co.uk/2021/06/bypassing-image-load-kernel-callbacks/
[Hiding Your .NET ETW — XPN InfoSec]: https://blog.xpnsec.com/hiding-your-dotnet-etw/
[TRR0029.WIN.A]: #procedure-a-persistent-native-module
[TRR0029.WIN.B]: #procedure-b-persistent-managed-module
[TRR0029.WIN.C]: #procedure-c-reflective-in-memory-module
