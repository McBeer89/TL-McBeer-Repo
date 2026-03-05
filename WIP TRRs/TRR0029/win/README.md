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

This TRR covers persistent and in-memory IIS module and ISAPI backdoors on
Windows — specifically native module registration via `applicationHost.config`,
managed module or compiled handler registration via `web.config`, and reflective
in-memory assembly loading into `w3wp.exe`.

Out of scope:

- File-based web shells in web root (different essential operations; T1505.003)
- Delivery mechanism and post-exploitation commands (tangential)
- Implementation-specific details such as DLL names, C2 triggers, encoding, and evasion hooks (tangential)
- ASP.NET Core on IIS (different architecture; IIS proxies to Kestrel)

Compiled `IHttpHandler` assemblies registered in `web.config`'s `<handlers>`
section share the same essential operations and telemetry as managed modules
and are covered under Procedure B. Script-based handler remapping via
`PageHandlerFactory` involves different essential operations and falls under
T1505.003.

This technique maps to MITRE ATT&CK [T1505.004].

## Technique Overview

An attacker with access to an IIS server can register a malicious component — either a native C++ DLL or a .NET assembly — directly into the IIS HTTP request pipeline, causing that component to execute when the server processes matching HTTP requests. Because the component runs inside the IIS worker process (`w3wp.exe`) rather than as a separate process, it can intercept, inspect, and manipulate traffic without spawning child processes or producing the process-tree artifacts associated with traditional web shells. A module registered for early pipeline stages such as `RQ_BEGIN_REQUEST` executes on every request the server handles; a compiled handler registered for a specific URL pattern executes only on matching requests. Persistent variants register through IIS configuration files and survive reboots; in-memory variants load reflectively into the worker process without touching disk or configuration, but are lost when the process terminates.

## Technical Background

### IIS Request Pipeline Architecture

IIS 7.0 introduced a unified integrated pipeline that replaced the older ISAPI-only architecture. All HTTP requests traverse this pipeline inside `w3wp.exe`, the IIS worker process. When a request arrives, the kernel-mode driver `HTTP.sys` receives the TCP connection and parses the HTTP request. HTTP.sys then routes the request to the appropriate application pool's `w3wp.exe` instance based on the site's configured bindings. Inside the worker process, the request passes sequentially through an ordered list of registered modules at each of the following pipeline stages: `RQ_BEGIN_REQUEST`, `RQ_AUTHENTICATE_REQUEST`, `RQ_AUTHORIZE_REQUEST`, `RQ_RESOLVE_REQUEST_CACHE`, `RQ_MAP_REQUEST_HANDLER`, `RQ_ACQUIRE_REQUEST_STATE`, `RQ_PRE_EXECUTE_REQUEST_HANDLER`, `RQ_EXECUTE_REQUEST_HANDLER`, `RQ_RELEASE_REQUEST_STATE`, `RQ_UPDATE_REQUEST_CACHE`, `RQ_LOG_REQUEST`, and `RQ_END_REQUEST`. At each stage, every registered module that subscribed to that event is invoked in priority order.

A module registered for `RQ_BEGIN_REQUEST` executes on every request before any handler mapping, authentication, or logging. A module registered for `RQ_LOG_REQUEST` can modify or suppress log entries before IIS commits them to the W3C access log — an inherent capability of the pipeline that file-based web shells do not possess.

### Module Types and Registration

IIS supports two categories of HTTP modules.

**Native modules** are compiled C++ DLLs that export a `RegisterModule` function. Registration requires two configuration entries in `applicationHost.config`, which is the global IIS configuration file: a `<globalModules>` entry that installs the DLL server-wide, and a `<modules>` entry that enables it for one or more applications. Both entries require administrator access. When the worker process starts, IIS calls `LoadLibrary` on each registered native DLL and invokes its exported `RegisterModule` function to obtain its event subscriptions. ISAPI filters and ISAPI extensions — the legacy IIS 4–6 API — remain supported in IIS 7+ via `IsapiModule` and `IsapiFilterModule`. Their registration targets a `<isapiFilters>` section rather than `<globalModules>`, but the essential operations — DLL write to disk, configuration file modification, DLL load into the worker process, and request interception — are identical to those of a native module.

**Managed modules** are .NET assemblies that implement the `IHttpModule` interface. Registration requires only a `<modules>` entry in the application's `web.config` file. When ASP.NET is installed, the `<modules>` configuration section is unlocked by default (`overrideMode="Allow"`), meaning application-level operators can add managed modules without administrator rights. The Common Language Runtime (CLR) hosted within `w3wp.exe` loads the assembly on the first HTTP request and calls `IHttpModule.Init()` to register the module's event handlers.

All persistent registration paths — for both native and managed modules — require a write to either `applicationHost.config` or `web.config`. No registry-only or in-memory-only persistent registration path has been identified for IIS 7+.

### Process Context

All IIS module types execute within `w3wp.exe` under the application pool identity, which defaults to `IIS APPPOOL\{PoolName}`, a low-privilege virtual account. This is the same process that executes file-based web shell requests. A critical operational distinction exists, however: a malicious IIS module can execute commands entirely in-process using .NET or Win32 APIs, without spawning a child process. When no `cmd.exe` or `powershell.exe` child appears under `w3wp.exe`, process-tree-based telemetry for the worker process does not fire.

### Log Suppression Capability

Modules registered for the `RQ_LOG_REQUEST` pipeline event can read and modify the IIS log record before IIS writes it to the W3C access log. This allows a malicious module to rewrite the HTTP method, alter the URI, or strip header fields from its own traffic — all before the log entry is committed. This capability is inherent to the pipeline event model and available to any registered module.

### Compiled IIS HTTP Handlers

IIS also supports HTTP handlers (`IHttpHandler`), which respond only to URL-matched requests via `ProcessRequest()` rather than intercepting all pipeline traffic via event subscription. A compiled `IHttpHandler` assembly registered in the `<handlers>` section of `web.config` follows the same essential operations as a managed module (Procedure B): the assembly is written to `/bin`, `web.config` is modified, and the CLR loads the assembly via the managed assembly loader. The prerequisite operations, load mechanism, and telemetry are identical — only the web.config target section (`<handlers>` vs `<modules>`) and the execution model (URL-matched vs pipeline-wide) differ. Because these differences do not change the essential operations or telemetry at the DDM level, compiled `IHttpHandler` deployments are covered under Procedure B. Script-based handler remapping — where `web.config` routes a static extension through `PageHandlerFactory` and ASP.NET compiles a script file at request time — involves different essential operations (ASP.NET compilation, `buildProviders` registration) and falls under T1505.003.

### Telemetry Constraints

Two important constraints apply to the IIS configuration change event. Microsoft-IIS-Configuration/Operational EID 29 fires on module additions and removals that flow through the IIS configuration API layer — commands executed via administrative interfaces such as `appcmd` or the IIS Manager. Direct text edits to `applicationHost.config` or `web.config` bypass the API entirely; EID 29 does not fire for direct file edits. Sysmon 11 (FileCreate) fires on file overwrite regardless of how the file was modified, making it the only telemetry source that covers both API-mediated and direct-edit registration paths.

Sysmon 7 (ImageLoad) hooks via the kernel callback `PsSetLoadImageNotifyRoutine`, which is triggered by `NtMapViewOfSection`. Native DLLs loaded via `LoadLibrary` follow this kernel path, and Sysmon 7 fires. The CLR's managed assembly loader, however, does not trigger this callback — lab testing confirmed that Sysmon 7 does not fire when the CLR loads a .NET assembly from the `/bin` directory into `w3wp.exe`, nor when an assembly is loaded reflectively via `Assembly.Load(byte[])`. This means Sysmon 7 provides telemetry for Procedure A (native module) only. It does not cover Procedures B or C.

The telemetry source for managed assembly loads across both Procedures B and C is ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1), produced by the CLR runtime provider. Lab testing confirmed that EID 154 fires for both disk-backed and reflective assembly loads. At the EID 154 level, the two load paths are indistinguishable — both events show only the assembly name with no file path, so a consumer cannot determine from the event alone whether an assembly was loaded from disk or from a byte array. This event requires an active ETW consumer session subscribed to the runtime provider with `LoaderKeyword (0x8)` — it is not captured by default. Because ETW events are generated in user space, an attacker with code execution in `w3wp.exe` can suppress them by patching `ntdll!EtwEventWrite` (T1562.006).

## Procedures

| ID | Name | Summary | Distinguishing Operations |
|----|------|---------|--------------------------|
| [TRR0029.WIN.A] | Persistent Native Module | C++ DLL registered in `applicationHost.config`, loaded via `LoadLibrary` at worker process start. Requires administrator. Survives reboots. | DLL write + `applicationHost.config` modification + `LoadLibrary` (NtMapViewOfSection). ISAPI variant maps here. |
| [TRR0029.WIN.B] | Persistent Managed Module | .NET assembly in `/bin` registered in `web.config`, loaded via CLR on first request. Covers both `IHttpModule` (pipeline-wide) and compiled `IHttpHandler` (URL-matched) variants. No administrator required in default config. Survives reboots. | Assembly write + `web.config` modification + CLR managed loader. |
| [TRR0029.WIN.C] | Reflective In-Memory Module | .NET assembly loaded reflectively into `w3wp.exe` via `Assembly.Load(byte[])` from pre-existing code execution. No disk artifact. Not persistent. | Code execution in `w3wp.exe` + reflective assembly load (heap allocation, no NtMapViewOfSection). |

### Procedure A: Persistent Native Module

The attacker writes a compiled native DLL to the IIS server filesystem. This write produces Sysmon 11 (FileCreate) telemetry at the destination path. The DLL implements the IIS native module interface and exports a `RegisterModule` entry point that will be called by IIS at worker process start.

After writing the DLL, the attacker modifies `applicationHost.config` to add the module under both `<globalModules>` and `<modules>`. This configuration file write produces Sysmon 11 (FileCreate) telemetry on the `applicationHost.config` path. If the modification is performed through the IIS configuration API (via an administrative interface), Microsoft-IIS-Configuration/Operational EID 29 may also fire. If the attacker edits the file directly — opening and saving it outside the API — EID 29 does not fire; Sysmon 11 remains the sole telemetry source. Administrator access is required for `applicationHost.config` modification. The ISAPI filter and ISAPI extension variants of this path share the same essential operations: DLL write, configuration file modification, DLL load into `w3wp.exe`, and request interception. Only the configuration section name differs (`<isapiFilters>` instead of `<globalModules>`).

When the IIS worker process next starts or recycles, IIS calls `LoadLibrary` on the registered DLL path, loading the native image into `w3wp.exe`. This load produces Sysmon 7 (ImageLoad) telemetry with `w3wp.exe` as the loading process. IIS then calls the exported `RegisterModule` function, which registers the module's `CHttpModule` or `CGlobalModule` event handlers for the desired pipeline stages. Pipeline hook registration has no direct telemetry — its occurrence is inferred from the preceding load event.

On every subsequent HTTP request, `w3wp.exe` invokes the registered handlers at their subscribed pipeline stages. This interception is reflected in IIS W3C access logs, though a module subscribed to `RQ_LOG_REQUEST` can modify those entries before they are written. The backdoor survives worker process recycles and server reboots because its registration is stored in `applicationHost.config`.

#### Detection Data Model

![DDM - Procedure A: Persistent Native Module](ddms/trr0029_win_a.png)

The DDM shows two prerequisite nodes — Write DLL to Disk and Modify applicationHost.config — feeding into the Load Native DLL operation, which in turn flows to Intercept HTTP Request. Both prerequisite operations produce Sysmon 11 (FileCreate) telemetry independently. Load Native DLL produces Sysmon 7 (ImageLoad) telemetry. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

---

### Procedure B: Persistent Managed Module

The attacker writes a .NET assembly to the application's `/bin` directory (or to the Global Assembly Cache). This write produces Sysmon 11 (FileCreate) telemetry at the destination path. The assembly implements the `IHttpModule` interface and contains an `Init()` method that registers the module's event handlers.

After writing the assembly, the attacker modifies `web.config` to add a `<modules>` entry referencing the assembly. This configuration file write produces Sysmon 11 (FileCreate) telemetry on the `web.config` path. If the modification is performed through the IIS configuration API, Microsoft-IIS-Configuration/Operational EID 29 may also fire. Direct file edits bypass the API and do not produce EID 29. Because the `<modules>` section is unlocked by default when ASP.NET is installed, this modification does not require administrator rights in a default IIS configuration — distinguishing this procedure from Procedure A.

The assembly is not loaded at worker process start. Instead, on the first HTTP request to the application after the configuration change, the CLR hosted within `w3wp.exe` locates the assembly via the configured path and loads it into the worker process. The CLR's managed assembly loader does not trigger the kernel image load callback (`PsSetLoadImageNotifyRoutine`), so Sysmon 7 (ImageLoad) does not fire for this operation. The telemetry source for this load is ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1), which requires an active ETW consumer session — it is not captured by default. The CLR then calls `IHttpModule.Init()`, which registers the module's event handlers for the desired pipeline stages. As with the native module path, hook registration produces no direct telemetry.

On every subsequent HTTP request, `w3wp.exe` invokes the registered handlers at their subscribed stages. The backdoor survives worker process recycles and server reboots because its registration is stored in `web.config`.

A compiled `IHttpHandler` registered in the `<handlers>` section of `web.config` follows this same procedure. The prerequisite operations are identical: the assembly is written to `/bin` (Sysmon 11), and `web.config` is modified (Sysmon 11, EID 29 if API-mediated). The CLR loads the assembly through the same managed loader path (ETW EID 154). The execution model differs — an `IHttpHandler` responds to URL-matched requests via `ProcessRequest()` rather than subscribing to pipeline events via `Init()` — but this difference does not introduce or remove any essential operation at the telemetry level.

#### Detection Data Model

![DDM - Procedure B: Persistent Managed Module](ddms/trr0029_win_b.png)

The DDM shows two prerequisite nodes — Write Assembly to Bin and Modify web.config — feeding into the Load Managed Assembly operation, which in turn flows to Intercept HTTP Request. Both prerequisite operations produce Sysmon 11 (FileCreate) telemetry independently. The Modify web.config operation covers registration in either `<modules>` (IHttpModule) or `<handlers>` (compiled IHttpHandler) — both produce the same telemetry. Load Managed Assembly produces ETW DotNETRuntime EID 154 (AssemblyLoad_V1) telemetry, conditioned on an active ETW consumer. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

---

### Procedure C: Reflective In-Memory Module

This procedure does not write a file to disk and does not modify any IIS configuration file. Its pipeline is entirely distinct from Procedures A and B.

The attacker has pre-existing code execution within `w3wp.exe`. The mechanism by which this foothold is obtained is a separate technique (delivery is excluded from this TRR's scope) but the initial exploitation request is captured in IIS W3C access logs.

From within `w3wp.exe`, the attacker calls `Assembly.Load(byte[])`, passing a .NET assembly as a raw byte array. The CLR allocates memory from the heap and loads the assembly without writing any file to disk and without calling `NtMapViewOfSection`. Because `NtMapViewOfSection` is not invoked, Sysmon 7 (ImageLoad) does not fire. The only telemetry source for this load is ETW Microsoft-Windows-DotNETRuntime EID 154 (AssemblyLoad_V1), produced by the CLR runtime provider. This event requires an active ETW consumer session subscribed to the runtime provider with `LoaderKeyword (0x8)` — it is not captured by default. Because ETW events are generated in user space, an attacker with code execution in `w3wp.exe` can suppress them by patching `ntdll!EtwEventWrite` before loading the assembly.

The loaded assembly cannot independently register into the IIS pipeline at request time — the CLR enforces that `HttpApplication.RegisterModule()` can only be called during application startup, not after the application has been initialized. In practice, real-world implementations of this technique use a loader/proxy pattern: an already-registered component (a legitimate module, a trojanized handler, or code running within an existing request context) loads the assembly reflectively and dispatches requests to it. The loaded assembly executes within the existing pipeline hook rather than independently subscribing to pipeline events. The module then intercepts subsequent HTTP requests through its loader, producing IIS W3C access log entries. If the loader is an `IHttpModule` registered for `RQ_LOG_REQUEST`, it can modify or suppress those entries before IIS commits them — this capability is not available if the loader is a handler or runs within an ad-hoc request context. Because no configuration file was modified, the module is not persistent — it is lost when the `w3wp.exe` process terminates or recycles.

#### Detection Data Model

![DDM - Procedure C: Reflective In-Memory Module](ddms/trr0029_win_c.png)

The DDM shows Gain Code Execution flowing into Load Assembly Reflectively, which in turn flows to Intercept HTTP Request. Gain Code Execution produces IIS W3C Access Logs telemetry. Load Assembly Reflectively produces ETW DotNETRuntime EID 154 (AssemblyLoad_V1) telemetry, conditioned on an active ETW consumer. Intercept HTTP Request produces IIS W3C Access Logs telemetry.

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
- [IHttpHandler Interface — Microsoft Learn]
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
[IHttpHandler Interface — Microsoft Learn]: https://learn.microsoft.com/en-us/dotnet/api/system.web.ihttphandler
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
