# File-Based Web Shell Execution via IIS

## Metadata

| Key          | Value                                          |
|--------------|------------------------------------------------|
| ID           | TRR0000                                        |
| External IDs | [T1505.003]                                    |
| Tactics      | Persistence                                    |
| Platforms    | Windows                                        |
| Contributors | John                                           |

### Scope Statement

This TRR covers the execution of file-based web shells on Microsoft Internet
Information Services (IIS) web servers running on Windows. While web shells can
be deployed on many web server platforms (Apache, Nginx, Tomcat, etc.), the
execution mechanics differ meaningfully across platforms due to differences in
request processing architecture, handler models, and available scripting
engines. This report focuses exclusively on IIS because of its deep integration
with the Windows operating system and the ASP/ASP.NET execution pipeline.

The following are explicitly out of scope for this report and may be documented
in future TRRs:

- Fileless or memory-only web shells (such as those injected into the IIS
  pipeline via native modules, ISAPI filters/extensions, or reflection-based
  techniques)
- ASP.NET Core applications hosted on IIS, which use a fundamentally different
  execution model (IIS acts as a reverse proxy to Kestrel, or uses the
  ASP.NET Core Module for in-process hosting) with different handler mapping
  and compilation mechanics than the classic ASP/ASP.NET pipeline
- PHP web shells on IIS via FastCGI, which involve a different execution model
  (`php-cgi.exe`) that is better addressed in a platform-agnostic report
- Web shells on non-Windows platforms (Apache, Nginx, Tomcat, etc.)

Server-Side Includes (SSI) via `ssinc.dll` are discussed in the Technical
Background section but are not treated as a separate procedure. SSI-based web
shells follow the same essential operations as Procedures A and B; only the
handler and file extension differ, which are tangential elements.

This technique maps to MITRE ATT&CK [T1505.003] (Server Software Component:
Web Shell). It is also relevant to OWASP A02:2025 (Security Misconfiguration),
as web shell deployment often exploits misconfigured upload functionality,
excessive file permissions, or overly permissive handler mappings.

## Technique Overview

A web shell is a malicious script placed on a web server that provides an
attacker with remote access and command execution through the server's normal
HTTP request-handling mechanisms. The attacker interacts with the web shell by
sending crafted HTTP requests to the shell's URL. The web server processes the
request like any other page, but the web shell's code executes the attacker's
commands and returns the results in the HTTP response.

Web shells broadly fall into two categories: file-based and fileless.
File-based web shells exist as script files on disk (such as `.aspx` or `.asp`
files) and are executed through the web server's normal handler mappings.
Fileless web shells operate entirely in memory, typically injected into the
web server's processing pipeline through native modules, ISAPI extensions, or
reflection-based techniques, and leave no script file on disk. This report
covers file-based web shells on IIS exclusively; fileless web shells involve
fundamentally different essential operations and are documented separately.

File-based web shells are attractive to adversaries because they provide
persistent access that survives system reboots, blend in with normal web
traffic on ports 80 and 443 (making them difficult to distinguish from
legitimate activity), and leverage the web server's existing execution
capabilities without requiring additional software to be installed. On IIS, a
file-based web shell is typically an ASP or ASPX file placed in a
web-accessible directory. Once planted, the attacker can return at any time by
simply browsing to the web shell's URL.

## Technical Background

### IIS Architecture

Internet Information Services (IIS) is Microsoft's web server, included with
Windows Server. Understanding its architecture is essential to understanding how
web shells execute, because every web shell on IIS must pass through the same
request processing pipeline regardless of the shell's specific implementation.

#### HTTP.sys

All HTTP and HTTPS traffic destined for IIS passes through HTTP.sys, a
kernel-mode driver that listens for incoming requests on configured ports
(typically 80 and 443). HTTP.sys handles low-level tasks like connection
management, caching, and request routing. When a request requires processing by
application code, HTTP.sys routes it to the appropriate application pool based
on the site's configured bindings (hostname, port, and IP address). HTTP.sys
operates at the kernel level, below the reach of most detection strategies, but
all web shell traffic must transit through it.

#### Application Pools

An application pool is an isolation boundary within IIS. Each application pool
runs as its own instance of the IIS worker process, `w3wp.exe`. Different
websites or applications hosted on the same IIS server can be assigned to
different application pools, giving each its own worker process with its own
security identity and resource limits. The application pool's configured
identity determines the security context under which all code in that pool
executes â€” including any web shell code.

By default, application pools run under low-privilege virtual accounts (e.g.,
`IIS AppPool\DefaultAppPool`). However, administrators sometimes configure
pools to run under higher-privilege accounts such as `NetworkService`, domain
service accounts, or even `LocalSystem`. The web shell inherits whatever
permissions the application pool's identity has, which directly determines the
scope of what an attacker can accomplish through the shell.

#### The IIS Worker Process (w3wp.exe)

The worker process `w3wp.exe` is the most important component for understanding
web shell execution. When HTTP.sys routes a request to an application pool,
that pool's `w3wp.exe` instance handles the request. This process loads and
executes the requested file using the appropriate scripting engine, runs under
the application pool's identity, and has the ability to spawn child processes.

This last point is critical for detection: when a web shell executes operating
system commands by starting external programs (such as `cmd.exe` or
`powershell.exe`), those programs appear as child processes of `w3wp.exe`. Under
normal operations, `w3wp.exe` rarely spawns command interpreters or system
utilities, making this parent-child relationship one of the most reliable
detection signals for web shell activity.

However, not all web shell activity produces child processes. Web shells that
operate exclusively through .NET framework APIs (for example, using
`System.IO.File` for file operations, `System.Net.WebClient` for network
connections, or `System.Data.SqlClient` for database access) execute entirely
within the `w3wp.exe` process without ever spawning a child process. This
distinction is fundamental and is the basis for two of the procedures identified
in this TRR.

### Handler Mappings

IIS uses handler mappings to determine how to process a requested file. When a
request arrives, IIS examines the file extension and consults its handler
mapping configuration to determine whether the file should be served as static
content or processed by a scripting engine. Static file types (such as `.html`,
`.css`, `.js`, and image formats) are returned to the client without any code
execution. Script file types are handed to the appropriate engine for
processing.

On a default IIS installation with ASP.NET enabled, the following extensions are
mapped to executable handlers:

- `.aspx` â€” processed by the ASP.NET engine
- `.asp` â€” processed by the Classic ASP engine
- `.ashx` â€” processed by the ASP.NET generic handler
- `.asmx` â€” processed by the ASP.NET web service handler

IIS also supports Server-Side Includes (SSI) via the `ssinc.dll` ISAPI
extension. If SSI is enabled, files with extensions `.shtml`, `.stm`, and
`.shtm` can execute directives such as `<!--#exec cmd="command">`. These
represent additional executable extensions an attacker could leverage, though
the essential operations for execution are the same as for ASP/ASPX files.

If PHP or other third-party handlers have been configured, their associated
extensions (such as `.php`) will also be executable. For a web shell to function
under default handler mappings, it must use a file extension that is already
mapped to an executable handler. This is an essential and immutable constraint
â€” unless the attacker modifies the handler mappings themselves (see the
web.config section below).

### ASP vs. ASP.NET Execution

While both Classic ASP and ASP.NET files are executed by IIS, the underlying
execution mechanics differ in a way that is relevant to detection.

Classic ASP files (`.asp`) are interpreted directly by the ASP engine
(`asp.dll`) inside the `w3wp.exe` process. The script code is parsed and
executed at request time, and no additional artifacts are produced on disk
beyond the original `.asp` file.

ASP.NET files (`.aspx`) undergo a compilation step. On the first request to an
`.aspx` file, the ASP.NET engine compiles the file's source code into a .NET
assembly (DLL). This compiled assembly is stored in a temporary directory at
`C:\Windows\Microsoft.NET\Framework64\<version>\Temporary ASP.NET Files\` and
is then loaded into the `w3wp.exe` process for execution. Subsequent requests
to the same file reuse the compiled assembly without recompilation. On older
versions of ASP.NET, this compilation step may spawn `csc.exe` (the C# compiler)
as a child process of `w3wp.exe`; on newer versions using the Roslyn compiler,
the compilation may occur in-process.

The creation of a compiled DLL in the Temporary ASP.NET Files directory is an
observable artifact that can serve as an additional detection signal for ASPX
web shells. However, this artifact is not unique to web shells â€” any legitimate
`.aspx` page produces the same compilation artifact on its first request.

### The Web Root and Virtual Directories

Every IIS site has a configured physical path that maps to a directory on the
file system. The default path is `C:\inetpub\wwwroot\`. For a web shell to be
reachable via an HTTP request, the shell file must reside within this directory
structure or within a virtual directory configured in IIS. Virtual directories
can map to physical paths anywhere on the file system (for example,
`D:\shared\uploads\`), extending the web-accessible area beyond the default
web root. Files placed outside of any web-accessible path cannot be triggered
by an HTTP request and therefore cannot function as web shells.

### web.config and Handler Manipulation

IIS configuration can be modified at the directory level through `web.config`
files. A `web.config` file placed in any web-accessible directory can override
IIS settings for that directory and its subdirectories. This has significant
implications for web shell execution.

An attacker who can write a `web.config` file to a web-accessible directory can
manipulate handler mappings in two ways. First, they can add a custom handler
mapping that instructs IIS to process a normally static file extension (such as
`.jpg`, `.txt`, or `.png`) through the ASP.NET engine. The attacker then places
their web shell with that innocuous extension, bypassing any security controls
that monitor only traditional script extensions. Second, and more directly, the
attacker can define an inline `IHttpHandler` within the `web.config` file
itself, effectively turning the configuration file into the web shell. In this
variant, no separate script file is needed at all â€” the `web.config` is the
sole file the attacker must write.

When a `web.config` file is placed in a subdirectory, IIS dynamically reloads
that directory's configuration without requiring a server restart. This means
the attacker's handler manipulation takes effect immediately.

### IIS Application Initialization

IIS supports an Application Initialization feature that can be configured
through `web.config`. This feature causes IIS to automatically send internal
warmup requests to specified pages whenever an application pool starts,
recycles, or the server reboots. Under normal use, this ensures that frequently
accessed pages are pre-compiled and cached before the first real user request
arrives.

However, this feature has significant implications for web shell persistence.
If an attacker can configure Application Initialization via `web.config` and
designate the web shell as a preload page, IIS itself will automatically
trigger the web shell without the attacker needing to send their own HTTP
request. This transforms the web shell from a passive backdoor that waits for
the attacker to connect into an active one that executes on every app pool
lifecycle event. For a persistence-focused technique, this is a meaningful
escalation: it ensures the web shell's code runs even if the attacker loses
their ability to send requests to the server, and it generates the trigger
request from IIS internally rather than from an external source that might be
visible in network monitoring.

## Procedures

| ID             | Title                                    | Tactic      |
|----------------|------------------------------------------|-------------|
| TRR0000.WIN.A  | Web Shell with OS Command Execution      | Persistence |
| TRR0000.WIN.B  | Web Shell with In-Process Execution      | Persistence |
| TRR0000.WIN.C  | Web Shell via web.config Manipulation    | Persistence |

### Procedure A: Web Shell with OS Command Execution

This is the most commonly observed and well-documented form of web shell
activity. In this procedure, a malicious script file (typically `.aspx` or
`.asp`) is placed in a web-accessible directory on an IIS server. The file may
be delivered by creating a new file in the web root or by injecting web shell
code into an existing legitimate file. The method by which the file reaches the
server is outside the scope of this procedure â€” it could be delivered via
exploitation of a file upload vulnerability, through compromised administrative
credentials, by an attacker with existing access to the server, or through many
other means. The delivery method is tangential: the essential prerequisite is
simply that the malicious code must exist on disk in a location that IIS is
configured to serve.

An important detection note regarding file delivery: creating a new file and
modifying an existing file produce different telemetry. New file creation is
captured by Sysmon Event ID 11 (File Create). Modifying an existing file is
not captured by Sysmon 11; detection of modifications requires file integrity
monitoring (FIM) or other content-aware scanning. Injecting code into an
existing legitimate page is a stealthier delivery variant for this reason.

When the attacker sends an HTTP request to the web shell's URL, the request
enters the IIS pipeline through HTTP.sys and is routed to the appropriate
application pool's worker process (`w3wp.exe`). IIS examines the file extension,
matches it against its handler mappings, and invokes the appropriate scripting
engine. For `.aspx` files, the ASP.NET engine first compiles the file into a
temporary DLL (if it has not already been compiled from a prior request) and
then executes it. For `.asp` files, the Classic ASP engine interprets the code
directly.

What distinguishes this procedure is what happens next: the web shell code
calls a process-creation API (such as `System.Diagnostics.Process.Start()` in
.NET) to launch an external program â€” most commonly `cmd.exe` or
`powershell.exe` â€” with command-line arguments provided by the attacker in the
HTTP request. This spawns a new child process under `w3wp.exe`. The child
process executes the attacker's operating system command, and the output is
captured by the web shell code and returned to the attacker in the HTTP
response.

This process-spawning behavior is the primary detection opportunity for this
procedure. Under normal operations, `w3wp.exe` should rarely, if ever, spawn
command interpreters, system utilities, or other unexpected child processes.
Monitoring for suspicious child processes of `w3wp.exe` (such as `cmd.exe`,
`powershell.exe`, `whoami.exe`, `net.exe`, `ipconfig.exe`, `systeminfo.exe`,
and similar) provides a high-fidelity detection signal.

#### Detection Data Model

![DDM - Web Shell with OS Command Execution](ddms/trr0000_a.png)

The DDM for this procedure shows file prerequisite operations (Create New File
or Modify Existing File) feeding into the IIS request pipeline. The request
flows through Route Request and Match Handler before reaching Execute Code. The
procedure's distinguishing operation is the spawning of a child process from
`w3wp.exe`. The process creation telemetry (Sysmon Event ID 1, Windows Security
Event 4688) capturing the parent-child relationship between `w3wp.exe` and the
spawned process is the strongest detection opportunity in this procedure.

The Compile ASPX sub-operation (shown as a lower abstraction layer of Execute
Code) is relevant only when the web shell uses an `.aspx` extension and
produces an observable artifact in the form of a compiled DLL in the Temporary
ASP.NET Files directory. On older ASP.NET versions, the compilation may also
produce a `csc.exe` child process.

### Procedure B: Web Shell with In-Process Execution

This procedure follows the same prerequisite and pipeline operations as
Procedure A: a malicious script file is placed in a web-accessible directory
(either as a new file or injected into an existing file), an HTTP request
triggers it, the request is routed through IIS, the handler mapping is matched,
and the code is executed inside `w3wp.exe`.

The critical difference is that the web shell code never spawns a child process.
Instead, it performs all of its actions using .NET framework APIs or COM objects
that execute entirely within the `w3wp.exe` process. For example, a web shell
in this procedure might use `System.IO.File.ReadAllText()` to read sensitive
files, `System.IO.Directory.GetFiles()` to enumerate directory contents,
`System.Net.WebClient` to make outbound network connections, or
`System.Data.SqlClient` to query databases. All of these operations happen
inside `w3wp.exe` and produce no new processes.

This makes Procedure B significantly harder to detect using process-based
telemetry. There is no suspicious parent-child relationship to alert on, and
from a process monitoring perspective, `w3wp.exe` appears to be operating
normally. Detection must instead rely on secondary indicators: the initial file
creation event (the web shell being written to disk), patterns in IIS request
logs (such as repeated requests to a single unusual file, POST requests to a
file that normally would not receive them, or requests from anomalous source
IPs), unusual outbound network connections originating from `w3wp.exe`, or file
integrity monitoring detecting the appearance of new script files in the web
root.

The specific .NET API calls made by the web shell are attacker-controlled and
effectively infinite in variety â€” the attacker can use any API available to the
.NET framework. As such, the individual API calls are tangential to the
procedure and are not modeled in the DDM. However, the side effects of those
API calls may produce telemetry depending on the specific action: file
read/write operations may generate SACL audit events (Event 4663), outbound
network connections from `w3wp.exe` may appear in Sysmon Event ID 3 or firewall
logs, and registry access may produce Sysmon Events 12-14.

#### Detection Data Model

![DDM - Web Shell with In-Process Execution](ddms/trr0000_b.png)

The DDM for Procedure B is identical to Procedure A through the Execute Code
operation. It diverges at the final step, where instead of a process spawn,
the web shell calls .NET APIs directly. The Call .NET API operation has no
direct telemetry â€” you cannot observe the API call itself. Detection for this
procedure therefore depends on the file creation event (Sysmon 11 when the web
shell is first written to disk), IIS log analysis (W3C logs showing requests to
the shell's URL), and any telemetry produced by the side effects of the API
calls. This represents a meaningful detection gap compared to Procedure A, and
defenders should be aware that a web shell operating exclusively through
in-process API calls can evade most process-based detection strategies.

### Procedure C: Web Shell via web.config Manipulation

This procedure differs from Procedures A and B at the prerequisite stage rather
than at the execution stage. It is modeled as a distinct procedure because the
Write Config operation fundamentally changes the behavior of the IIS handler
matching process, introducing a different essential operation chain. Rather
than placing a traditional script file on disk and relying on default IIS
handler mappings, the attacker writes or modifies a `web.config` file in a
web-accessible directory to change how IIS handles requests for that directory.

There are two primary variants of this approach. In the first variant, the
attacker adds a custom handler mapping to the `web.config` that instructs IIS
to process a normally static file extension (such as `.jpg`, `.txt`, or `.log`)
through the ASP.NET engine. The attacker then places their web shell with that
innocuous extension in the same directory. Because the custom handler mapping
overrides the default static file handler, IIS treats the file as executable
code. This variant requires two files: the `web.config` and the web shell file
itself. However, the web shell file will bypass any security controls that
monitor only for traditional script extensions.

In the second and more direct variant, the attacker defines an inline
`IHttpHandler` directly within the `web.config` file. The handler's code is
embedded in the configuration XML and executes when a matching request arrives.
In this case, the `web.config` file is the sole file the attacker must write â€”
no separate script file is needed.

Both variants share a critical prerequisite operation: writing a `web.config`
file to a web-accessible directory. When a `web.config` is placed in a
subdirectory, IIS dynamically reloads that directory's configuration, causing
the new handler mappings to take effect immediately. From that point forward,
the request pipeline operates the same as in Procedures A and B: an HTTP
request is sent, the request is routed, the (now modified) handler mapping
matches, and code is executed inside `w3wp.exe`. The post-execution behavior
(process spawn or .NET API call) depends on what the web shell code does, just
as in the other procedures.

An additional persistence enhancement is possible if the attacker configures
IIS Application Initialization via the `web.config` (described in the
Technical Background section above). By designating the web shell as a preload
page, IIS itself will trigger the web shell on every app pool recycle or
server reboot, eliminating the need for the attacker to send their own HTTP
request. This transforms the web shell from a passive backdoor into one that
auto-executes on server lifecycle events, and the trigger request originates
from IIS internally rather than from an external source.

The primary detection opportunity for this procedure is monitoring for the
creation or modification of `web.config` files in web-accessible directories.
This can be observed through Sysmon Event ID 11 (if the file is newly created),
file integrity monitoring, and IIS configuration change logging. Changes to
`web.config` in production environments should be rare and tightly controlled,
making new or modified `web.config` files a high-fidelity detection signal.

#### Detection Data Model

![DDM - Web Shell via web.config Manipulation](ddms/trr0000_c.png)

The DDM for Procedure C shows the Write Config operation feeding into Match
Handler, reflecting the fact that it modifies how handler matching behaves. In
the inline handler variant, Write Config is the sole prerequisite operation â€”
no separate Create New File or Modify Existing File operation is needed. In the
custom handler mapping variant, Write Config is accompanied by a file operation
to place the web shell with an unusual extension. The downstream pipeline
(Route Request â†’ Match Handler â†’ Execute Code) is structurally the same as in
Procedures A and B, but Match Handler now operates against the attacker-defined
handler mappings rather than the server defaults. The post-execution branch
between process spawn and .NET API calls remains the same, as post-execution
behavior depends on the web shell's code, not on how the handler was configured.

## Available Emulation Tests

| ID             | Link                |
|----------------|---------------------|
| TRR0000.WIN.A  | [Atomic Test T1505.003-1], [Atomic Test T1505.003-2] |
| TRR0000.WIN.B  |                     |
| TRR0000.WIN.C  |                     |

## References

- [IIS Architecture Overview - Microsoft Learn]
- [Handler Mappings in IIS - Microsoft Learn]
- [Application Pools in IIS - Microsoft Learn]
- [ASP.NET Compilation Overview - Microsoft Learn]
- [Virtual Directories in IIS - Microsoft Learn]
- [web.config Reference - Microsoft Learn]
- [IIS Application Initialization - Microsoft Learn]
- [Server-Side Includes in IIS - Microsoft Learn]
- [IHttpHandler Interface - Microsoft Learn]
- [Detect and Prevent Web Shell Malware - NSA/CISA]
- [Web Shell Attacks Continue to Rise - Microsoft Security Blog]
- [T1505.003 - MITRE ATT&CK]

[T1505.003]: https://attack.mitre.org/techniques/T1505/003/
[IIS Architecture Overview - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/introduction-to-iis-architecture
[Handler Mappings in IIS - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
[Application Pools in IIS - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/
[ASP.NET Compilation Overview - Microsoft Learn]: https://learn.microsoft.com/en-us/previous-versions/aspnet/ms178466(v=vs.100)
[Virtual Directories in IIS - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/application/virtualdirectory
[web.config Reference - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/
[IIS Application Initialization - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/applicationinitialization/
[Server-Side Includes in IIS - Microsoft Learn]: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude
[IHttpHandler Interface - Microsoft Learn]: https://learn.microsoft.com/en-us/dotnet/api/system.web.ihttphandler
[Detect and Prevent Web Shell Malware - NSA/CISA]: https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
[Web Shell Attacks Continue to Rise - Microsoft Security Blog]: https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
[T1505.003 - MITRE ATT&CK]: https://attack.mitre.org/techniques/T1505/003/
[Atomic Test T1505.003-1]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md#atomic-test-1---deploy-asp-webshell
[Atomic Test T1505.003-2]: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1505.003/T1505.003.md#atomic-test-2---deploy-aspx-webshell
