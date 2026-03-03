# TRR0029 Procedure Table — T1505.004: IIS Components (Windows)

## Procedures

| ID | Name | Summary | Distinguishing Operations |
|----|------|---------|--------------------------|
| TRR0029.WIN.A | Persistent Native Module | C++ DLL registered in applicationHost.config, loaded via LoadLibrary into w3wp.exe at worker process start. Requires administrator access. Survives reboots and worker recycles. | Write DLL to disk + Modify applicationHost.config + Load via LoadLibrary (NtMapViewOfSection). ISAPI filter/extension variant maps here. |
| TRR0029.WIN.B | Persistent Managed Module | .NET IHttpModule assembly placed in /bin (or GAC) and registered in web.config, loaded via CLR on first HTTP request. Does not require administrator when modules section is unlocked (default). Survives reboots. | Write assembly to /bin + Modify web.config + Load via CLR disk resolver (NtMapViewOfSection). No admin required in default config. |
| TRR0029.WIN.C | Reflective In-Memory Module | .NET assembly loaded reflectively into w3wp.exe memory via Assembly.Load(byte[]) from a pre-existing code execution foothold. No file written to disk. No configuration file modified. Not persistent — lost on w3wp.exe termination. | Gain code execution in w3wp.exe + Reflective assembly load (heap allocation, no NtMapViewOfSection). Zero disk artifacts. Zero config changes. |

## Procedure-to-DDM Mapping

| Procedure | Active Path (Red Arrows) | DDM Export File |
|-----------|-------------------------|-----------------|
| TRR0029.WIN.A | n0 → n2 → n9, n1 → n2 (r0, r1, r5) | trr0029_win_a.json |
| TRR0029.WIN.B | n3 → n5 → n9, n4 → n5 (r2, r3, r6) | trr0029_win_b.json |
| TRR0029.WIN.C | n6 → n7 → n9 (r4, r7) | trr0029_win_c.json |

## DDM Node Summary

| Node | Caption | Telemetry | Procedures |
|------|---------|-----------|------------|
| n0 | Write DLL to Disk | Sysmon 11 (FileCreate) | A |
| n1 | Modify applicationHost.config | Sysmon 11 (FileCreate), IIS-Config/Operational EID 29 (API-mediated only) | A |
| n2 | Load Native DLL | Sysmon 7 (ImageLoad) | A |
| n3 | Write Assembly to Bin | Sysmon 11 (FileCreate) | B |
| n4 | Modify web.config | Sysmon 11 (FileCreate), IIS-Config/Operational EID 29 (API-mediated only) | B |
| n5 | Load Managed Assembly | Sysmon 7 (ImageLoad) | B |
| n6 | Gain Code Execution | IIS W3C Access Logs, EDR Behavioral | C |
| n7 | Load Assembly Reflectively | ETW DotNETRuntime EID 154 (AssemblyLoad_V1) | C |
| n9 | Intercept HTTP Request | IIS W3C Access Logs | A, B, C |

**Note:** Pipeline hook registration (RegisterModule/IHttpModule.Init) precedes interception but has no direct telemetry and was excluded from the DDM per the inclusion test (Observable: NO). Its occurrence is inferred from the preceding load event.

## Telemetry Coverage Summary

| Telemetry Source | Procedure A | Procedure B | Procedure C |
|-----------------|-------------|-------------|-------------|
| Sysmon 11 (FileCreate) | DLL write + config write | Assembly write + config write | Not applicable |
| Sysmon 7 (ImageLoad) | DLL load into w3wp.exe | Assembly load into w3wp.exe | Does NOT fire (heap allocation) |
| IIS-Config/Operational EID 29 | Config write (API-mediated only) | Config write (API-mediated only) | Not applicable |
| ETW DotNETRuntime EID 154 | Not applicable | Not applicable | Reflective assembly load (requires ETW consumer) |
| IIS W3C Access Logs | HTTP interception | HTTP interception | Exploit request + HTTP interception |
| EDR Behavioral | — | — | Exploit / code execution |

## Alternate Path Analysis (Phase 3 Research)

Six candidate paths investigated — all resolved as tangential variations or out-of-scope:

1. **GAC-registered managed module** — Merge with Procedure B (storage location is tangential; CLR load mechanism unchanged)
2. **appcmd vs. PowerShell vs. direct file edit** — Already in Exclusion Table (registration tool is attacker-controlled)
3. **IIS Express** — Out of scope (developer tool, not production server)
4. **IceApple hybrid model** — Sequential combination of Procedures A/B + C (no new essential operations)
5. **Add-WebConfigurationProperty vs. appcmd** — Sub-variant of #2 (same API path, same config write)
6. **Precondition manipulation** — Tangential parameter within same config file write

## Review Gate Resolution

Initial review returned FAIL with two critical issues:
- **C1 (Fixed):** Node n8 "Register Pipeline Hooks" failed Observable criterion (scoping Constraint #4 explicitly marks Observable: NO). Removed from DDM. Loading nodes now flow directly to n9 "Intercept HTTP Request". Hook registration noted in n9 properties.
- **C2 (Fixed):** Node n6 "Exploit Web Application" named the delivery method (tangential per Exclusion Table). Renamed to "Gain Code Execution" — the essential, immutable operation.
