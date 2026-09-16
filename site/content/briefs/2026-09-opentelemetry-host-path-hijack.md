---
title: Untrusted Search Path Vulnerability in OpenTelemetry.Resources.Host on macOS
slug: 2026-09-opentelemetry-host-path-hijack
description: The OpenTelemetry.Resources.Host NuGet package is vulnerable to arbitrary code execution on macOS due to the use of bare paths for system command execution, allowing PATH hijacking.
date: "2026-09-16T19:07:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opentelemetry:opentelemetry_resources_host:*:*:*:*:*:*:*:*
vendors:
  - OpenTelemetry
products:
  - OpenTelemetry.Resources.Host (< 1.16.0-beta.2)
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The host.id resource attribute detector launches the sh and ioreg executables by bare name rather than by absolute path, so both are resolved through the PATH environment variable.
    confidence_band: high
cves:
  - id: CVE-2026-81192
    cvss: 7
    epss: 0.00138
references:
  - https://github.com/advisories/GHSA-v8pv-4842-x354
  - https://github.com/open-telemetry/opentelemetry-dotnet-contrib/pull/4760
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade OpenTelemetry.Resources.Host NuGet package to 1.16.0-beta.2 or later
      owner: IT Operations
      due: 24h
      evidence: The vulnerability was fixed by open-telemetry/opentelemetry-dotnet-contrib#4760 which executes ioreg directly using its absolute path.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable OpenTelemetry.Resources.Host packages to version 1.16.0-beta.2 or later
      owner: IT Operations
      addresses: CVE-2026-81192
      evidence: This vulnerability only affect macOS hosts; the vulnerability was fixed by version 1.16.0-beta.2.
---

The OpenTelemetry.Resources.Host NuGet package (versions prior to 1.16.0-beta.2) contains an untrusted search path vulnerability on macOS, tracked as CVE-2026-81192. The `host.id` resource attribute detector initiates the `ioreg` and `sh` system binaries using bare names rather than absolute file paths. This implementation relies on the system's `PATH` environment variable to locate the executables.

A local, less-privileged attacker capable of modifying the `PATH` environment variable or placing a malicious executable into a directory that appears earlier in the `PATH` than system directories can intercept the execution request. When the host application - which may be running with elevated privileges - triggers the detector, it unknowingly executes the attacker-supplied binary. This results in arbitrary code execution within the context of the application process. Defenders should prioritize updating the library to the patched version, as the vulnerability is specific to macOS environments and no effective workarounds exist.

## Attack Chain

1. Attacker gains access to a user account on a macOS system where a vulnerable application is installed.
2. Attacker identifies a process or service utilizing the `OpenTelemetry.Resources.Host` package.
3. Attacker identifies a writable directory that is included in the `PATH` variable used by the targeted process.
4. Attacker writes a malicious executable named `ioreg` to that directory.
5. Attacker modifies the environment variables of the targeted process or waits for the process to restart with the hijacked `PATH` configuration.
6. The targeted application invokes the `host.id` resource attribute detector.
7. The system resolves the call for `ioreg` to the malicious binary provided by the attacker.
8. The application executes the malicious binary with the application's elevated permissions, granting the attacker code execution.

## Impact

This vulnerability allows for local privilege escalation on macOS systems. If an application using the affected library runs as root or another highly privileged service user, an attacker can achieve code execution at that elevated level. This facilitates full system compromise, data theft, and persistent access within the target environment.

## Recommendation

Update the `OpenTelemetry.Resources.Host` NuGet package to version 1.16.0-beta.2 or later immediately. Ensure that environment variable configurations for critical services are hardened to prevent unauthorized modification of the `PATH` variable. There are currently no known configuration workarounds for this vulnerability.
