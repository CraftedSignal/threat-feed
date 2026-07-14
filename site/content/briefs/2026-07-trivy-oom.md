---
title: Trivy Unbounded Read Leads to Denial of Service via Helm Chart Tar Bomb
slug: 2026-07-trivy-oom
description: Trivy versions prior to 0.71.0 are vulnerable to CVE-2026-54448, a denial-of-service attack where a crafted Helm chart archive (.tgz) can cause unbounded memory consumption, leading to the OS OOM killer terminating the Trivy process and other services on the host or CI runner.
date: "2026-07-14T20:24:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:aquasec:trivy:*:*:*:*:*:go:*:*
tags:
  - supply-chain
  - vulnerability
  - denial-of-service
  - ci-cd
vendors:
  - Aquasecurity
products:
  - Trivy (< 0.71.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'An attacker who can place a malicious `.tgz` file in the scanned path can craft a small compressed archive that decompresses to gigabytes, causing the Trivy process to be killed by the OS OOM killer. The practical impact in CI environments is denial of service: the scan fails, the pipeline is blocked, and repeated submissions re-trigger the same condition.'
    confidence_band: high
cves:
  - id: CVE-2026-54448
    cvss: 6.5
    epss: 0.0025
references:
  - https://github.com/advisories/GHSA-q3fv-x8vg-qqm4
---

Trivy, an open-source vulnerability scanner from Aquasecurity, is affected by CVE-2026-54448, a denial-of-service vulnerability present in versions prior to 0.71.0. This flaw allows an attacker to exhaust system memory and trigger an Out-Of-Memory (OOM) kill of the Trivy process and potentially other co-located processes. The vulnerability occurs when Trivy scans a malicious Helm chart archive (`.tgz` file) as part of configuration, filesystem, or image scans with misconfiguration scanning enabled. Its custom tar unpacker attempts to read each archive entry into memory using `io.ReadAll` without any size limitations. A small, specially crafted compressed archive can decompress to gigabytes of data, rapidly consuming all available RAM. This can lead to CI pipeline failures, service disruptions, and increased cloud resource costs in affected environments. The issue was fixed in Trivy v0.71.0 by replacing the custom unpacker with the official Helm SDK's `archive.LoadArchiveFiles`, which enforces size limits and validates archive structure.

## Attack Chain

1. An attacker creates a highly compressed `.tgz` Helm chart archive designed to decompress into an extremely large file, for example, by embedding a large number of null bytes.
2. The attacker places this crafted `.tgz` file in a location that a vulnerable Trivy instance is configured to scan, such as a repository that a CI pipeline runs `trivy config .` on, or within a container image scanned for misconfigurations.
3. A vulnerable Trivy instance (version < 0.71.0) initiates a scan that includes the path containing the malicious `.tgz` file, for example, via `trivy config <dir>`, `trivy filesystem --scanners misconf <dir>`, or `trivy image --scanners misconf <image>`.
4. Trivy's internal tar unpacker encounters the malicious `.tgz` file and attempts to decompress and parse it as a Helm chart.
5. Due to the unbounded `io.ReadAll` implementation, Trivy attempts to read the entire decompressed (gigabytes-large) archive entry into memory without any size limits.
6. The Trivy process rapidly consumes all available memory on the host system or CI runner where it is executing, leading to severe memory pressure.
7. The operating system's Out-Of-Memory (OOM) killer is triggered in response to the memory exhaustion.
8. The OOM killer forcibly terminates the Trivy process and potentially other processes sharing the same host, resulting in a denial of service (DoS) for the scanning operation and potential disruption to the CI pipeline or affected system.

## Impact

An attacker exploiting CVE-2026-54448 can cause a denial of service by exhausting all available memory on the host running the vulnerable Trivy process. This triggers the operating system's OOM killer, which terminates the Trivy process and may also affect other processes sharing the same host or CI runner. In CI/CD environments, the practical impact is that security scans fail, pipelines are blocked, and repeated submissions of malicious archives continue to disrupt operations. Cloud CI runners may also incur additional costs due to prolonged resource consumption attempts. There is no observed impact on the confidentiality or integrity of the scanned system itself, only its availability.

## Recommendation

* Upgrade Trivy to version `v0.71.0` or later immediately to patch CVE-2026-54448. The fix replaces the vulnerable custom tar unpacker with the official Helm SDK which includes size limits.
* If immediate upgrade is not possible, set memory limits (e.g., via cgroups or container runtime configurations) on the Trivy process to bound the blast radius of memory exhaustion.
* Use the `--skip-dirs` flag to exclude directories containing untrusted Helm chart archives (`.tgz` files) from Trivy scans.
* Avoid scanning repositories or container images that are known to contain untrusted `.tgz` files when using vulnerable versions of Trivy.
