---
title: Authentication Bypass and RCE in Kestra OSS
slug: 2026-08-kestra-auth-bypass
description: Kestra OSS versions 1.3.20 and below are vulnerable to an authentication bypass via an incorrectly implemented filter, enabling unauthenticated remote code execution with root privileges.
date: "2026-08-01T09:53:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:kestra:kestra:*:*:*:*:*:*:*:*
tags:
  - cve-2026-53576
  - rce
  - authentication-bypass
  - kestra
vendors:
  - Kestra
products:
  - Kestra OSS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The authentication filter contains a logic flaw that allows attackers to bypass authentication by appending /configs to any endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This flaw allows an unauthenticated remote attacker to create, modify, and execute arbitrary workflows, leading to remote code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Commands run as root (uid=0).
    confidence_band: high
cves:
  - id: CVE-2026-53576
    cvss: 10
    epss: 0.00592
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-53576
  - https://github.com/kestra-io/kestra/security/advisories/GHSA-2q47-568g-9h4f
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=B4CF4F19-DA3B-5987-8FF5-A2A8BBBB870C
ioc_counts:
  url: 1
rules:
  - title: Detect CVE-2026-53576 Authentication Bypass Attempt
    description: Detects exploitation attempts by identifying requests to API endpoints that include the bypass string '/configs' which deviate from expected application routing.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-53576 is a critical authentication bypass vulnerability affecting Kestra OSS versions up to v1.3.20. The vulnerability stems from a flaw in the authentication filter logic, specifically within `AuthenticationFilter.java`, which checks if a request path ends with the string `/configs` to determine if an endpoint is a configuration route. Because this check uses `endsWith()` rather than an exact match, an attacker can bypass authentication on any API endpoint by simply appending `/configs` to the requested URL. This allows unauthenticated users to create, modify, and execute arbitrary workflows. Successful exploitation grants an attacker the ability to execute system commands with root privileges, leading to full system compromise. If the Kestra instance is running within a container with the Docker socket mounted, an attacker can perform a container escape to gain control of the host machine.

## Attack Chain

1. Attacker identifies an internet-facing Kestra instance vulnerable to CVE-2026-53576.
2. Attacker crafts a malicious API request targeting `/api/v1/main/flows/configs` to bypass authentication.
3. Attacker submits a POST request to create a new flow containing arbitrary malicious commands.
4. Attacker crafts a second request targeting `/api/v1/main/executions/configs/configs` to trigger the execution of the previously created malicious flow.
5. The Kestra service executes the workflow, running the embedded commands with root privileges on the underlying host.
6. Attacker leverages shell commands to establish a reverse shell or exfiltrate system data from the host.
7. If the container environment is misconfigured, the attacker uses the exposed Docker socket to escape the container and compromise the host environment.

## Impact

Successful exploitation results in full unauthorized control over the Kestra instance. Impacts include complete confidentiality loss (access to environment variables and secrets), loss of integrity (unauthorized modification of workflows), and full system compromise via RCE. In containerized environments, the lack of host isolation through improper Docker socket mounting facilitates container escapes, providing attackers with persistent host-level access.

## Recommendation

1. Upgrade all Kestra OSS deployments to a patched version immediately, as identified in the Kestra security advisory (GHSA-2q47-568g-9h4f).
2. Deploy the Sigma rule below to detect exploitation attempts targeting the `/configs` bypass vector in web server logs.
3. Remove any instances where `/var/run/docker.sock` is mounted into Kestra containers to prevent potential container escape scenarios.
4. Implement strict network segmentation and restrict access to the Kestra management API using VPNs or IP whitelisting.
