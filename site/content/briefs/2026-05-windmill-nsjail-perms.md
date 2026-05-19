---
title: Windmill nsjail Sandbox Incorrect Permissions Vulnerability (CVE-2026-47107)
slug: 2026-05-windmill-nsjail-perms
description: Windmill versions prior to 1.703.2 are vulnerable to incorrect default permissions in the nsjail sandbox configuration, allowing authenticated users to inject malicious entries into critical system files, leading to potential privilege escalation and man-in-the-middle attacks.
date: "2026-05-19T18:18:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - man-in-the-middle
  - cve
vendors:
  - Windmill
products:
  - Windmill (< 1.703.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-47107
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47107
rules:
  - title: Detect Suspicious Modification of /etc/hosts, /etc/resolv.conf, or /etc/ssl/certs/ca-certificates.crt in nsjail Sandbox
    description: Detects CVE-2026-47107 exploitation — modification of critical system files within a nsjail sandbox environment.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1555.003
    data_sources:
      - file_event
      - linux
  - title: Detect nsjail Execution of Common Network Tools
    description: Detects potential lateral movement or information gathering attempts within a nsjail environment by monitoring the execution of common network tools.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - lateral_movement
    techniques:
      - T1016
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Windmill, a low-code internal tool platform, is susceptible to a critical vulnerability (CVE-2026-47107) due to insecure default permissions within its nsjail sandbox configuration. Specifically, the /etc directory is bind-mounted without adequate read-write restrictions. This flaw permits authenticated users to manipulate essential system files such as /etc/hosts, /etc/resolv.conf, and /etc/ssl/certs/ca-certificates.crt from within script execution sandboxes. The vulnerability exists in versions prior to 1.703.2. Successful exploitation allows attackers to poison entries persistently across all subsequent script executions on the compromised worker pod. This can lead to the redirection of hostnames, interception of DNS queries, execution of transparent HTTPS man-in-the-middle attacks, and interception of WM_TOKEN JWTs. This can allow attackers to gain workspace-admin access to victim workspaces across tenants.

## Attack Chain

1. An authenticated user gains access to the Windmill platform.
2. The user executes a malicious script within a nsjail sandbox.
3. The script leverages the lack of write restrictions on the /etc directory.
4. The script writes malicious entries to /etc/hosts to redirect hostnames.
5. Alternatively, the script writes malicious entries to /etc/resolv.conf to intercept DNS queries.
6. The script could also modify /etc/ssl/certs/ca-certificates.crt to perform HTTPS man-in-the-middle attacks.
7. The attacker intercepts WM_TOKEN JWTs used for authentication.
8. The attacker uses the stolen JWTs to gain workspace-admin access, escalating privileges and potentially compromising data across tenants.

## Impact

Successful exploitation of this vulnerability (CVE-2026-47107) could lead to significant compromise of the Windmill platform. Attackers can persistently redirect hostnames, intercept DNS queries, perform HTTPS man-in-the-middle attacks, and escalate privileges to gain workspace-admin access. The CVSS v3.1 base score for this vulnerability is 9.6, highlighting the severity. The poisoning of shared worker pods can impact multiple tenants.

## Recommendation

*   Upgrade Windmill to version 1.703.2 or later to remediate the vulnerability described in CVE-2026-47107.
*   Deploy the Sigma rule `Detect Suspicious Modification of /etc/hosts, /etc/resolv.conf, or /etc/ssl/certs/ca-certificates.crt in nsjail Sandbox` to identify potential exploitation attempts.
*   Monitor process creation events for scripts writing to sensitive files within nsjail environments, using the detection rule and tuning for your environment.
