---
title: Remote Code Execution in Netflix Genie via Malicious Library Upload
slug: 2026-10-netflix-genie-rce
description: CVE-2024-4701 is a critical remote code execution vulnerability in Netflix Genie 4.3.0, enabling attackers to execute arbitrary code by uploading a malicious shared library that triggers upon container login.
date: "2026-10-15T18:04:05Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:netflix:genie:4.3.0:*:*:*:*:*:*:*
vendors:
  - Netflix
products:
  - Genie (4.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability is exploited by uploading a malicious shared library via the application's file upload functionality.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The malicious library is subsequently executed when a user logs into the Genie application container.
    confidence_band: high
cves:
  - id: CVE-2024-4701
    cvss: 9.9
    epss: 0.24629
references:
  - https://netflix.github.io/genie/docs/4.3.0/demo/docker-compose.yml
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-JOEBEETON-CVE-2024-4701-POC
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to Genie administrative endpoints
      owner: SOC
      due: 24h
      evidence: High CVSS 9.9 RCE vulnerability in public-facing application
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch Netflix Genie 4.3.0
      owner: IT Operations
      addresses: CVE-2024-4701
      evidence: PoC confirmed for version 4.3.0
---

Netflix Genie version 4.3.0 is affected by a critical remote code execution (RCE) vulnerability, tracked as CVE-2024-4701. The vulnerability stems from an insecure file upload mechanism that permits the placement of malicious shared library files within the application's environment. Attackers can leverage this flaw to upload custom shared objects (.so files) and auxiliary configuration files. The execution is deferred until a user performs an interactive login into the Genie application container, at which point the application environment processes the uploaded library. This vulnerability carries a CVSS score of 9.9, and a publicly available proof-of-concept (PoC) exploit confirms the ease of execution. Defenders should prioritize patching or restricting access to the Genie administrative interface, as successful exploitation results in full code execution within the container context.

## Attack Chain

1. The attacker identifies the Genie administrative interface on the network.
2. The attacker prepares a malicious payload consisting of a shared library (e.g., pe.so) and associated upload manifest files.
3. The attacker performs an unauthorized HTTP POST request to the Genie file upload endpoint, transmitting the malicious binary.
4. The Genie application stores the malicious files within the containerized file system.
5. The attacker or an administrator initiates an interactive session into the container using the 'docker exec' command.
6. The Genie application environment, during the user authentication or login process, dynamically loads the malicious library.
7. The arbitrary code within the library executes with the privileges of the Genie process.
8. The attacker achieves persistence or objective completion, evidenced in the PoC by writing command output to the /tmp directory.

## Impact

Successful exploitation of CVE-2024-4701 allows an attacker to achieve remote code execution on the underlying container. This facilitates full system compromise, data exfiltration, and potential lateral movement within the containerized environment. Given the 9.9 CVSS rating and the availability of a functional PoC, organizations deploying Netflix Genie 4.3.0 face a high risk of active exploitation.

## Recommendation

* Immediately restrict network access to the Genie management API and administrative interfaces to trusted management subnets only.
* Monitor file integrity within the Genie container environment, specifically looking for new .so or binary files appearing in application directories.
* Audit all active docker containers for unexpected 'docker exec' sessions.
* Upgrade Netflix Genie to a version beyond 4.3.0 or apply vendor-supplied patches as they become available to remediate the insecure upload vector.
