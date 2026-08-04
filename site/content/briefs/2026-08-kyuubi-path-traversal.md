---
title: Unauthenticated Arbitrary File Write in Apache Kyuubi REST API
slug: 2026-08-kyuubi-path-traversal
description: An unauthenticated path-traversal vulnerability in the Apache Kyuubi REST API (CVE-2026-52680) allows remote attackers to write arbitrary files to the filesystem, leading to remote code execution.
date: "2026-08-04T13:42:57Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Apache
products:
  - Apache Kyuubi (1.7.0 - 1.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated arbitrary file write in Apache Kyuubi's REST API via the multipart batch-submission endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: A login shell then sources /etc/profile.d/*.sh and executes the payload.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=1D1C4050-7D40-5B6E-819C-42E0C48EDB48
rules:
  - title: Detect CVE-2026-52680 Exploitation Attempt - Path Traversal in REST API
    description: Detects exploitation attempts against the Apache Kyuubi REST API by identifying POST requests to the batch endpoint containing directory traversal characters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to Kyuubi REST API on port 10099
      owner: IT Operations
      due: 2h
      evidence: Unauthenticated REST API is vulnerable by design
    - action: Deploy detection rule for path traversal patterns on the REST API
      owner: Detection Engineering
      due: 24h
      evidence: Public PoC exploit is available
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Apache Kyuubi 1.12.0 or higher
      owner: IT Operations
      addresses: CVE-2026-52680
      evidence: Vendor fix in version 1.12.0
---

Apache Kyuubi versions 1.7.0 through 1.11.1 contain an unauthenticated arbitrary file write vulnerability (CVE-2026-52680) in the REST API's batch submission endpoint. The flaw exists in the `Utils.writeToTempFile` method within `kyuubi-common`, which fails to sanitize the user-supplied filename during multipart form uploads. An attacker can craft a `POST` request to `/api/v1/batches` containing a filename with path-traversal sequences (e.g., `../`). While the application mangles the basename by appending a suffix, attackers can target directories such as `/etc/profile.d/` to drop scripts that are automatically sourced by login shells. This vulnerability is particularly dangerous when Kyuubi is configured with `kyuubi.authentication=NONE`, which is the default setting. The exploit allows code execution as the user running the Kyuubi process, which could result in full system compromise if Kyuubi is incorrectly running with root privileges.

## Attack Chain

1. Attacker performs reconnaissance to identify Apache Kyuubi REST interfaces reachable on TCP port 10099.
2. Attacker verifies the target is unauthenticated by sending a `GET` request to `/api/v1/ping`.
3. Attacker constructs a multipart `POST` request to `/api/v1/batches`.
4. The request includes a `batchRequest` JSON payload and a `resourceFile` multipart part.
5. The `resourceFile` uses a path-traversal filename (e.g., `../../../../../../etc/profile.d/pwn.sh`) to escape the target directory.
6. The Kyuubi process writes the malicious payload to the filesystem (e.g., `/etc/profile.d/pwn--.sh`).
7. A user (or scheduled task) initiates a login shell, triggering the system to source the malicious script in `/etc/profile.d/`.
8. The payload executes within the context of the user opening the shell, achieving remote code execution.

## Impact

The vulnerability allows unauthenticated attackers to achieve remote code execution on the host server. The impact is significant for organizations running Kyuubi in exposed environments, as it enables full server compromise if the Kyuubi process operates with elevated privileges.

## Recommendation

* Upgrade all instances of Apache Kyuubi to version 1.12.0 or later immediately to incorporate proper path normalization.
* Enable authentication by setting `kyuubi.authentication` to a secure mechanism (e.g., KERBEROS, LDAP, or PAM) instead of the default `NONE`.
* Ensure the Kyuubi service runs with the least privilege possible; never run the service as root.
* Restrict access to the Kyuubi REST gateway (default port 10099) using network firewalls or VPNs to prevent public or untrusted network exposure.
* Monitor webserver access logs for anomalous `POST` requests to `/api/v1/batches` that contain directory traversal patterns.
