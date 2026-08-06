---
title: Critical Path Traversal and RCE in Dinky
slug: 2026-08-dinky-path-traversal
description: Dinky v1.2.5 contains a path traversal vulnerability in the /download/uploadFromRsByLocal endpoint, which is protected by a hardcoded authentication token, allowing unauthenticated attackers to achieve arbitrary file write and remote code execution.
date: "2026-08-06T23:29:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Dinky
products:
  - Dinky (1.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The route is marked @SaIgnore and /download/** is excluded from the Sa-Token interceptor, so the only guard is a header equality check against a dinkyToken value.
    confidence_band: high
cves:
  - id: CVE-2026-70558
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70558
rules:
  - title: Detect CVE-2026-70558 Exploitation - Unauthorized POST to Upload Handler
    description: Detects potential exploitation attempts by monitoring requests to the vulnerable upload endpoint that utilize the known hardcoded authentication token.
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
    - action: Restrict access to the Dinky HTTP port (8888) to known internal IP addresses only
      owner: IT Operations
      due: 24h
      evidence: The endpoint is exposed to any user who can reach the HTTP port.
  mitigation_plan:
    - priority: immediate
      action: Change the default Dinky token if the software configuration allows, or restrict access via WAF/Network segmentation
      owner: IT Operations
      addresses: CVE-2026-70558
      evidence: The default hardcoded token facilitates unauthenticated access.
---

Dinky v1.2.5 is vulnerable to a critical path traversal and arbitrary file write vulnerability within the POST /download/uploadFromRsByLocal handler. The application fails to validate the caller-supplied path parameter before passing it to Java file operations, allowing an attacker to write files outside of the intended directory. While the endpoint is intended to be secured, it is excluded from the application's primary authentication interceptor. Security relies solely on a header equality check against a 'dinkyToken' header. This token is hardcoded in the source code as 'efda1551-7958-4e0f-80a8-dfd107df3e38' and is identical across all deployments.

Attackers who reach the application's HTTP port (default 8888) can supply this hardcoded token to bypass access controls. Given that default installations often run with excessive write permissions in the /opt/dinky directory, this vulnerability allows for remote code execution by overwriting application classpath files or static assets, facilitating persistent access and browser-based attacks against administrators.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain code execution as the Dinky service account (typically uid 9999). Observed impact includes the modification of static assets to execute JavaScript in administrative sessions and the overwriting of compiled Java classes within the application's classpath to execute arbitrary code upon JVM restart. This affects all deployments of Dinky v1.2.5 and the current development branch.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized access attempts or suspicious file write operations.
* Update Dinky to a patched version once released to remediate the hardcoded token and path validation flaws.
* Audit and restrict file system permissions for the Dinky service account to prevent modification of application-critical files and directories.
* Block inbound traffic to the Dinky HTTP port from untrusted networks and ensure that management interfaces are not exposed to the public internet.
