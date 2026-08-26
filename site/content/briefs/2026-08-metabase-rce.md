---
title: Critical Pre-Authentication RCE in Metabase (CVE-2023-38646)
slug: 2026-08-metabase-rce
description: A critical pre-authentication Remote Code Execution vulnerability in Metabase allows unauthenticated attackers to execute arbitrary system commands via malicious H2 database connection strings.
date: "2026-08-26T09:03:48Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:metabase:metabase:*:*:*:*:-:*:*:*
  - cpe:2.3:a:metabase:metabase:*:*:*:*:enterprise:*:*:*
vendors:
  - Metabase
products:
  - Metabase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can supply a malicious payload to the /api/setup/validate endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The exploit leverages H2 database trigger injection, where a specially crafted connection string can cause the application to execute system commands via Java's Runtime.getRuntime().exec() method.
    confidence_band: high
cves:
  - id: CVE-2023-38646
    cvss: 9.8
    epss: 0.98677
references:
  - https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0UTL4NDER-ANOTHER-METABASE-RCE-CVE-2023-38646
rules:
  - title: Detects CVE-2023-38646 Exploitation - H2 Database Trigger Injection
    description: Detects exploitation attempts against CVE-2023-38646 by monitoring for suspicious H2 driver configuration patterns in POST requests to the setup validation endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
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
    - action: Upgrade all Metabase instances to patched versions.
      owner: IT Operations
      due: 24h
      evidence: CVE-2023-38646 mitigation requirements.
  hunt_leads:
    - lead: Search logs for POST requests to /api/setup/validate
      technique_id: T1190
      data_needed:
        - Webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Endpoint used to trigger RCE.
---

CVE-2023-38646 is a critical vulnerability affecting multiple versions of Metabase (prior to 0.43.7.2, 1.43.7.2, 0.44.7.1, 1.44.7.1, 0.45.4.1, 1.45.4.1, 0.46.6.1, and 1.46.6.1). This vulnerability exists within the setup validation process, specifically in the `/api/setup/validate` endpoint. An unauthenticated attacker can supply a specially crafted JSON payload that includes a malicious H2 database connection string. Due to improper input validation and handling of the `subname` parameter, the application is forced to execute system-level commands through the H2 database engine's driver functionality. The recent publication of multiple functional proof-of-concept exploits significantly lowers the barrier for exploitation, making immediate remediation essential for any internet-exposed Metabase instance.

## Attack Chain

1. Attacker identifies an internet-facing Metabase server.
2. Attacker sends a crafted POST request to the `/api/setup/validate` endpoint.
3. The request includes a JSON body with a `details` object containing a malicious `subname` parameter.
4. The `subname` parameter is configured to use the `org.h2.Driver` class with a path containing a malicious SQL `CREATE TRIGGER` statement.
5. The Metabase application processes the payload, triggering the H2 database driver to initialize the malicious connection string.
6. The `CREATE TRIGGER` statement executes on the backend, invoking Java's `Runtime.getRuntime().exec()` method.
7. The attacker-specified shell command (e.g., base64 encoded bash command) executes on the underlying operating system.
8. Successful execution leads to full application or host compromise, potentially allowing for persistent access or further exfiltration.

## Impact

Successful exploitation of CVE-2023-38646 grants an attacker full remote code execution privileges with the context of the Metabase application. This exposes the organization to complete data exfiltration, service disruption, and potential lateral movement into the internal network where the database instance is hosted. With a CVSS score of 9.8, the impact includes full loss of confidentiality, integrity, and availability.

## Recommendation

* Immediately upgrade Metabase to the latest patched version (>= 0.43.7.2, 1.43.7.2, 0.44.7.1, 1.44.7.1, 0.45.4.1, 1.45.4.1, 0.46.6.1, or 1.46.6.1).
* Monitor webserver logs for unauthorized POST requests to `/api/setup/validate` containing strings indicative of H2 driver initialization or SQL trigger keywords (e.g., `CREATE TRIGGER`, `org.h2.Driver`, `RUNSCRIPT`).
* Restrict network access to the Metabase management interface, ensuring it is not accessible from the public internet.
* Deploy the provided Sigma rule to detect exploitation attempts at the webserver level.
