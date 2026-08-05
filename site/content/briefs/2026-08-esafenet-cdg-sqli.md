---
title: SQL Injection in ESAFENET CDG
slug: 2026-08-esafenet-cdg-sqli
description: A publicly exploitable SQL injection vulnerability in ESAFENET CDG allows unauthenticated remote attackers to execute arbitrary database queries via the keyid parameter.
date: "2026-08-05T02:04:14Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-application-vulnerability
  - sqli
  - remote-code-execution
vendors:
  - ESAFENET
products:
  - CDG (20260615 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Such manipulation of the argument keyid leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-18859
    cvss: 7.3
rules:
  - title: Detect CVE-2026-18859 Exploitation - SQL Injection via keyid
    description: Detects exploitation attempts against the ESAFENET CDG endpoint by looking for common SQL injection markers in the keyid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rule to block requests containing SQL injection strings to the vulnerable endpoint.
      owner: SOC
      due: 24h
      evidence: Public exploit available for CVE-2026-18859.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the CDG server.
      owner: IT Operations
      addresses: CVE-2026-18859
      evidence: Publicly available exploit code for a remote SQL injection.
---

A high-severity SQL injection vulnerability has been identified in ESAFENET CDG software, affecting versions up to 20260615. The flaw is located within an undisclosed function of the file /CDGServer3/ukey/usbkey;logindojojs. An unauthenticated, remote attacker can manipulate the keyid argument to inject malicious SQL commands, potentially resulting in unauthorized data access or modification. Publicly available exploit code exists, increasing the risk of active exploitation. The vendor has not yet released a patch or responded to disclosure efforts. Defenders should treat this as an immediate risk to any exposed CDG server deployments.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing ESAFENET CDG servers.
2. Attacker crafts an HTTP GET or POST request targeting the /CDGServer3/ukey/usbkey;logindojojs endpoint.
3. Attacker injects malicious SQL syntax into the keyid parameter, bypassing input sanitization.
4. The web server process passes the unsanitized parameter to the backend database engine.
5. The database executes the injected commands within the context of the service account.
6. Attacker extracts sensitive data from the underlying database or modifies application records to maintain persistence or escalate privileges.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain unauthorized access to data stored within the CDG database. Depending on the database configuration, this may result in complete data exfiltration, modification, or potential lateral movement within the network. This vulnerability poses a significant risk to organizations using CDG for sensitive document or data protection.

## Recommendation

Prioritize the identification of all internet-facing ESAFENET CDG installations. Given the lack of a vendor patch, implement strict perimeter filtering to restrict access to the /CDGServer3/ukey/usbkey;logindojojs path. Deploy WAF rules to inspect and block incoming HTTP requests containing SQL injection patterns in the keyid parameter. Monitor web server access logs for anomalous requests to the identified vulnerable endpoint.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2026-18859
- https://vuldb.com/cve/CVE-2026-18859
