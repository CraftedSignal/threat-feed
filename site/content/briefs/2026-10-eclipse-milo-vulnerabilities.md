---
title: Multiple Critical Vulnerabilities in Eclipse Milo OPC UA Implementation
slug: 2026-10-eclipse-milo-vulnerabilities
description: Multiple high-severity vulnerabilities in Eclipse Milo, including improper authorization and memory management flaws, allow unauthenticated remote attackers to bypass access controls, delete protected nodes, or crash services.
date: "2026-10-15T17:00:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:eclipse:milo:*:*:*:*:*:*:*:*
tags:
  - ics
  - opc-ua
  - denial-of-service
  - broken-access-control
vendors:
  - Eclipse Foundation
products:
  - Eclipse Milo (>=0.6.0, <=1.1.4)
  - Eclipse Milo (>=1.0.0, <=1.1.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Vulnerability
    evidence: An anonymous or otherwise low-privileged client to execute a denied method by batching it with an allowed method.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: allowing a remote unauthenticated client to exhaust pooled direct memory by repeatedly sending incomplete chunks and disconnecting, potentially terminating the server.
    confidence_band: high
cves:
  - id: CVE-2026-58080
    cvss: 8.2
    epss: 0.00378
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-01
  - https://www.cve.org/CVERecord?id=CVE-2026-62927
  - https://www.cve.org/CVERecord?id=CVE-2026-63252
  - https://www.cve.org/CVERecord?id=CVE-2026-58080
  - https://www.cve.org/CVERecord?id=CVE-2026-63248
  - https://github.com/eclipse-milo/milo/releases/tag/v1.1.5
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - OT Security
  immediate_actions:
    - action: Upgrade Eclipse Milo to version 1.1.5
      owner: IT Operations
      due: 48h
      evidence: Vendor fix provided by Eclipse Foundation
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to OPC UA server endpoints via firewall
      owner: Network Security
      addresses: CVE-2026-62927, CVE-2026-63252, CVE-2026-58080
      evidence: Source advisory
---

The Eclipse Foundation has disclosed multiple critical vulnerabilities affecting the Eclipse Milo OPC UA stack, specifically versions 0.6.0 through 1.1.4. These flaws span authorization logic, memory management, and configuration handling. The most severe vulnerabilities, such as CVE-2026-58080 and CVE-2026-62927, allow unauthenticated remote attackers to bypass role-based access control, invoke protected methods, or manipulate protected nodes. Other issues, such as CVE-2026-63252, facilitate remote denial-of-service (DoS) attacks via memory exhaustion in UASC server transport handlers.

These vulnerabilities pose a significant risk to industrial control systems (ICS) and critical infrastructure, including the energy, manufacturing, and water sectors. Successful exploitation can lead to unauthorized data access, credential recovery, user impersonation, and total service disruption. Defenders should prioritize migrating affected instances to Eclipse Milo 1.1.5, as no patches are available for the 0.6.x branch.

## Impact

Successful exploitation of these vulnerabilities allows unauthenticated remote attackers to compromise the integrity and availability of OPC UA servers. Potential impacts include the permanent deletion of protected data, extraction of sensitive credentials and session metadata, impersonation of authorized users, and the ability to cause complete server failure (DoS). These vulnerabilities are particularly critical in industrial environments where Milo is used for communication between supervisory systems and field devices.

## Recommendation

* Upgrade all deployments of Eclipse Milo to version 1.1.5 immediately, as no security updates are provided for the 0.6.x branch.
* Identify and audit all OPC UA server configurations that rely on role-based access control (RBAC), specifically checking if `OpcUaServerConfig.copy()` is used, as this is vulnerable to CVE-2026-58080.
* Restrict network access to OPC UA endpoints to only known, trusted client IP addresses to mitigate remote unauthenticated exploitation attempts.
* Implement monitoring for abnormal service crashes or frequent channel disconnects, which may indicate exploitation of the memory exhaustion vulnerability (CVE-2026-63252).
