---
title: CVE-2026-84823 WildFly Path Traversal Information Disclosure
slug: 2026-10-wildfly-path-traversal
description: An authenticated user with the Monitor role in WildFly can exploit a path traversal vulnerability in the take-snapshot operation to perform unauthorized reads of sensitive configuration files.
date: "2026-10-16T02:41:35Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jboss:wildfly:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - credential-access
vendors:
  - JBoss
products:
  - WildFly
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This allows the Monitor role to read back the server configuration, including sensitive credentials, which would otherwise be restricted by RBAC, leading to information disclosure.
    confidence_band: high
cves:
  - id: CVE-2026-84823
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84823
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Monitor management API logs for take-snapshot operations involving path traversal patterns
      owner: SOC
      due: 24h
      evidence: Source describes vulnerability in take-snapshot operation
  mitigation_plan:
    - priority: immediate
      action: Upgrade WildFly to the latest version once the vendor release containing the fix for CVE-2026-84823 is available
      owner: IT Operations
      addresses: CVE-2026-84823
      evidence: NVD vulnerability reporting
---

A path traversal vulnerability exists in WildFly, identified as CVE-2026-84823. The vulnerability originates within the take-snapshot management operation. While the Monitor role is intended as a low-privileged, read-only RBAC assignment, a user holding this role can manipulate the name parameter during the snapshot process. By providing a path traversal payload as the value for this parameter, an attacker can coerce the application to write a copy of the server configuration to an arbitrary location on the underlying filesystem. This enables the attacker to subsequently access files that should be protected by standard RBAC restrictions. Successfully exploiting this flaw results in the disclosure of sensitive server configuration data, which may include plaintext credentials, service tokens, or system integration secrets.

## Attack Chain

1. Attacker authenticates to the WildFly management interface using legitimate credentials for a user account assigned the Monitor role.
2. Attacker identifies the take-snapshot management operation exposed via the JBoss Management API.
3. Attacker crafts a malicious HTTP request targeting the take-snapshot endpoint.
4. Attacker inserts path traversal characters (e.g., ../../../) into the 'name' parameter of the request body.
5. The application server processes the input and writes the current server configuration file to the attacker-defined target location.
6. Attacker accesses the newly created or overwritten file to retrieve contents that contain sensitive system credentials.
7. Attacker parses the retrieved configuration file to extract administrative secrets for further escalation or lateral movement.

## Impact

Successful exploitation leads to unauthorized information disclosure, specifically the compromise of sensitive credentials stored within WildFly configuration files. This allows a low-privileged user to bypass RBAC protections, potentially leading to full administrative compromise of the application server or surrounding infrastructure if sensitive credentials (e.g., database passwords, LDAP bind credentials) are recovered.

## Recommendation

* Review existing WildFly management interface logs for unauthorized or unexpected requests to the take-snapshot operation.
* Audit current RBAC assignments to ensure the Monitor role is only assigned to authorized personnel.
* Monitor file integrity on the application server, specifically focusing on the creation of new files in sensitive directories that match the naming conventions of server configuration snapshots.
* Apply the security patch for CVE-2026-84823 provided by the vendor immediately upon release.
