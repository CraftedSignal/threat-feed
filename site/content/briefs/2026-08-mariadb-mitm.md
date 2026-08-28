---
title: MariaDB Node.js Connector Credential Disclosure via MitM
slug: 2026-08-mariadb-mitm
description: The MariaDB connector for Node.js (CVE-2026-55215) inadvertently sends database credentials during the handshake process before server identity is validated, enabling cleartext credential theft by an active man-in-the-middle.
date: "2026-08-28T21:14:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*
tags:
  - credential-theft
  - vulnerability
  - npm
  - nodejs
vendors:
  - MariaDB
products:
  - mariadb (< 3.2.4)
  - mariadb (3.3.0 – 3.3.2)
  - mariadb (3.4.0 – 3.4.5)
  - mariadb (3.5.0 – 3.5.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: An active man-in-the-middle (MitM) attacker can capture the account password during the handshake.
    confidence_band: high
cves:
  - id: CVE-2026-55215
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-cqhc-2h57-wpxf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55215
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade npm/mariadb to fixed versions 3.2.4, 3.3.3, 3.4.6, or 3.5.3.
      owner: IT Operations
      due: 48h
      evidence: Fixed in 3.2.4, 3.3.3, 3.4.6, and 3.5.3.
  mitigation_plan:
    - priority: immediate
      action: Configure certificate verification to VERIFY_CA or VERIFY_FULL.
      owner: Application Security
      addresses: CVE-2026-55215
      evidence: Use a verifying SSL mode (e.g. VERIFY_CA / VERIFY_FULL).
---

The MariaDB connector for Node.js contains a high-severity vulnerability (CVE-2026-55215) where database credentials are transmitted in cleartext to an untrusted peer during the initial handshake. This occurs when SSL/TLS is enabled but the client is not configured to explicitly verify the server's certificate or CA. Under these conditions, the connector performs authentication before completing the identity validation check. While the connection eventually terminates due to a failed fingerprint validation, the damage occurs during the handshake when an active man-in-the-middle (MitM) attacker can capture the credentials by presenting any certificate to the client. This vulnerability affects multiple versions across the 3.x release branch. Organizations using the affected MariaDB npm package are at risk of credential exposure if network-level attackers can position themselves on the path between the application and the database server.

## Impact

Successful exploitation leads to the disclosure of database credentials, allowing an attacker to gain unauthorized access to the backend MariaDB instance. The impact is significant as it provides persistent access to sensitive data stored within the database. The scope includes any application environment using the vulnerable npm package where SSL/TLS is enabled without strict certificate validation (e.g., using default configurations or incomplete SSL settings).

## Recommendation

1. Upgrade the MariaDB npm package to the patched versions: 3.2.4, 3.3.3, 3.4.6, or 3.5.3.
2. If patching is not immediately feasible, configure certificate verification explicitly in the connection settings.
3. Ensure the application provides the appropriate CA or server certificate and enforces `VERIFY_CA` or `VERIFY_FULL` modes to ensure identity validation occurs before authentication credentials are transmitted.
