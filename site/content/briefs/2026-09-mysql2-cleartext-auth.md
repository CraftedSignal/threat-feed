---
title: MySQL2 Auth Plugin Downgrade Vulnerability
slug: 2026-09-mysql2-cleartext-auth
description: The mysql2 Node.js database driver is vulnerable to credential theft because it does not enforce TLS before executing a requested authentication switch to the mysql_clear_password plugin.
date: "2026-09-01T18:00:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - vulnerability
  - nodejs
products:
  - mysql2 (< 3.22.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: A rogue MySQL server (or MITM) can force mysql2 to send credentials in plaintext by requesting an auth switch to mysql_clear_password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3f6p-5ww8-9rcr
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade mysql2 dependency to 3.22.0 or later across all applications.
      owner: Application Security
      due: 48h
      evidence: Source advisory specifies mysql2 < 3.22.0 as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade mysql2 to 3.22.0 or later.
      owner: IT Operations
      addresses: mysql2 < 3.22.0
      evidence: Source advisory provides version 3.22.0 as the fix.
---

The mysql2 package for Node.js is susceptible to credential interception due to insecure implementation of the mysql_clear_password authentication plugin. When a client connects to a server, the authentication process is managed by a list of standard plugins. An attacker operating a rogue MySQL server or performing a man-in-the-middle (MITM) attack can issue an AuthSwitchRequest (0xFE) to downgrade the authentication method to mysql_clear_password. Unlike other plugins, such as caching_sha2_password, the mysql2 driver fails to verify if a secure TLS connection is established before transmitting the password in plaintext. This flaw affects all versions of mysql2 prior to 3.22.0. With approximately 9 million weekly downloads, this vulnerability poses a significant risk to applications in environments where network traffic is not fully encrypted, particularly those traversing untrusted or internal network segments.

## Attack Chain

1. Attacker establishes a rogue MySQL server or performs a MITM position between the application and the legitimate database.
2. The mysql2 client initiates a connection to the database.
3. The rogue server responds with an initial handshake advertising support for caching_sha2_password.
4. The client sends a hashed authentication response as expected by the protocol.
5. The rogue server ignores the response and issues an AuthSwitchRequest (0xFE) command.
6. The AuthSwitchRequest specifically requests the mysql_clear_password authentication plugin.
7. The mysql2 driver, failing to check for an active SSL/TLS layer, invokes the mysql_clear_password plugin.
8. The driver transmits the plaintext database password to the rogue server, where the attacker captures it.

## Impact

The vulnerability results in the exposure of database credentials in plaintext. This impacts any application using mysql2 (< 3.22.0) that has not explicitly enforced TLS connections for all database communications. Given the library's high volume of weekly downloads (9 million), this poses a systemic risk to enterprise applications, particularly in cloud-native environments where network paths between services may be intercepted or spoofed.

## Recommendation

- Upgrade the mysql2 package to version 3.22.0 or later immediately to include the mandatory TLS check for authentication plugins.
- Enforce SSL/TLS connections for all database configurations within the application code to prevent unauthorized downgrades.
- Audit network egress traffic from application servers to identify unexpected connections to database ports (default 3306) targeting unauthorized infrastructure.
- Implement network-level segmentation and mutual TLS (mTLS) for database communications to mitigate the impact of rogue or compromised database nodes.
