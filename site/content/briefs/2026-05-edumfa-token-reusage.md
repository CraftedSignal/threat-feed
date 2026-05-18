---
title: eduMFA Token Reusage Vulnerability due to Incorrect InnoDB Snapshot Isolation
slug: 2026-05-edumfa-token-reusage
description: eduMFA versions prior to 2.9.1 are vulnerable to token reusage due to incorrect InnoDB snapshot isolation in MySQL and MariaDB versions prior to 11.6.2 (or newer with innodb_snapshot_isolation=off), affecting token types such as TOTP, HOTP, and likely WebAuthN, where tokens are intended for single use, requiring racing the transaction for exploitation.
date: "2026-05-18T15:37:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - mfa
  - token reusage
vendors:
  - MariaDB
products:
  - MariaDB
  - eduMFA (< 2.9.1)
references:
  - https://github.com/advisories/GHSA-qq2p-4282-cfc5
  - https://mariadb.com/resources/blog/isolation-level-violation-testing-and-debugging-in-mariadb/
rules:
  - title: Detect MariaDB Configuration with innodb_snapshot_isolation OFF
    description: Detects MariaDB instances with innodb_snapshot_isolation explicitly set to OFF, indicating a potential vulnerability to token reusage in multi-factor authentication systems.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - config_change
      - mariadb
  - title: Detect eduMFA Request for token validation with multiple requests in short time
    description: Detects requests attempting to validate the same eduMFA token from the same IP address within a short time period, which may indicate token reusage attempts
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in eduMFA versions prior to 2.9.1 related to the handling of transaction isolation within the database layer. Specifically, when eduMFA is deployed with MySQL or MariaDB versions prior to 11.6.2 (or newer versions with `innodb_snapshot_isolation` explicitly set to OFF), it is possible for attackers to reuse token values due to faulty transaction isolation. This is because the database might not properly serialize token usage, allowing multiple requests to validate the same token before it is invalidated. The affected token types include TOTP, HOTP, and potentially WebAuthN, all of which rely on single-use tokens. Exploitation requires racing conditions. The vulnerability was addressed in eduMFA version 2.9.1.

## Attack Chain

1. User initiates a multi-factor authentication process.
2. eduMFA generates a time-based or counter-based one-time password (TOTP or HOTP).
3. The token and associated user data are written to the database.
4. Attacker initiates multiple authentication requests using the same token value in rapid succession.
5. Due to incorrect InnoDB snapshot isolation, multiple authentication requests may read the same uncommitted token value from the database before it is invalidated by the first successful authentication.
6. The database validates the token for each of the attacker's requests, as the isolation level does not prevent concurrent reads before write.
7. If the race succeeds, multiple authentication sessions are established using the same token.
8. The attacker gains unauthorized access to the user's account.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass multi-factor authentication and gain unauthorized access to user accounts. This could lead to data breaches, account compromise, and other malicious activities. The number of potentially affected users depends on the deployment size of eduMFA and the number of users relying on TOTP, HOTP or WebAuthN for authentication. Sectors that rely on eduMFA for authentication are potentially at risk.

## Recommendation

*   Upgrade eduMFA to version 2.9.1 to apply the fix that locks rows prior to write with SELECT FOR UPDATE.
*   If upgrading is not immediately feasible, set `innodb_snapshot_isolation` to ON in MariaDB configurations (default in MariaDB >= 11.6.2) as a workaround.
