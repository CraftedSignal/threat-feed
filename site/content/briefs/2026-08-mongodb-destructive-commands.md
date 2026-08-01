---
title: Detection of Destructive MongoDB Commands
slug: 2026-08-mongodb-destructive-commands
description: Detection logic for identifying first-time client IP addresses issuing destructive MongoDB administrative commands often used in wipe-and-extort data destruction campaigns.
date: "2026-08-01T01:42:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - impact
  - network
  - mongodb
vendors:
  - MongoDB
products:
  - MongoDB
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries with access to an exposed or compromised MongoDB service may use these commands to destroy data, disrupt applications, or prepare a wipe-and-extort attack.
    confidence_band: high
references:
  - https://www.bleepingcomputer.com/news/security/mongo-lock-attack-ransoming-deleted-mongodb-databases/
  - https://flare.io/learn/resources/blog/mongodb-ransom
  - https://attack.mitre.org/techniques/T1485/
rules:
  - title: First-Time Destructive MongoDB Command from a Client IP
    description: Detects the first client IP observed issuing MongoDB commands capable of dropping databases, collections, or security configurations, which may indicate data destruction or extortion attempts.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - network_connection
rules_count: 1
---

This brief covers the detection of destructive administrative commands within MongoDB network traffic. Threat actors targeting exposed or compromised MongoDB instances often perform reconnaissance followed by the execution of commands designed to destroy data, drop indexes, or purge identity and access management configurations. These operations are frequently precursors to extortion or data disruption. Defenders must monitor for unauthorized or unusual client IP addresses attempting these destructive operations, as they are indicators of active compromise or unauthorized service manipulation.

This detection focuses on identifying the first instance of a client IP address issuing specific destructive MongoDB commands over a five-day observation window, helping to filter out established, authorized maintenance activity while flagging new, suspicious entities performing destructive database operations.

## Attack Chain

1. Attacker performs network scanning to identify exposed MongoDB instances reachable over the internet or internal network.
2. Attacker establishes a connection to the MongoDB service and attempts authentication or exploits unauthenticated instance vulnerabilities.
3. Attacker performs reconnaissance by querying for databases, collections, and user/role information (e.g., listDatabases, listCollections, usersInfo).
4. Attacker issues destructive commands to remove existing databases, collections, or indexes to disrupt operations.
5. Attacker executes commands to purge users or roles, effectively locking out legitimate administrators.
6. Attacker inserts a ransom note or indicator of extortion into the database (e.g., strings like "bitcoin", "README", "RECOVER").
7. Attacker exfiltrates or deletes remaining data to finalize the wipe-and-extort objective.

## Impact

Successful exploitation leads to unauthorized data destruction, application service disruption, and potential extortion. If an attacker gains sufficient privileges to execute destructive commands, the targeted organization may face significant data loss, downtime, and operational degradation. MongoDB wipe-and-extort attacks are known for high-velocity automated data destruction across both single instances and clusters.

## Recommendation

- Deploy network monitoring tools capable of decapsulating and inspecting MongoDB protocol traffic.
- Establish baseline activity for database administrators and automation services to reduce noise from the rule.
- Configure alerts for any client IP address performing first-time destructive actions as defined in the provided detection rule.
- Enforce strict network access control lists (ACLs) to ensure only authorized application and management hosts can communicate with MongoDB instances.
- Maintain offline, immutable backups and ensure restoration procedures are verified to recover from potential data destruction events.
