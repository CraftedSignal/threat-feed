---
title: 'RabbitMQ: Multiple Vulnerabilities'
slug: 2026-07-rabbitmq-multiple-vulnerabilities
description: An unauthenticated, remote attacker can exploit multiple vulnerabilities in RabbitMQ to conduct denial-of-service attacks, bypass authorization and tenant boundaries, manipulate or disclose data, and perform cross-site scripting attacks.
date: "2026-07-23T10:31:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - data-exfiltration
  - web-application
  - xss
vendors:
  - Broadcom
products:
  - RabbitMQ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Cross Site Scripting Angriffe durchzuführen.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Autorisierungs- und Mandantengrenzen zu umgehen
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Daten zu manipulieren oder offenzulegen
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Server Denial of Service
    evidence: Denial-of-Service-Angriffe durchzuführen
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Daten zu manipulieren
    confidence_band: med
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2485
---

The German Federal Office for Information Security (BSI) has released an advisory concerning multiple vulnerabilities identified in RabbitMQ. A remote, unauthenticated attacker can exploit these vulnerabilities to achieve various malicious objectives. These include initiating denial-of-service attacks, circumventing established authorization and tenant boundaries within the system, manipulating or disclosing sensitive data, and executing cross-site scripting (XSS) attacks. The advisory, published on July 23, 2026, details the potential for significant impact on system availability, data integrity, and confidentiality. Organizations utilizing RabbitMQ are advised to address these vulnerabilities promptly to mitigate the risk of compromise.

## Impact

Successful exploitation of these vulnerabilities by a remote attacker could lead to severe consequences. The system's availability could be compromised through denial-of-service attacks, rendering RabbitMQ services inaccessible. Attackers could bypass authorization mechanisms, potentially gaining unauthorized access to sensitive tenant data or administrative functions. Furthermore, the integrity and confidentiality of data are at risk, with attackers capable of manipulating or disclosing information. Cross-site scripting vulnerabilities could also be leveraged to compromise user sessions or launch further attacks against administrators or users interacting with the RabbitMQ management interface.

## Recommendation

* Prioritize patching or upgrading your RabbitMQ installations to the latest secure versions as soon as they become available from Broadcom.
* Regularly review and monitor RabbitMQ application logs for any anomalies related to authorization bypass attempts, unexpected data access, or unusual service disruptions.
* Implement robust network segmentation and access controls to limit remote access to RabbitMQ instances, especially the management interface, reducing the attack surface for the vulnerabilities described in this brief.
