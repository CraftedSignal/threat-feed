---
title: Oracle Database SQL Injection Leads to OS-Level RCE and khunt Toolkit Deployment
slug: 2026-08-oracle-sql-injection
description: A threat actor exploited SQL injection in a public-facing application to achieve OS-level remote code execution by abusing Oracle Java Source to deploy the custom 'khunt' post-exploitation toolkit.
date: "2026-08-18T20:51:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - remote-code-execution
  - khunt
  - oracle
  - credential-theft
vendors:
  - Oracle
products:
  - Oracle Database
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attacker had managed to make copies of several registry hives (SAM, SECURITY, SYSTEM)... determined that this attack was the result of a SQL injection (SQLi) attack.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabled malicious functionalities like running OS commands
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: attempting to exfiltrate SAM, SECURITY, and SYSTEM registry hives
    confidence_band: high
iocs:
  - type: ip
    value: 178.162.151.229
ioc_counts:
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block 178.162.151.229 at firewall
      owner: SOC
      due: 24h
      evidence: Identified attacker IP address
  hunt_leads:
    - lead: Search Oracle audit logs for 'CREATE JAVA SOURCE' or 'KHUNT%'
      technique_id: T1190
      data_needed:
        - Oracle database audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Huntress advisory indicates use of these specific strings
  mitigation_plan:
    - priority: immediate
      action: Review and sanitize web application SQL inputs
      owner: IT Operations
      addresses: SQL Injection
      evidence: SQL injection cited as root cause
---

On July 27, 2026, researchers observed a sophisticated attack chain targeting an organization's Oracle Database server. The attackers leveraged a SQL injection vulnerability in a public-facing web application to execute malicious commands within the database engine. A novel component of this attack involved the abuse of the 'CREATE JAVA SOURCE' functionality, which permits the storage and execution of Java code directly as database schema objects. The attackers utilized this mechanism to drop and compile a custom post-exploitation toolkit dubbed 'khunt'. The toolkit, which included modules such as 'khuntCmd' and 'khuntHash', enabled the threat actor to execute arbitrary operating system commands, write data to local files, and facilitate the collection of sensitive Windows system information. This attack highlights the persistent risk of traditional SQL injection when combined with database-native code execution features.

## Attack Chain

1. An attacker identifies a SQL injection vulnerability in a public-facing web application connected to an Oracle Database.
2. The attacker uses the injection vector to execute administrative SQL commands within the database engine.
3. The attacker utilizes the 'CREATE JAVA SOURCE' feature to inject custom Java code into the database schema as a stored object.
4. The database engine compiles the injected Java source into a malicious utility, specifically the 'khunt' toolkit components (e.g., khuntCmd).
5. The attacker invokes the stored Java object via SQL to execute arbitrary commands at the OS level on the database host.
6. The 'khunt' toolkit is used to interact with the Windows filesystem, specifically writing task lists and interacting with registry hive files.
7. The attacker targets the SAM, SECURITY, and SYSTEM registry hives to dump credentials for offline analysis.
8. Final objectives include exfiltrating these registry hives to an external, attacker-controlled server (178.162.151.229).

## Impact

The successful deployment of the 'khunt' toolkit granted the attacker OS-level remote code execution on the database host. This enabled the unauthorized access and exfiltration of critical Windows registry hives, potentially leading to total credential compromise and further lateral movement within the victim environment. The use of legitimate database features to hide malicious logic presents a significant detection challenge.

## Recommendation

* Deploy Sigma rules to monitor for unauthorized 'CREATE JAVA SOURCE' commands or the presence of suspicious Java source objects in Oracle databases.
* Block the identified attacker IP 178.162.151.229 at the network perimeter and egress points.
* Audit Oracle database logs for the execution of Java objects, specifically monitoring for instances containing the string 'KHUNT%'.
* Implement strict input validation on all web applications interfacing with database backends to prevent SQL injection.
* Restrict database service account permissions on the underlying host OS to prevent them from accessing sensitive files like registry hives (SAM, SYSTEM, SECURITY).
