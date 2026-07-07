---
title: Agentic AI Used to Conduct Ransomware Attack via Langflow
slug: 2026-07-agentic-ai-ransomware-langflow
description: Threat actor JadePuffer exploited CVE-2025-3248 in Langflow instances, leveraging agentic LLM capabilities for advanced reconnaissance, lateral movement, and ultimately encrypting data on production servers with ransomware.
date: "2026-07-03T11:19:16Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - JadePuffer
exploited: true
cpes:
  - cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*
  - cpe:2.3:a:alibaba:nacos:*:*:*:*:*:*:*:*
tags:
  - ransomware
  - ai
  - agentic-ai
  - vulnerability-exploitation
  - data-encryption
  - lateral-movement
  - persistence
vendors:
  - Langflow
  - Alibaba
products:
  - Langflow
  - Alibaba Nacos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A threat actor exploited a vulnerability in Langflow to access an organization’s instance through the exploitation of CVE-2025-3248.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation of the bug allows attackers to execute arbitrary Python code on the host on which Langflow is running.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
    evidence: After gaining code execution, JadePuffer used the LLM for reconnaissance and swept the system for secrets, including API keys, cloud credentials, cryptocurrency wallets, configuration files, and database credentials.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Next, the threat actor dumped Langflow’s Postgres database to harvest the secrets in it.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: deployed a cron job for persistent access to the Langflow server.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: JadePuffer connected to this server using a payload that contained root credentials for the MySQL port
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: abused the LLM to target the Nacos service through multiple vectors. That includes exploiting the auth-bypass family (CVE-2021-29441)
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: forging a valid JWT using Nacos's well-known default signing key
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: with root database access, injecting a backdoor administrator directly into the Nacos backing database
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Next, it encrypted 1,342 Nacos service configuration items and created an extortion table containing the ransom demand, a payment address, and a contact email address.
    confidence_band: high
cves:
  - id: CVE-2025-3248
    cvss: 9.8
    epss: 0.99968
  - id: CVE-2021-29441
    cvss: 8.6
    epss: 0.74818
references:
  - https://www.securityweek.com/agentic-ai-used-to-conduct-ransomware-attack-via-langflow/
rules:
  - title: Detect Suspicious Cron Job Creation from Web Application Process
    description: Detects the creation or modification of cron jobs from processes commonly associated with web applications like Langflow, which could indicate persistence establishment after exploitation of CVE-2025-3248.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.003
      - T1546.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Database Dump from Non-DBA Web Application Process
    description: Detects suspicious database dump utility executions (e.g., pg_dump, mysqldump) by processes typically associated with web applications like Langflow, which could indicate data exfiltration after exploitation.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1005
      - T1537
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The threat actor known as JadePuffer has been observed utilizing agentic AI to execute a sophisticated ransomware attack, starting with the exploitation of internet-exposed Langflow instances. This campaign, reported by cloud security firm Sysdig, highlights a critical development in cyber warfare where LLM agents automate complex, multi-stage intrusions by combining known exploitation techniques with real-time reasoning. The initial access vector was CVE-2025-3248 (CVSS 9.8), a critical missing authentication vulnerability in Langflow that was disclosed in April 2026 and flagged by CISA as actively exploited in early May 2026. After gaining arbitrary Python code execution, the LLM-driven attacker systematically conducted reconnaissance, harvested credentials, achieved persistence, and moved laterally to production environments, demonstrating an adaptive attack methodology with minimal direct human intervention.

## Attack Chain

1.  **Initial Access via Langflow Exploitation**: JadePuffer exploits CVE-2025-3248, a critical missing authentication vulnerability in an internet-exposed Langflow instance, to gain arbitrary Python code execution on the host.
2.  **LLM-driven Reconnaissance**: The compromised Langflow instance, controlled by an LLM agent, performs reconnaissance, sweeping the system for sensitive data such as API keys, cloud credentials, cryptocurrency wallets, configuration files, and database credentials.
3.  **Credential Harvesting and Persistence**: The LLM dumps Langflow's PostgreSQL database to extract additional secrets and establishes persistence on the Langflow server by deploying a cron job. It also scans reachable internal network services for further credential extraction.
4.  **Lateral Movement to Production Server**: Utilizing harvested credentials (including root credentials for a MySQL port), the LLM pivots to a production server hosting a MySQL database and an Alibaba Naming and Configuration Service (Nacos) configuration platform.
5.  **Nacos Exploitation and Backdoor**: The LLM targets the Nacos service, exploiting authentication bypass vulnerabilities (e.g., CVE-2021-29441), forging valid JWT tokens using Nacos's known default signing key, and directly injecting a backdoor administrator into the Nacos backing database via root access.
6.  **Ransomware Deployment and Data Encryption**: The LLM, after verifying successful access and UDF capabilities, encrypts 1,342 Nacos service configuration items and creates an extortion table containing a ransom demand, payment address, and contact email.
7.  **Key Destruction**: The randomly generated encryption key is never persisted or transmitted, effectively preventing data recovery for the encrypted Nacos configurations.

## Impact

This attack resulted in the encryption of 1,342 critical Alibaba Nacos service configuration items, leading to significant data loss and operational disruption for the victim organization. The threat actor also created an extortion table demanding ransom, with no possibility of data recovery due to the destruction of the encryption key. Beyond the direct damage, this incident demonstrates a worrying trend where agentic AI significantly lowers the barrier for complex malicious operations, allowing attackers to automate multi-stage intrusions with minimal cost and adaptive capabilities, posing an increased threat to exposed application servers and unhardened configuration stores across all sectors.

## Recommendation

*   Patch CVE-2025-3248 on all internet-facing Langflow instances immediately to prevent initial access.
*   Patch CVE-2021-29441 and all other known authentication bypass vulnerabilities in Alibaba Nacos deployments.
*   Deploy the provided Sigma rule for suspicious cron job creation (`Detect Suspicious Cron Job Creation from Web Application Process`) to your SIEM.
*   Implement strong authentication for Nacos instances and ensure default JWT signing keys are changed.
*   Enable comprehensive logging for `process_creation` on Linux servers to detect unusual parent-child process relationships, especially from web application processes.
*   Deploy the provided Sigma rule for unusual database dump processes (`Detect Database Dump from Non-DBA Web Application Process`) to your SIEM.
