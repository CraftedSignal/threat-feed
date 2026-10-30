---
brief_id: brief-2026-10-30-vapor-panda-artex
event_id: brief-2026-10-30-vapor-panda-artex
revision: 1
activity_at: "2026-10-30T03:01:32Z"
title: 'VAPOR PANDA: AI-Driven ARTEX Global Espionage Campaign'
slug: 2026-10-vapor-panda-artex
description: VAPOR PANDA is conducting a large-scale global espionage campaign using the AI agent framework ARTEX to automate parallel intrusions against government, defense, and technology sectors.
date: "2026-10-30T03:01:32Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - VAPOR PANDA
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - espionage
  - ai-agent
  - cloud-security
  - credential-theft
  - artex
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploited SAML, XXE
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036.005
    technique_name: Match Legitimate Name or Location
    evidence: Renamed a legitimate GameHook binary as svchost.exe
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.005
    technique_name: Cloud Instance Metadata API
    evidence: Queried the metadata service via XXE to obtain cloud role credentials
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/
iocs:
  - type: domain
    value: nginxmysql.com
  - type: domain
    value: sqlserver-sqlite.com
  - type: domain
    value: www.ddduuuppp.com
  - type: ip
    value: 45.153.126.223
  - type: ip
    value: 89.46.234.50
  - type: ip
    value: 192.121.47.20
  - type: hash_sha256
    value: 49fe70419fd19b81ca8d730a6ef7c1ec71b681d60b390761070d42686c7d2068
  - type: hash_sha256
    value: 3fb5a9fb3e2cb1d6208966bd4e55d10282d19c7250d827efa560463d60a12ee4
  - type: hash_sha256
    value: 364251838edfcf5ef1107fa692da3c5bd9a540482449f645992830134bf807ab
ioc_counts:
  domain: 3
  hash_sha256: 3
  ip: 3
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - CTI
    - Detection Engineering
  immediate_actions:
    - action: Block listed C2 domains and IPs at DNS/Firewall layers.
      owner: SOC
      due: 1h
      evidence: Source provides confirmed C2 infrastructure.
  hunt_leads:
    - lead: Search for unauthorized metadata service access attempts (e.g., requests to 169.254.169.254) from non-orchestration agents.
      technique_id: T1552.005
      data_needed:
        - Cloud Platform flow logs
        - Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Queried the metadata service via XXE
---

VAPOR PANDA has launched a global espionage campaign utilizing the AI agent framework ARTEX to manage parallel, automated intrusions against over 200 organizations worldwide. By integrating commercial LLMs and the Chinese-developed DeepSeek LLM, the adversary orchestrates complex attack chains directed by human operators. The campaign specifically targets government foreign ministries, defense, pharmaceutical, nuclear, and telecommunications sectors. A notable advancement is the inclusion of specific instructions within the AI-agent workflow to conduct environmental discovery and identify hosts lacking specific security sensors for evasion.

## Attack Chain

1. Initial Access: Exploitation of public-facing applications (SAML, XXE) and use of valid credentials via stolen VPN configurations.
2. Execution: Issuance of commands to cloud instances via systems managers and execution of payloads via hijacked DLLs.
3. Credential Access: Usage of XXE to query cloud metadata services, reading LAPS passwords, and forging SAML/mail server administrator tokens.
4. Privilege Escalation: Abuse of resource-based constrained delegation to impersonate privileged service accounts.
5. Discovery: Automated inventory of endpoint sensor coverage to guide evasion strategy.
6. Persistence: Deployment of JSP/PHP web shells on compromised servers.
7. Collection: Remote extraction of email contents from compromised mail servers.
8. Exfiltration: Traffic routing through proxies and protocol tunneling (Chisel, SoftEther).

## Impact

The campaign has impacted high-value government entities in Latin America, Europe, Asia, and the Middle East, alongside strategic industry targets in the U.S. Observed activities include unauthorized access to sensitive internal communications, mailboxes, and strategic target files for future exploitation.

## Recommendation

- Monitor for unauthorized access to cloud metadata services (e.g., 169.254.169.254) originating from unexpected internal processes.
- Audit and rotate SAML signing keys and administrative service account credentials, particularly those associated with mail server management.
- Implement strict egress filtering for known proxy and tunneling protocols such as Chisel and SoftEther.
- Review VPN configurations for anomalies and enforce multi-factor authentication (MFA) for all external remote services.
- Investigate the presence of unauthorized JSP or PHP files on web servers.
