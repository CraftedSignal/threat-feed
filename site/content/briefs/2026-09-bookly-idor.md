---
title: IDOR Vulnerability in Bookly WordPress Plugin
slug: 2026-09-bookly-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability in the Bookly WordPress plugin allows unauthenticated attackers to enumerate and exfiltrate private AI booking transcripts via sequential ID incrementation.
date: "2026-09-16T05:46:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bookly:bookly:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - idor
  - cve-2026-89063
vendors:
  - Bookly
products:
  - Bookly (<= 28.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can enumerate all customer conversations simply by incrementing the conversation_id parameter.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to read the full AI booking conversation transcript of any customer.
    confidence_band: high
cves:
  - id: CVE-2026-89063
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89063
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Bookly plugin to a version > 28.1
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-89063 remediation
  hunt_leads:
    - lead: High-volume sequential requests to conversation_id parameter
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker can enumerate all customer conversations simply by incrementing the conversation_id parameter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Bookly plugin beyond 28.1
      owner: IT Operations
      addresses: CVE-2026-89063
      evidence: CVE-2026-89063 advisory
---

The Bookly WordPress plugin, specifically versions 28.1 and earlier, contains an Insecure Direct Object Reference (IDOR) vulnerability identified as CVE-2026-89063. The vulnerability stems from the 'conversation_id' parameter in the plugin's AI booking functionality, which fails to enforce access control or validate that the requesting user owns the requested conversation session. Because the conversation IDs are assigned as sequential integers, an unauthenticated attacker can systematically enumerate these values to access sensitive customer data stored in AI booking transcripts, including names, email addresses, phone numbers, and appointment details. Beyond data exfiltration, the flaw permits attackers to inject arbitrary messages into active or historical conversations, which are then processed by the cloud AI worker. This capability creates a significant risk for unauthorized access to customer interactions and data leakage across any WordPress site running the affected plugin versions.

## Impact

Successful exploitation allows unauthenticated actors to harvest PII for all scheduled appointments and manipulate interactions with the AI assistant. This presents a severe privacy risk to organizations using the plugin for scheduling, potentially leading to unauthorized data exposure and the compromise of automated customer service workflows.

## Recommendation

Prioritized actions for security and IT teams:
- Update the Bookly plugin for WordPress to the latest available version beyond 28.1 to mitigate CVE-2026-89063.
- Audit web server access logs for anomalous, high-frequency GET or POST requests directed at the Bookly conversation API endpoint involving incrementing integer parameters in the 'conversation_id' field.
- Monitor for unauthorized access patterns where a single IP address requests a broad range of sequential conversation IDs, which is a strong indicator of enumeration attempts against this IDOR vulnerability.
