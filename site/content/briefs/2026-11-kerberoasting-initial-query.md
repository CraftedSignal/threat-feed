---
brief_id: brief-2026-11-10-kerberoasting-initial-query
event_id: brief-2026-11-10-kerberoasting-initial-query
revision: 1
activity_at: "2026-11-10T06:40:44Z"
title: Kerberoasting Activity Identification
slug: 2026-11-kerberoasting-initial-query
description: This brief provides a detection baseline for identifying potential Kerberoasting activity by monitoring for RC4-encrypted service ticket requests in Windows security logs.
date: "2026-11-10T06:40:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection rule logic derived from SigmaHQ repository
tags:
  - credential-access
  - kerberos
  - windows
  - security-monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    subtechnique_id: T1558.003
    subtechnique_name: Kerberoasting
    evidence: The rule is designed to detect the request for service tickets using RC4 encryption, which is the hallmark of the Kerberoasting technique.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_kerberoasting_activity.yml
  - https://www.trustedsec.com/blog/art_of_kerberoast/
  - https://adsecurity.org/?p=3513
  - https://en.hackita.it/articoli/kerberoasting/
rules:
  - title: Detect Kerberoasting Activity via Event 4769
    description: Detects potentially malicious Kerberoasting activity by identifying RC4-encrypted service ticket requests (Event ID 4769), excluding standard machine account and krbtgt traffic.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1558.003
    data_sources:
      - security
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable logging for Kerberos Service Ticket Operations on Domain Controllers
      owner: IT Operations
      due: 48h
      evidence: Required for Event ID 4769 collection
    - action: Deploy Sigma rule for Kerberoasting activity
      owner: Detection Engineering
      due: 72h
      evidence: Detects RC4 service ticket requests
  hunt_leads:
    - lead: Identify high-frequency Event ID 4769 events for a single source IP targeting multiple unique service names within a short window
      technique_id: T1558.003
      data_needed:
        - Event ID 4769 (Source Address, TargetUserName, ServiceName, TicketEncryptionType)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes indicate need for threshold-based alerting
---

Kerberoasting is an attack technique where an actor requests service tickets (TGS) for service accounts from a Domain Controller and attempts to crack the service ticket offline to recover the account password. This rule monitors Windows Event ID 4769 to identify requests using RC4 encryption (0x17), which is a common indicator of Kerberoasting, while filtering out known benign activity such as machine account authentication and requests for the krbtgt service. This rule serves as a base for behavior-based detection and should be combined with threshold analysis to identify anomalous request patterns.

## Recommendation
- Deploy the provided Sigma rule to your SIEM to monitor for Kerberoasting activity.
- Establish a baseline of normal service ticket request volume for your environment.
- Implement alert thresholds to trigger on high volumes of 4769 events with RC4 encryption (0x17) originating from a single source within a 5-second window.
- Filter out legacy applications that require RC4 encryption to prevent false positives.
