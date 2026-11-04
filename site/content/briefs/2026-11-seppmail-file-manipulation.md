---
brief_id: brief-2026-11-04-seppmail-file-manipulation
event_id: brief-2026-11-04-seppmail-file-manipulation
revision: 1
activity_at: "2026-11-04T12:00:43Z"
title: 'SEPPmail Secure Email Gateway: Arbitrary file manipulation via Large File Transfer (CVE-2026-114425)'
slug: 2026-11-seppmail-file-manipulation
description: SEPPmail Secure Email Gateway versions prior to 15.1.1 are vulnerable to arbitrary file read, move, or delete operations due to improper validation of metadata in Large File Transfer attachments.
date: "2026-11-04T12:00:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified information regarding CVE-2026-114425 and product versioning.
cpes:
  - cpe:2.3:a:seppmail:secure_email_gateway:*:*:*:*:*:*:*:*
vendors:
  - SEPPmail
products:
  - Secure Email Gateway (< 15.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote sender can cause the mail-processing worker to disclose, move, or delete an accessible regular file.
    confidence_band: high
cves:
  - id: CVE-2026-114425
    kev_status: "false"
references:
  - https://docs.seppmail.com/en/20_revision-history.html
  - https://sploitus.com/exploit?id=CVE-2026-114425
  - https://sploitus.com/exploit?id=CVE-2026-114425&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch SEPPmail Secure Email Gateway to 15.1.1
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory documentation regarding version 15.1.1 fix for CVE-2026-114425
  hunt_leads:
    - lead: Monitor mail-processing logs for file operation errors or access patterns targeting sensitive system directories
      technique_id: T1083
      data_needed:
        - SEPPmail application logs
        - System-level file access audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows an unauthenticated remote sender to read, move, or delete an accessible regular file.
  mitigation_plan:
    - priority: immediate
      action: Disable Large File Transfer (LFT) feature
      owner: IT Operations
      addresses: CVE-2026-114425
      evidence: The vulnerability is triggered by metadata in Large File Transfer attachments.
---

SEPPmail Secure Email Gateway versions before 15.1.1 are susceptible to unauthenticated arbitrary file read, move, or delete attacks. The vulnerability exists within the Large File Transfer (LFT) feature, which incorrectly trusts externally provided file path metadata. Attackers can leverage this to manipulate files processed by the mail-worker, which executes with root privileges. This vulnerability is identified as CVE-2026-114425.

## Impact

Successful exploitation allows an unauthenticated remote attacker to read, move, or delete arbitrary files on the system with root-level privileges, potentially leading to full system compromise or information disclosure of sensitive email data.

## Recommendation

- Upgrade SEPPmail Secure Email Gateway to version 15.1.1 or later immediately.
- If patching is not immediately feasible, disable the Large File Transfer (LFT) feature on internet-facing SEPPmail gateways until the update can be applied.
- Audit system logs for unexpected file deletions or access attempts targeting critical system configuration files.
