---
brief_id: brief-2026-10-22-aide-bypass
event_id: brief-2026-10-22-aide-bypass
revision: 1
activity_at: "2026-10-22T19:57:47Z"
title: 'AIDE: Integrity check bypass via invalid UTF-8 filenames'
slug: 2026-10-aide-bypass
description: AIDE versions 0.16 through 0.19.4 fail to process filenames containing invalid UTF-8 sequences, allowing local attackers to hide malicious files from integrity monitoring.
date: "2026-10-22T19:57:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - integrity-bypass
  - detection-evasion
  - security-tooling
vendors:
  - AIDE
products:
  - AIDE (0.16 - 0.19.4)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.001
    subtechnique_name: Disable or Modify Tools
    evidence: An attacker can craft a malicious file or directory name by including invalid UTF-8 bytes so that the file/directory is silently ignored by AIDE.
    confidence_band: high
references:
  - https://seclists.org/oss-sec/2026/q4/306
action_plan:
  priority: elevated
  owners:
    - SOC
    - System Administration
  immediate_actions:
    - action: Inventory systems running AIDE versions 0.16 to 0.19.4
      owner: System Administration
      due: 48h
      evidence: Vulnerability affects AIDE versions 0.16 through 0.19.4
  hunt_leads:
    - lead: Identify files or directories with invalid UTF-8 characters in names
      technique_id: T1562.001
      data_needed:
        - Filesystem metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers use invalid UTF-8 byte sequences to bypass AIDE
  mitigation_plan:
    - priority: medium
      action: Upgrade to patched version of AIDE when released
      owner: System Administration
      addresses: AIDE integrity bypass
      evidence: Fix will resolve improper handling of invalid UTF-8 sequences
---

AIDE (Advanced Intrusion Detection Environment) contains a vulnerability where filenames containing invalid UTF-8 byte sequences are silently ignored during integrity checks. This vulnerability affects versions 0.16 through 0.19.4. A local attacker can leverage this behavior to conceal files or directories from AIDE, effectively bypassing the system integrity monitor.

## Impact
An attacker with local file system access can create directories or files using invalid UTF-8 encoding to prevent detection by AIDE. This allows the concealment of unauthorized scripts, payloads, or modified system files, undermining the integrity of the host monitoring solution.

## Recommendation
- Upgrade to a version of AIDE that includes a fix for invalid UTF-8 filename handling once released by the maintainers.
- Audit existing AIDE databases for files that may be intentionally hidden using non-UTF-8 characters in filenames.
- Monitor local filesystem events for the creation of files with non-standard or invalid encoding patterns in sensitive directories.
