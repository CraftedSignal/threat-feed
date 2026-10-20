---
brief_id: brief-2026-10-suspicious-lsass-access
event_id: brief-2026-10-suspicious-lsass-access
revision: 1
activity_at: "2026-10-05T12:01:54Z"
title: Potentially Suspicious LSASS Access Flags
slug: 2026-10-suspicious-lsass-access
description: Monitoring for unusual process access requests to the Local Security Authority Subsystem Service (LSASS) using specific GrantedAccess flags, a common indicator of credential dumping attempts.
date: "2026-10-05T12:01:54Z"
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
  validation_status: needs_environment_validation
tags:
  - credential-access
  - windows
  - lsass
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: Detects process access requests to LSASS process with potentially suspicious access flags
    confidence_band: high
rules:
  - title: Detect Potentially Suspicious LSASS Access Flags
    description: Detects process access requests to LSASS with access flags commonly associated with credential dumping tools.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_access
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon Event ID 10 and deploy provided Sigma rule
      owner: Detection Engineering
      due: 48h
      evidence: Source SIGMA-HQ repository
  hunt_leads:
    - lead: Identify processes with abnormal GrantedAccess flags targeting lsass.exe
      technique_id: T1003.001
      data_needed:
        - ProcessAccess events (Event ID 10)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Observed tool-based credential dumping techniques
  mitigation_plan:
    - priority: medium
      action: Apply least-privilege principles to service accounts accessing LSASS
      owner: IT Operations
      addresses: Credential access
      evidence: Standard security hardening
---

This brief details the detection of suspicious process access requests targeting the Windows Local Security Authority Subsystem Service (LSASS) process. LSASS is responsible for enforcing security policies and handling user authentication, making it a primary target for credential dumping activities by threat actors. Attackers often attempt to read the memory of lsass.exe to extract cleartext passwords, NTLM hashes, or Kerberos tickets. 

Defenders can identify these attempts by monitoring Windows Event ID 10 (ProcessAccess), which logs requests for process handles. Specific hex-encoded access flags, such as 0x1f0fff or 0x14C2, are frequently associated with tool-based memory dumping. Because security software, administrative tools, and system processes legitimately access LSASS, establishing a robust baseline of expected behavior is critical. This detection logic identifies potential credential theft attempts by filtering out common, well-known benign processes and emphasizing non-standard access rights.

## Impact

Successful unauthorized access to LSASS memory allows attackers to harvest credentials from the system. If successful, this can lead to lateral movement, privilege escalation, and persistent access to the broader enterprise environment, effectively compromising the integrity of the authentication chain.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for unauthorized process access to LSASS.
* Tune the detection by identifying and adding internal administrative tools or specialized security software to the exclusion filters.
* Investigate any detected alerts by reviewing the 'SourceImage' and 'GrantedAccess' values to determine if the activity originates from known, trusted security agents or unauthorized binaries.
* Ensure Sysmon (Event ID 10) or equivalent process access auditing is enabled on all critical endpoints and domain-joined machines.
