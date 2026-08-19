---
title: Privilege Escalation in Splunk AI Toolkit via Agent Run History
slug: 2026-08-splunk-ai-toolkit-privesc
description: A privilege escalation vulnerability in Splunk AI Toolkit versions prior to 6.0.0 allows non-privileged users to execute searches with system-level permissions by exploiting an insecure session token replacement mechanism in the Agent Run History handler.
date: "2026-08-19T22:44:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Splunk
products:
  - AI Toolkit (< 6.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a user who does not hold the admin or power Splunk roles could run searches with system-level privileges
    confidence_band: high
cves:
  - id: CVE-2026-76391
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76391
  - https://help.splunk.com/en/splunk-enterprise/apply-machine-learning/use-ai-toolkit/6.0.0/ai-toolkit-connections-containers-and-agents/ai-toolkit-agent-launchpad
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Splunk AI Toolkit to version 6.0.0 or higher
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76391 remediation requires version 6.0.0
---

Splunk AI Toolkit versions below 6.0.0 contain a privilege escalation vulnerability (CVE-2026-76391) that allows users without administrative or power user roles to execute searches with system-level privileges. The issue stems from the Agent Run History handler, which incorrectly replaces the user's session key with a system authentication token before initiating search operations. This flaw permits unauthorized users to access restricted data, modify system integrity, and manage search jobs belonging to other users. Defenders should identify instances of the AI Toolkit within their environment and upgrade to version 6.0.0 or higher to remediate the insecure authentication handling.

## Impact

Successful exploitation allows a low-privileged user to bypass access controls and perform operations with system-level authorization. This results in unauthorized data exfiltration, the ability to view or delete sensitive search jobs of other users, and potential compromise of system integrity within the Splunk environment.

## Recommendation

- Upgrade all Splunk AI Toolkit installations to version 6.0.0 or higher immediately.
- Audit logs for the Agent Run History handler to identify searches initiated by users without appropriate administrative privileges.
- Review permissions for all users assigned to the AI Toolkit to minimize exposure while the patch is being applied.
- Apply the vendor-recommended security patch documented in the Splunk AI Toolkit release notes for version 6.0.0.
