---
title: Privilege Escalation in Pardus LightDM Greeter via Incorrect Permissions
slug: 2026-09-pardus-lightdm-vuln
description: An incorrect permission assignment vulnerability in the Pardus LightDM Greeter component, tracked as CVE-2026-79617, allows local attackers to exploit access control misconfigurations for privilege escalation.
date: "2026-09-09T16:58:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:tubitak:pardus_lightdm_greeter:*:*:*:*:*:*:*:*
vendors:
  - TÜBİTAK BİLGEM
products:
  - Pardus LightDM Greeter (< 0.4.15)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Incorrect Permission Assignment for Critical Resource vulnerability in TÜBİTAK BİLGEM Software Technologies Research Institute Pardus LightDM Greeter allows Exploiting Incorrectly Configured Access Control Security Levels.
    confidence_band: high
cves:
  - id: CVE-2026-79617
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79617
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Pardus LightDM Greeter to version 0.4.15
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-79617 patch availability
  mitigation_plan:
    - priority: immediate
      action: Patch Pardus LightDM Greeter to 0.4.15
      owner: IT Operations
      addresses: CVE-2026-79617
      evidence: NVD vulnerability details
---

The Pardus LightDM Greeter, a component developed by the TÜBİTAK BİLGEM Software Technologies Research Institute, contains an incorrect permission assignment vulnerability identified as CVE-2026-79617. This flaw stems from improperly configured access control security levels within the greeter process. An attacker with local access to the system can exploit this misconfiguration to bypass intended security constraints, potentially resulting in unauthorized privilege escalation. The vulnerability affects all versions of the Pardus LightDM Greeter prior to 0.4.15. Defenders should prioritize updating the greeter component to the patched version, as unauthorized access to the login interface context can provide a vector for further system compromise.

## Impact

The vulnerability poses a significant risk to host systems running the affected Pardus LightDM Greeter, as successful exploitation enables local privilege escalation. This could allow an unprivileged local user to gain higher-level permissions, compromising the integrity and confidentiality of the host operating system. Organizations utilizing Pardus Linux distributions where this specific greeter component is active are at risk if they remain on versions earlier than 0.4.15.

## Recommendation

- Upgrade the Pardus LightDM Greeter component to version 0.4.15 or later immediately.
- Audit local system access logs for unauthorized attempts to interact with or restart the LightDM service.
- Review access control lists on critical system configuration files associated with the greeter process.
