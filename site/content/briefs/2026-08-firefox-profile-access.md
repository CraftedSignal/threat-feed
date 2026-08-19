---
title: Unauthorized Access to Firefox Profile Directory
slug: 2026-08-firefox-profile-access
description: This detection identifies non-Firefox processes attempting to access sensitive user data stored within the Firefox profile directory, a common technique utilized by information-stealing malware to harvest credentials and browser history.
date: "2026-08-19T22:27:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - infostealer
vendors:
  - Mozilla
products:
  - Firefox
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Password Stores
    evidence: The following analytic detects non-Firefox processes accessing the Firefox profile directory, which contains sensitive user data such as login credentials, browsing history, and cookies.
    confidence_band: high
rules:
  - title: Detect Unauthorized Access to Firefox Profile
    description: Detects non-Firefox processes accessing files within the Firefox profile directory, potentially indicating credential harvesting by malware.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Object Access for user profile directories on high-value endpoints.
      owner: IT Operations
      due: 72h
      evidence: Source document implementation guide.
  hunt_leads:
    - lead: Search for non-browser process activity in AppData\Roaming\Mozilla\Firefox\Profiles.
      technique_id: T1555.003
      data_needed:
        - Windows Event ID 4663
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source description of T1555.003 analytic.
---

The Firefox profile directory stores sensitive user information, including login credentials, browsing cookies, and session history. This directory is a primary target for various information-stealing malware (infostealers) and Remote Access Trojans (RATs) seeking to harvest data for downstream exfiltration or account takeover. Defenders should monitor for access to these sensitive paths by processes other than the legitimate Firefox executable. This detection logic leverages Windows Security Event ID 4663, requiring the "Audit Object Access" policy to be enabled on Windows endpoints. Monitoring this activity is critical for detecting early-stage data harvesting attempts by a wide array of malware families, including RedLine Stealer, AgentTesla, Vidar, and various RATs.

## Attack Chain

1. Initial infection (e.g., via phishing, malicious download, or secondary payload deployment).
2. Malware achieves persistence on the target Windows system.
3. Malware enumerates local file systems to locate the Firefox profile path (typically under AppData\Roaming\Mozilla\Firefox\Profiles).
4. The malicious process attempts to open or read files (cookies, logins.json, key4.db) within the profile directory.
5. The Windows Security subsystem generates Event ID 4663 (An attempt was made to access an object) due to the enabled Object Access auditing.
6. The security logging engine records the access attempt, attributing it to the non-Firefox process.
7. If successful, the malware exfiltrates the harvested credentials and session tokens to a remote C2 server.

## Impact

Successful exploitation leads to the theft of stored credentials, session tokens, and browsing history. This exposure significantly increases the risk of unauthorized account access, identity theft, and potential further compromise of the internal environment by the threat actor.

## Recommendation

- Enable "Audit Object Access" in Windows Group Policy to capture Event ID 4663 on critical workstations.
- Deploy the provided Sigma rule (or equivalent SIEM logic) to alert on processes accessing the Firefox profile path that are not 'firefox.exe' or other trusted system processes.
- Review and tune the exclusion list in the detection logic to account for legitimate security tools or backup applications that may legitimately interact with user profile directories.
- Investigate alerts triggered by this rule to determine if the originating process is legitimate software or an unauthorized infostealer.
