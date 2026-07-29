---
title: Authentication Bypass in AMMOS Instrument Toolkit GUI
slug: 2026-07-ait-auth-bypass
description: The AMMOS Instrument Toolkit (AIT) GUI before version 2.5.1 allows unauthenticated attackers to bypass credential checks to establish sessions and issue arbitrary spacecraft commands.
date: "2026-07-29T16:20:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - cve-2026-60112
  - critical-infrastructure
vendors:
  - NASA
products:
  - AMMOS Instrument Toolkit (AIT) GUI (< 2.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AMMOS Instrument Toolkit (AIT) GUI before 2.5.1 contains a missing authentication vulnerability that allows any unauthenticated network attacker to obtain a valid session
    confidence_band: high
cves:
  - id: CVE-2026-60112
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60112
---

The AMMOS Instrument Toolkit (AIT) GUI, used for spacecraft command and control, contains a critical authentication vulnerability (CVE-2026-60112) affecting versions prior to 2.5.1. The flaw exists within the Sessions.create() method, which fails to enforce credential validation during session initiation. An unauthenticated network attacker can leverage this failure to establish a valid user session. Once authenticated, the attacker can interact with the handle_cmd() function, which lacks internal security checks, allowing the injection of arbitrary commands directly into the AIT command bus. This vulnerability poses a severe risk to mission-critical infrastructure, as it grants unauthorized remote control over spacecraft operations without requiring valid user authentication or authorization tokens.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable instances of the AIT GUI.
2. Attacker initiates an unauthenticated connection request to the AIT web interface.
3. Attacker triggers the vulnerable Sessions.create() method without providing valid credentials.
4. The application generates and returns a valid session token due to missing validation logic.
5. Attacker utilizes the assigned session token to access privileged application endpoints.
6. Attacker calls the handle_cmd() function with malicious command parameters.
7. The application forwards the injected commands directly to the command bus.
8. Unauthorized commands are executed by the target system or downstream spacecraft hardware.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full command-line control over the AIT command bus. This permits unauthorized execution of arbitrary spacecraft commands, potentially leading to mission degradation, loss of control over satellite instruments, or permanent hardware damage. Any organization utilizing versions of AIT GUI earlier than 2.5.1 in network-exposed environments is at immediate risk.

## Recommendation

1. Upgrade to AIT GUI version 2.5.1 or later immediately to patch the missing authentication logic in Sessions.create().
2. Restrict network access to the AIT GUI interface to trusted management networks only, preventing exposure to untrusted segments.
3. Audit web server and application logs for anomalous POST requests to the session creation endpoints that do not correspond to known valid login attempts.
