---
title: Insufficient Session Expiration in Frauscher Sensortechnik FDS 102
slug: 2026-08-fds-session-expiration
description: CVE-2026-14950 is an insufficient session expiration vulnerability in Frauscher Sensortechnik FDS 102 that allows an attacker with a valid session identifier to maintain access beyond the intended expiration time.
date: "2026-08-20T11:11:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Frauscher Sensortechnik
products:
  - FDS 102 (2.1.0 to 2.13.3)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated remote attacker in possession of a valid session identifier is able to continue using the session after it should have expired.
    confidence_band: high
cves:
  - id: CVE-2026-14950
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14950
  - https://www.certvde.com/en/advisories/VDE-2026-078/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Frauscher Sensortechnik FDS 102 to the patched version.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-14950 remediation
---

CVE-2026-14950 identifies an insufficient session expiration flaw (CWE-613) within the web interface of the Frauscher Sensortechnik FDS 102 system, affecting versions 2.1.0 through 2.13.3. This vulnerability enables an unauthenticated attacker who has obtained a valid session identifier - potentially through interception, theft, or by leveraging an unattended machine - to continue using the session indefinitely, even after the system's expiration policy should have terminated it. This persistence mechanism allows unauthorized users to maintain an active, authenticated state, effectively bypassing standard session timeout security controls. Defenders should prioritize patching affected FDS 102 units and implement strict monitoring for anomalous session activity or unauthorized session token reuse.

## Impact

The vulnerability carries a CVSS v3.1 score of 9.8 (Critical), indicating high risk for unauthorized access and control over the affected FDS 102 interface. If exploited, an attacker gains persistent access to the management environment, potentially leading to unauthorized monitoring or configuration changes of sensitive industrial sensor systems. The vulnerability affects a critical component of industrial infrastructure management, and failure to apply available patches leaves systems open to prolonged unauthorized access.

## Recommendation

* Apply the security update provided by Frauscher Sensortechnik to all FDS 102 instances running version 2.13.3 or earlier to remediate CVE-2026-14950.
* Monitor web application logs for session tokens that persist beyond expected operational windows or show abnormal temporal patterns.
* Enforce strict session management policies, including idle timeouts and secure transport (HTTPS) to mitigate the risk of session identifier interception.
