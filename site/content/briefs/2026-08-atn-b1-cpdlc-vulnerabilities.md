---
title: Vulnerabilities in ATN-B1 Controller Pilot Data Link Communications (CPDLC)
slug: 2026-08-atn-b1-cpdlc-vulnerabilities
description: The ATN-B1 CPDLC protocol is susceptible to message injection and denial-of-service attacks due to reliance on unauthenticated, clear-text radio frequency communication.
date: "2026-08-07T19:48:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - Advisory Circular 90-117 Data Link Communications
  - ATN-B1 CPDLC
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Lack of authentication for Very High Frequency Data Link messages allows rogue ground stations to inject CPDLC messages.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Broadcast control frames can disconnect multiple aircraft simultaneously leading to delayed clearances.
    confidence_band: high
cves:
  - id: CVE-2025-71409
    cvss: 7.1
  - id: CVE-2025-71410
    cvss: 5.3
  - id: CVE-2025-71411
    cvss: 5.3
  - id: CVE-2025-71412
    cvss: 7.1
  - id: CVE-2025-71413
    cvss: 5.3
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-219-01
  - https://www.cve.org/CVERecord?id=CVE-2025-71409
  - https://www.cve.org/CVERecord?id=CVE-2025-71410
  - https://www.cve.org/CVERecord?id=CVE-2025-71411
  - https://www.cve.org/CVERecord?id=CVE-2025-71412
  - https://www.cve.org/CVERecord?id=CVE-2025-71413
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Monitor aviation communication logs for unusual message injection patterns.
      owner: SOC
      due: 72h
      evidence: Source document notes vulnerability to unauthorized message injection.
  mitigation_plan:
    - priority: medium_term
      action: Monitor for firmware or protocol-level patches from equipment vendors.
      owner: IT Operations
      addresses: CVE-2025-71409 through CVE-2025-71413
      evidence: Source indicates no current mitigation exists.
---

The Controller Pilot Data Link Communications (CPDLC) protocol over Aeronautical Telecommunication Network Baseline 1 (ATN-B1) contains critical design-level vulnerabilities stemming from the use of legacy, clear-text, and unauthenticated radio frequency (RF) links. Researchers identified that these flaws allow for unauthorized message injection, denial-of-service (DoS) attacks, and forced session resets. 

Specific vulnerabilities identified include:
- CVE-2025-71409: Lack of authentication allowing rogue ground station message injection.
- CVE-2025-71410: Use of unnumbered disconnect (U DISC) frames to terminate sessions.
- CVE-2025-71411: Use of broadcast control frames to disconnect multiple aircraft simultaneously.
- CVE-2025-71412: Injection of false emergency or status messages.
- CVE-2025-71413: Improper check for unusual or exceptional conditions.

While currently observed primarily in lab environments, these vulnerabilities pose a risk to aviation operational safety by delaying safety-critical instructions and increasing cognitive workload for flight crews and controllers. No mitigations are currently available for the affected protocol standards.

## Impact

Successful exploitation of these vulnerabilities can lead to the compromise of situational awareness, operational delays in air traffic management, and potential misallocation of resources due to the injection of false emergency status messages. These issues impact the global transportation sector, specifically affecting organizations relying on the ATN-B1 CPDLC protocol for pilot-controller communications.

## Recommendation

- Monitor for anomalous or unexpected CPDLC message traffic patterns within aviation communication systems.
- Establish and review internal contingency procedures for manual voice-link reversion in the event of suspected CPDLC session disruption.
- Report any suspected RF-based message injection or unsolicited session terminations to relevant national aviation authorities and CISA for correlation.
- Review the technical advisories for CVE-2025-71409, CVE-2025-71410, CVE-2025-71411, CVE-2025-71412, and CVE-2025-71413 as they become available for updates on mitigation paths.
