---
title: Russian State-Backed 'LAUNDRY BEAR' Exploits Zimbra Zero-Click Vulnerability
slug: 2026-07-russian-laundry-bear-zimbra-zero-click
description: The Russian state-supported threat group LAUNDRY BEAR is exploiting a zero-click vulnerability, dubbed 'beehive,' in the Zimbra Collaboration Suite (ZCS) webmail service, actively stealing sensitive emails and gaining persistent access to compromised networks since July 2025 by merely viewing a malicious email, with Western organizations across various sectors being targeted.
date: "2026-07-23T14:41:39Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - LAUNDRY BEAR
tags:
  - phishing
  - zero-click
  - espionage
  - state-sponsored
  - zimbra
  - email-theft
vendors:
  - Zimbra
products:
  - Zimbra Collaboration Suite (ZCS)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Russian state-supported cyber actors have targeted Western organisations with a malicious campaign which uses a zero-click exploit coined “beehive” (or “Ulej”) to steal emails, the UK has warned. ... Unlike traditional phishing campaigns, “beehive” allows the threat actors to gain extensive and sustained access to emails without requiring a user’s input. Instead of clicking a link or opening a file, the user only has to view a malicious email within a vulnerable version of the ZCS webmail service to be compromised.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
    evidence: Since July 2025, LAUNDRY BEAR has successfully targeted and stolen sensitive email information from organisations that use Zimbra Collaboration Suite (ZCS) software.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Russian state-supported actors develop new technique to target Western email platforms and gain persistent access to compromised networks.
    confidence_band: high
references:
  - https://www.ncsc.gov.uk/news/uk-and-partners-expose-russian-state-supported-actors-for-new-zero-click-phishing-campaign
  - https://media.defense.gov/2026/Jul/22/2003965244/-1/-1/1/CSA_RUSSIA_PHISHING_TARGET_ZIMBRA.PDF
---

GCHQ’s National Cyber Security Centre (NCSC) and international partners have exposed LAUNDRY BEAR, a Russian state-supported advanced persistent threat (APT) group, for an ongoing zero-click phishing campaign. Active since July 2025, this campaign leverages a previously unknown exploit, internally dubbed "beehive" (or "Ulej"), targeting vulnerable versions of Zimbra Collaboration Suite (ZCS) webmail services. Unlike traditional phishing, the "beehive" exploit allows the attackers to gain extensive and sustained access to sensitive email information and compromised networks without any user interaction beyond viewing a malicious email. The campaign, which was initially trialed on Ukrainian victims, has subsequently targeted numerous Western organizations across sectors including defence, government, education, energy, law enforcement, media, NGOs, and technology, indicating an espionage objective to covertly acquire email data. The use of Artificial Intelligence in developing the codebase for this operation has also been noted.

## Attack Chain

1. The LAUNDRY BEAR threat group, with Russian state support, sends a specially crafted malicious email to a target organization using a vulnerable Zimbra Collaboration Suite (ZCS) instance.
2. A user within the target organization views the malicious email in their ZCS webmail client.
3. Upon viewing, the "beehive" zero-click exploit is automatically triggered within the vulnerable ZCS software, requiring no further user interaction (e.g., clicking a link or opening an attachment).
4. The exploit grants the attackers extensive and sustained access to the target user's email account.
5. Attackers proceed to steal sensitive email information from the compromised account.
6. The threat actors establish persistent access to the compromised email system or broader network, facilitating long-term espionage activities.

## Impact

The LAUNDRY BEAR campaign has resulted in the successful theft of sensitive email information and persistent access to compromised networks for espionage purposes. Since July 2025, organizations utilizing Zimbra Collaboration Suite (ZCS) have been targeted, with specific victim sectors in the US including defence, government, education, energy, law enforcement, media, NGOs, and technology. The techniques were first observed being tested on Ukrainian victims before being deployed against NATO member countries. A successful attack can lead to the exfiltration of confidential communications, intellectual property, and other critical data, posing significant national security and economic risks.

## Recommendation

* Immediately patch all Zimbra Collaboration Suite (ZCS) installations to the latest secure version to remediate the "beehive" zero-click vulnerability.
* Enhance network monitoring capabilities for anomalous activity originating from or destined for Zimbra Collaboration Suite (ZCS) components.
* Organizations should refer to the advisories from NCSC (https://www.ncsc.gov.uk/news/uk-and-partners-expose-russian-state-supported-actors-for-new-zero-click-phishing-campaign) and NSA (https://media.defense.gov/2026/Jul/22/2003965244/-1/-1/1/CSA_RUSSIA_PHISHING_TARGET_ZIMBRA.PDF) for comprehensive mitigation advice.
* Strengthen online account security practices, including multi-factor authentication, across all enterprise applications.
