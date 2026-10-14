---
title: FAMOUS CHOLLIMA Laptop Farm Operations Disrupted
slug: 2026-10-famous-chollima-disruption
description: The U.S. FBI and CrowdStrike disrupted domestic laptop farms operated by the DPRK-nexus actor FAMOUS CHOLLIMA to conduct employment fraud and gain persistent access to victim organizations.
date: "2026-10-14T00:30:24Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FAMOUS CHOLLIMA
tags:
  - laptop-farm
  - employment-fraud
  - initial-access
  - insider-threat
  - dprk
---

In late September 2026, CrowdStrike's Counter Adversary Operations team collaborated with the FBI to dismantle several "laptop farms" located within the United States. These facilities were maintained by the DPRK-nexus actor FAMOUS CHOLLIMA to facilitate fraudulent remote employment at various American companies. By securing roles using stolen or synthetic identities, operatives trick organizations into shipping corporate-managed hardware to U.S.-based residential addresses controlled by the actor.

Once received, facilitators at these farms configure the devices with hardware and software, including Remote Monitoring and Management (RMM) tools, allowing remote actors in the DPRK to bypass geolocation controls and satisfy identity verification requirements. This infrastructure serves as a proxy for the actors, providing a physical presence to fulfill Know Your Client (KYC) requirements and enabling long-term persistence within victim networks. Targeted sectors include aerospace, energy, financial services, healthcare, and defense engineering. The disruption demonstrates a concerted effort to dismantle the physical U.S. infrastructure supporting these illicit revenue-generating operations.

## Attack Chain

1. Actor assumes a fraudulent or stolen identity to apply for remote positions at target organizations.
2. Actor successfully secures employment and manipulates the onboarding process to redirect corporate-issued hardware to residential "laptop farm" addresses.
3. Physical facilitators at the laptop farm receive the hardware and connect it to local power and network infrastructure.
4. Facilitators install Remote Monitoring and Management (RMM) software to grant the remote actor persistent access to the corporate device.
5. Facilitators or the actor spoof device identifiers, such as mapping video capture cards as webcams, to bypass endpoint monitoring and fraud detection.
6. Actors use the farm-hosted devices to authenticate into the victim's corporate environment, appearing to originate from domestic IP space.
7. The actor conducts daily work tasks under the fraudulent persona to receive wages while simultaneously leveraging the persistent access for broader network infiltration.
8. Illicit wages are siphoned to the regime, and the access is maintained for ongoing espionage or long-term operational goals.

## Impact

The campaign has impacted dozens of organizations across critical sectors including aerospace, energy, financial services, healthcare, cybersecurity, defense engineering, and government technology. Successful exploitation allows the actor to siphon illicit wages back to the DPRK regime while maintaining persistent, authenticated access within high-value corporate and government environments, effectively bypassing standard remote work security controls.

## Recommendation

* Implement rigorous physical address verification during the employee onboarding process to identify and flag residential addresses associated with known shipping hubs or "laptop farm" indicators.
* Monitor for the use of unauthorized RMM software and remote access tools within corporate device fleets; block or alert on the execution of tools not officially supported by IT (reference T1219).
* Analyze hardware inventory for anomalous device identifiers, such as multiple unrelated users sharing identical webcam or peripheral hardware IDs.
* Implement multi-factor authentication (MFA) that relies on hardware-bound identity verification rather than solely on IP-based geolocation, which the actor actively circumvents through farm infrastructure.
* Conduct periodic audits of remote worker geolocation and network traffic patterns to identify persistent connections originating from shared or suspicious domestic infrastructure.
