---
title: Iranian State-Sponsored Espionage Campaign Utilizing CHOSEN BRICK Spyware
slug: 2026-09-chosen-brick
description: Iranian state-sponsored actors are targeting dissidents, activists, and journalists with the CHOSEN BRICK spyware, delivered via tailored social engineering on messaging platforms to facilitate surveillance and data exfiltration.
date: "2026-09-15T19:04:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - espionage
  - spyware
  - social-engineering
  - surveillance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Iranian state actors have been observed impersonating contacts over messaging apps such as WhatsApp and Telegram, building rapport with targets before deploying CHOSEN BRICK.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The advisory warns CHOSEN BRICK is persistent and will survive a reboot of the target device.
    confidence_band: high
references:
  - https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists
  - https://www.ic3.gov/CSA/2026/260915.pdf
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Review endpoint logs for suspicious persistence entries on Windows devices associated with high-risk individuals.
      owner: SOC
      due: 24h
      evidence: The advisory warns CHOSEN BRICK is persistent and will survive a reboot of the target device.
  hunt_leads:
    - lead: Identification of anomalous file executions originating from messaging application directories or temporary folders.
      technique_id: T1566
      data_needed:
        - Sysmon Event ID 1
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Targets are tricked into downloading software enabled by spear-phishing.
---

The UK National Cyber Security Centre (NCSC), in coordination with the US FBI and the Netherlands AIVD, has identified a persistent espionage campaign by Iranian state-sponsored actors targeting dissidents, activists, and journalists globally. The primary tool of this campaign is a Windows-based spyware family dubbed CHOSEN BRICK. Actors employ highly tailored social engineering techniques, often building rapport with victims over messaging applications such as WhatsApp and Telegram, to trick them into executing the malware. The campaign is characterized by the use of contextually relevant lures, including fabricated documents such as fake medical test results. Once deployed, CHOSEN BRICK establishes persistence and provides the attackers with comprehensive surveillance capabilities, including exfiltration of emails, contact lists, and social media communications, as well as real-time monitoring through screen captures and microphone access. The exfiltrated data is subsequently leveraged to intimidate targets, with sensitive information appearing on public leak sites.

## Attack Chain

1. Initial contact is established with the target via encrypted messaging platforms like WhatsApp or Telegram by actors masquerading as known associates.
2. Attackers engage in prolonged social engineering to build rapport, often utilizing highly specific, relevant lures such as fake MRI test results to gain the victim's trust.
3. The target is persuaded to download and execute the payload, masquerading as a legitimate file or document.
4. CHOSEN BRICK executes on the Windows endpoint and modifies system configuration to ensure persistence across reboots.
5. The malware initiates a callback to attacker-controlled infrastructure to receive commands and establish C2.
6. The spyware performs internal reconnaissance and harvests sensitive data, including emails, contacts, and social media messaging history.
7. CHOSEN BRICK enables unauthorized remote monitoring through background screen capture and active microphone recording.
8. Stolen data is exfiltrated to the attackers, who subsequently publish sensitive information on pro-regime leak sites to maximize intimidation.

## Impact

The campaign focuses on the transnational repression of critics of the Iranian regime. Targets include journalists, activists, and dissidents worldwide, including those based in the UK. The primary consequences include severe privacy loss, physical safety risks due to the public exposure of private communications on leak sites, and sustained psychological intimidation. The use of stolen data for public shaming serves as a mechanism to silence opposition and deter further dissent.

## Recommendation

1. Deploy endpoint detection capabilities to identify unauthorized persistence mechanisms as described in the CHOSEN BRICK technical analysis (refer to the FBI report https://www.ic3.gov/CSA/2026/260915.pdf).
2. Implement strict organizational policies regarding the download and execution of unsolicited files sent via messaging platforms, even from seemingly known contacts.
3. Conduct security awareness training for high-risk individuals focusing on the recognition of sophisticated, tailored social engineering lures.
4. Review and monitor for anomalous data egress patterns that align with exfiltration TTPs observed in the campaign.
5. Encourage high-risk individuals to sign up for government-provided cyber defense services and follow the specific mitigation advice published in the joint NCSC/FBI/AIVD advisory.
