---
title: 3CX DesktopApp Supply Chain Attack
slug: 2026-10-3cx-supply-chain
description: The 3CX supply chain attack involved the distribution of trojanized software updates to facilitate unauthorized network access and potential data exfiltration.
date: "2026-10-05T12:30:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:3cx:3cx:18.11.1213:*:*:*:*:macos:*:*
  - cpe:2.3:a:3cx:3cx:18.12.402:*:*:*:*:macos:*:*
  - cpe:2.3:a:3cx:3cx:18.12.407:*:*:*:*:macos:*:*
  - cpe:2.3:a:3cx:3cx:18.12.407:*:*:*:*:windows:*:*
  - cpe:2.3:a:3cx:3cx:18.12.416:*:*:*:*:macos:*:*
  - cpe:2.3:a:3cx:3cx:18.12.416:*:*:*:*:windows:*:*
tags:
  - supply-chain
  - trojan
  - 3cx
vendors:
  - 3CX
products:
  - 3CXDesktopApp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: The 3CX supply chain attack involved the distribution of compromised software updates through the 3CXDesktopApp.
    confidence_band: high
cves:
  - id: CVE-2023-29059
    cvss: 7.8
    epss: 0.04373
references:
  - https://www.sentinelone.com/blog/smoothoperator-ongoing-campaign-trojanizes-3cx-software-in-software-supply-chain-attack/
  - https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp
  - https://www.3cx.com/community/threads/3cx-desktopapp-security-alert.119951/
  - https://nvd.nist.gov/vuln/detail/CVE-2023-29059
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for existence of 3CXDesktopApp and ensure versions are patched.
      owner: IT Operations
      due: 24h
      evidence: Vendor alert regarding CVE-2023-29059.
  hunt_leads:
    - lead: DNS queries from endpoints to domains associated with 3CX infrastructure.
      technique_id: T1195.002
      data_needed:
        - Sysmon Event ID 22
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic documented in splunk-escu for identifying malicious DNS beacons.
---

In early 2023, the 3CX desktop application was compromised as part of a significant software supply chain attack. Threat actors successfully injected malicious code into signed 3CXDesktopApp updates, which were then distributed to customers globally through the official vendor update mechanism. This technique allowed attackers to achieve initial access to a large number of downstream enterprise networks by exploiting the trust associated with legitimate signed binaries. The malicious updates enabled the deployment of secondary payloads, leading to potential unauthorized network access, internal reconnaissance, and data exfiltration. Defenders must monitor for DNS beacons and anomalous network activity associated with the infrastructure used by this campaign, as established in CVE-2023-29059. The scope of targeting included organizations globally that relied on the affected 3CX communication software.

## Attack Chain

1. Attackers compromise the build environment or update infrastructure used by 3CX.
2. Trojanized, digitally signed versions of the 3CXDesktopApp are published to the official update servers.
3. Targets install or receive an automatic update of the compromised 3CXDesktopApp software.
4. The malicious code within the application executes, initiating communication with hardcoded C2 domains.
5. The primary payload retrieves secondary malicious modules from attacker-controlled external infrastructure.
6. The second-stage malware facilitates internal network reconnaissance and credential harvesting.
7. Attackers establish persistence and begin exfiltrating sensitive internal data to external C2 nodes.

## Impact

The supply chain attack compromised numerous organizations across multiple sectors, leveraging the widespread use of 3CX communication platforms. Successful exploitation allowed attackers to bypass perimeter security controls, establish long-term persistence in corporate environments, and perform unauthorized data exfiltration, representing a critical risk to organizational confidentiality and integrity.

## Recommendation

1. Monitor DNS query logs for connections to known malicious infrastructure associated with the 3CX campaign, utilizing the domain lookup provided by your threat intelligence platform.
2. Implement detection for unauthorized network communication from the 3CXDesktopApp process (Sysmon Event ID 22 or equivalent DNS logs).
3. Ensure all instances of 3CXDesktopApp are updated to the latest vendor-provided versions to mitigate CVE-2023-29059.
4. Perform retrospective hunting in DNS and proxy logs for any communication with infrastructure associated with the 3CX actor starting from early 2023.
