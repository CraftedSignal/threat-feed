---
title: Critical XSS Vulnerabilities in AFFiNE
slug: 2026-03-affine-xss
description: Two critical XSS vulnerabilities, Reflected XSS in the /image-proxy endpoint and Stored XSS in bookmark cards, were discovered in AFFiNE, a self-hosted alternative to Notion, with the vendor being unresponsive.
date: "2026-03-19T12:09:56Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - xss
  - vulnerability
  - affine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rxyovl/critical_xss_vulnerabilities_in_affine_are_being/
  - https://gabdevele.dev/posts/2026/multiple-critical-xss-affine/
  - https://github.com/toeverything/AFFiNE/
iocs:
  - type: url
    value: https://gabdevele.dev/posts/2026/multiple-critical-xss-affine/
  - type: url
    value: https://github.com/toeverything/AFFiNE/
ioc_counts:
  url: 2
rules:
  - title: Detect Access to AFFiNE Image Proxy Endpoint
    description: Detects access to the AFFiNE /image-proxy endpoint which is vulnerable to reflected XSS.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Bookmark Cards with Javascript Links
    description: Detects bookmark cards containing JavaScript links, indicative of stored XSS vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A cybersecurity researcher discovered two critical XSS vulnerabilities in AFFiNE, a self-hosted alternative to Notion, which has 66k stars on GitHub. The vulnerabilities include a reflected XSS in the `/image-proxy` endpoint and a stored XSS vulnerability in bookmark cards. The `/image-proxy` endpoint vulnerability allows unauthenticated users to fetch arbitrary URLs and reflect the URL headers in the response, potentially leaking internal IP addresses. The stored XSS vulnerability enables attackers to insert JavaScript links within bookmark cards. The researcher reported that the AFFiNE maintainers have been unresponsive to vulnerability reports for months, despite ongoing commits to the repository, raising concerns about the security of AFFiNE users.

## Attack Chain

1. An attacker identifies an AFFiNE instance.
2. The attacker crafts a malicious URL targeting the `/image-proxy` endpoint with a payload designed to reflect arbitrary headers, possibly revealing internal network information.
3. The attacker sends the crafted URL to a victim, or the attacker directly accesses the vulnerable endpoint if internal IP leakage is the goal.
4. The AFFiNE server fetches the URL and reflects the attacker-controlled headers in the response, leading to XSS execution in the victim's browser.
5. Alternatively, the attacker crafts a bookmark card containing a "javascript:" link.
6. The attacker saves the malicious bookmark card within AFFiNE.
7. When a user clicks on the malicious bookmark card, the injected JavaScript code executes within their browser session, enabling further malicious actions.
8. The attacker can then steal cookies, redirect the user, or perform other actions within the context of the AFFiNE application.

## Impact

Successful exploitation of the reflected XSS vulnerability can expose internal IP addresses of AFFiNE instances, potentially affecting all users of the self-hosted application. The stored XSS vulnerability can lead to account takeover, data theft, or further propagation of malicious content within the AFFiNE workspace. AFFiNE has 66k stars on GitHub, indicating a significant user base, making the impact potentially widespread. The affected sectors are broad, as AFFiNE is a general-purpose productivity tool.

## Recommendation

*   Block the `/image-proxy` endpoint at the network or proxy level as a temporary mitigation for the reflected XSS vulnerability, as suggested by the researcher.
*   Educate users to avoid clicking on links starting with "javascript:" in bookmark cards to prevent exploitation of the stored XSS vulnerability.
*   Deploy the Sigma rule to detect access to the vulnerable `/image-proxy` endpoint.
*   Deploy the Sigma rule to detect bookmark cards with suspicious JavaScript links.
