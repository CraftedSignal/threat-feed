---
title: Multiple Remote Code Execution Vulnerabilities in Fortinet FortiSIEM
slug: 2026-10-fortinet-fortisiem-rce
description: Multiple vulnerabilities in Fortinet FortiSIEM allow unauthenticated remote attackers to execute arbitrary code on the affected appliance, risking complete platform compromise.
date: "2026-10-14T16:23:41Z"
lastmod: "2026-10-18T17:39:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:6.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:6.4.1:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:6.4.2:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:6.5.0:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:6.5.1:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortisiem:7.0.0:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2023-34992&utm_source=rss&utm_medium=rss
tags:
  - remote-code-execution
  - vulnerability
  - appliance
vendors:
  - Fortinet
products:
  - FortiSIEM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote, unauthenticated attacker can exploit multiple vulnerabilities in Fortinet FortiSIEM to execute arbitrary program code.
    confidence_band: high
cves:
  - id: CVE-2023-34992
    cvss: 10
    epss: 0.81698
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3934
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2023-34992&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all FortiSIEM appliances and restrict access to management interfaces.
      owner: IT Operations
      due: 24h
      evidence: General security best practice for remediating unpatched remote-accessible infrastructure.
  mitigation_plan:
    - priority: immediate
      action: Patch FortiSIEM as soon as the vendor releases security updates.
      owner: IT Operations
      addresses: FortiSIEM vulnerabilities
      evidence: BSI Security Advisory WID-SEC-2026-3934
updates:
  - at: "2026-10-18T17:39:24Z"
    level: L2
    summary: poc_available; added CVE-2023-34992
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HORIZON3AI-CVE-2023-34992&utm_source=rss&utm_medium=rss
---

Fortinet has disclosed multiple vulnerabilities affecting FortiSIEM that could permit a remote, unauthenticated attacker to achieve arbitrary code execution. These vulnerabilities represent a significant risk to security operations, as they allow for the potential compromise of the SIEM platform, which is responsible for centralizing and processing an organization's security telemetry. The exploitation of these flaws could grant an attacker full control over the FortiSIEM appliance, facilitating data exfiltration, lateral movement within the management network, or the disabling of security monitoring capabilities. Organizations utilizing FortiSIEM are advised to monitor official vendor security advisories for specific patches or mitigation steps and prioritize deployment of updates to affected appliances.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code with the privileges of the affected service. If compromised, the SIEM platform becomes a vector for further internal network reconnaissance or a repository for sensitive organizational security data, including logs and alerts. This vulnerability affects the confidentiality, integrity, and availability of the central security monitoring infrastructure.

## Recommendation

Prioritize the identification of all internet-facing FortiSIEM appliances within the environment. Monitor the Fortinet PSIRT portal for the release of firmware updates addressing these specific vulnerabilities and patch all affected systems immediately. Ensure that access to the FortiSIEM management interface is restricted to authorized administrative networks and employ network-level access controls to minimize the attack surface until patches are applied.
