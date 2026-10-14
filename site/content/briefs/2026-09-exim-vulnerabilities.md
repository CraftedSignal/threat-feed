---
title: Multiple Vulnerabilities in Exim Mail Transfer Agent
slug: 2026-09-exim-vulnerabilities
description: Multiple vulnerabilities in the Exim mail transfer agent allow remote, unauthenticated attackers to perform memory corruption, security constraint bypass, and denial-of-service.
date: "2026-09-21T13:51:21Z"
lastmod: "2026-10-14T21:52:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*
  - cpe:2.3:a:libspf2_project:libspf2:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KIRINSE-CVE-2023-42115&utm_source=rss&utm_medium=rss
vendors:
  - Exim
products:
  - Exim
  - Exim (< 4.96.1)
cves:
  - id: CVE-2023-42115
    cvss: 9.8
    epss: 0.12088
  - id: CVE-2023-42116
    cvss: 9.8
    epss: 0.03756
  - id: CVE-2023-42117
    cvss: 9.8
    epss: 0.0679
  - id: CVE-2023-42118
    cvss: 8.8
    epss: 0.1901
  - id: CVE-2023-42119
    cvss: 3.1
    epss: 0.01609
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3475
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KIRINSE-CVE-2023-42115&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Exim to the latest secure version provided by the OS distribution
      owner: IT Operations
      addresses: CVE-2023-42114, CVE-2023-42115, CVE-2023-42116, CVE-2023-42117, CVE-2023-42118, CVE-2023-42119
      evidence: Source identifies multiple vulnerabilities in Exim
updates:
  - at: "2026-10-14T21:52:28Z"
    level: L2
    summary: poc_available; added CVE-2023-42119; exim version < 4.96.1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KIRINSE-CVE-2023-42115&utm_source=rss&utm_medium=rss
---

The Exim mail transfer agent is affected by multiple security vulnerabilities (CVE-2023-42114, CVE-2023-42115, CVE-2023-42116, CVE-2023-42117, CVE-2023-42118, and CVE-2023-42119). These flaws allow a remote, unauthenticated attacker to exploit the software via crafted network communications. Successful exploitation may result in memory corruption, the bypass of existing security controls, unauthorized disclosure or manipulation of data, and the induction of denial-of-service states. Defenders should identify all instances of Exim within their environment and ensure they are patched to the latest version provided by their distribution or vendor to mitigate these risks.

## Impact

Successful exploitation of these vulnerabilities can lead to full compromise of the Exim process, allowing for potential data exfiltration, service disruption, and manipulation of email traffic. Organizations relying on Exim for mail routing are at risk of service outages and unauthorized access to sensitive communications.

## Recommendation

Prioritize the identification and patching of all internet-facing Exim instances. Monitor mail server infrastructure for abnormal memory usage or service restarts, which may indicate attempted exploitation or crash-inducing behavior.
