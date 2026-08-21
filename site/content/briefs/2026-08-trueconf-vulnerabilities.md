---
title: Active Exploitation of TrueConf Server Vulnerabilities
slug: 2026-08-trueconf-vulnerabilities
description: TrueConf Server versions 5.3.x, 5.4.x, and 5.5.x are vulnerable to CVE-2026-72529 and CVE-2026-72530, which are currently being exploited in the wild according to CISA KEV.
date: "2026-08-21T01:14:57Z"
lastmod: "2026-08-21T07:33:18Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:trueconf:trueconf_server:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:trueconf:trueconf_server:*:*:*:*:*:linux_kernel:*:*
vendors:
  - TrueConf
products:
  - TrueConf Server 5.3
  - TrueConf Server 5.4
  - TrueConf Server 5.5
affected_os:
  - Windows
  - Linux
cves:
  - id: CVE-2026-72529
    cvss: 9.8
  - id: CVE-2026-72530
    cvss: 9
references:
  - https://cyber.gc.ca/en/alerts-advisories/trueconf-security-advisory-av26-835
  - https://trueconf.com/blog/news/security-fixes-updates-and-advisories
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-72529
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-72530
  - https://www.securityweek.com/cisa-urges-immediate-patching-of-exploited-trueconf-vulnerabilities/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch TrueConf Server instances to the versions specified in the security advisory
      owner: IT Operations
      due: 24h
      evidence: CISA KEV addition confirms active exploitation
updates:
  - at: "2026-08-21T07:33:18Z"
    level: L1
    summary: OS windows; OS linux
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/cisa-urges-immediate-patching-of-exploited-trueconf-vulnerabilities/
---

TrueConf has issued a security advisory regarding multiple vulnerabilities affecting the TrueConf Server software suite. The affected versions include 5.3.x (prior to 5.3.9), 5.4.x (prior to 5.4.9), and 5.5.x (prior to 5.5.5). On August 20, 2026, the Cybersecurity and Infrastructure Security Agency (CISA) added these vulnerabilities, tracked as CVE-2026-72529 and CVE-2026-72530, to its Known Exploited Vulnerabilities (KEV) catalog. This designation confirms that threat actors are actively exploiting these flaws in real-world environments. Organizations running TrueConf Server are urged to update to the latest available versions immediately to mitigate the risk of unauthorized access or exploitation.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized actors to compromise TrueConf Server instances, which may lead to full system takeover, unauthorized access to internal communications, or data exfiltration. Given the inclusion of these CVEs in the CISA KEV, all internet-facing TrueConf Server instances are at immediate risk of compromise.

## Recommendation

- Immediately audit all internet-facing TrueConf Server instances to identify affected versions (5.3.x < 5.3.9, 5.4.x < 5.4.9, 5.5.x < 5.5.5).
- Apply the vendor-provided patches as detailed in the TrueConf Security Advisories page.
- Prioritize patching any TrueConf Server instances accessible from the public internet.
- Review network access logs for unusual patterns originating from or directed toward TrueConf Server infrastructure.
