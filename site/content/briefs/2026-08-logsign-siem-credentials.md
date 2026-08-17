---
title: Insufficiently Protected Credentials in Logsign SIEM
slug: 2026-08-logsign-siem-credentials
description: Logsign SIEM versions 6.4.97 through 6.4.113 are vulnerable to an insufficiently protected credentials flaw, allowing privileged users to retrieve embedded sensitive data (CVE-2026-14564).
date: "2026-08-17T14:46:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - credential-theft
  - logsign
vendors:
  - Innotim Software Telecommunications and Consulting Trade Ltd. Co.
products:
  - Logsign SIEM (6.4)
cves:
  - id: CVE-2026-14564
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14564
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0847
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Logsign SIEM to version 6.4.114.
      owner: IT Operations
      due: 48h
      evidence: Vendor patch availability.
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to Logsign SIEM to trusted networks only.
      owner: IT Operations
      addresses: CVE-2026-14564
      evidence: NVD advisory.
---

CVE-2026-14564 describes a vulnerability in Innotim Software's Logsign SIEM product, specifically affecting versions 6.4.97 up to, but not including, 6.4.114. The flaw is categorized as an Insufficiently Protected Credentials issue (CWE-522). This vulnerability allows an authenticated attacker with administrative privileges to retrieve sensitive data embedded within the application. Given the nature of a SIEM, which centralizes logs, security alerts, and often credentials for managed assets, the ability to extract embedded secrets represents a critical risk to the broader security ecosystem. Organizations running affected versions are urged to upgrade to version 6.4.114 or later to remediate the exposure.

## Impact

Successful exploitation of this vulnerability enables an attacker with elevated access to bypass security controls and gain unauthorized access to sensitive information stored or processed by the SIEM. This potentially facilitates lateral movement, credential theft, and access to integrated infrastructure monitoring data, which could impact the entire network environment.

## Recommendation

- Upgrade all Logsign SIEM instances to version 6.4.114 or later to address CVE-2026-14564.
- Audit logs for the period prior to patching to identify any anomalous access to sensitive system configurations or configuration export events.
- Review administrative access logs for unusual user activity associated with the affected product.
