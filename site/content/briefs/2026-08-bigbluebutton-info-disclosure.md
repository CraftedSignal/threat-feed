---
title: Information Disclosure Vulnerability in BigBlueButton
slug: 2026-08-bigbluebutton-info-disclosure
description: A vulnerability in BigBlueButton versions prior to 2.7.7 allows a remote, unauthenticated attacker to access sensitive information due to improper data handling.
date: "2026-08-14T14:06:22Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - BigBlueButton
products:
  - BigBlueButton (< 2.7.7)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A vulnerability in BigBlueButton allows a remote, unauthenticated attacker to perform information disclosure.
    confidence_band: high
cves:
  - id: CVE-2024-36127
    cvss: 7.5
    epss: 0.00441
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2845
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade BigBlueButton to version 2.7.7 or later
      owner: IT Operations
      addresses: CVE-2024-36127
      evidence: Source advisory recommends update to mitigate the information disclosure vulnerability.
---

A security vulnerability has been identified in BigBlueButton, a web-based conferencing system, affecting versions prior to 2.7.7. The vulnerability, tracked as CVE-2024-36127, allows a remote, unauthenticated attacker to perform information disclosure. This flaw is rooted in improper handling of sensitive data within the application environment, which potentially exposes confidential information that should be restricted. Organizations using BigBlueButton deployments are advised to update to version 2.7.7 or later to remediate the issue.

## Impact

Successful exploitation of this vulnerability enables unauthorized access to sensitive information within the BigBlueButton application environment. This could result in the exposure of meeting details, participant data, or other system-level information depending on the specific data handled by the vulnerable endpoints. The impact is primarily a loss of confidentiality.

## Recommendation

- Upgrade BigBlueButton server installations to version 2.7.7 or later to mitigate CVE-2024-36127.
- Review server-side logs for unusual patterns of unauthenticated access to sensitive API endpoints or data directory structures following the update process.
