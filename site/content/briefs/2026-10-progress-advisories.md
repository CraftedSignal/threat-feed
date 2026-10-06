---
title: Security Updates for Progress Telerik Fiddler Classic and Sitefinity Next.js SDK
slug: 2026-10-progress-advisories
description: Progress Software has issued patches for vulnerabilities in Telerik Fiddler Classic, including CVE-2026-77805, and the Sitefinity Next.js SDK.
date: "2026-10-06T00:49:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:telerik_fiddler_classic:*:*:*:*:*:*:*:*
  - cpe:2.3:a:progress:sitefinity_nextjs_sdk:*:*:*:*:*:*:*:*
vendors:
  - Progress
products:
  - Telerik Fiddler Classic (< 6.0.20262.10021)
  - '@progress/sitefinity-nextjs-sdk (< 15.4.8638)'
affected_os:
  - Windows
cves:
  - id: CVE-2026-77805
    cvss: 7.9
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-security-advisory-av26-999
  - https://www.telerik.com/fiddler/fiddler-classic/documentation/knowledge-base/kb-security-weak-executable-signature-verification-cve-2026-77805
  - https://community.progress.com/s/article/Sitefinity-Critical-Security-Advisory-for-Addressing-Security-Vulnerabilities-in-Next-js-September-2026
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Telerik Fiddler Classic to 6.0.20262.10021
      owner: IT Operations
      addresses: CVE-2026-77805
      evidence: Vendor advisory requires version 6.0.20262.10021
    - priority: immediate
      action: Upgrade @progress/sitefinity-nextjs-sdk to 15.4.8638
      owner: IT Operations
      addresses: Sitefinity Next.js SDK vulnerabilities
      evidence: Vendor advisory requires version 15.4.8638
---

Progress Software has released security updates to address vulnerabilities affecting Telerik Fiddler Classic and the Sitefinity Next.js SDK. Telerik Fiddler Classic is affected by a weak executable signature verification vulnerability, tracked as CVE-2026-77805. This vulnerability may allow for unauthorized manipulation of executable signatures, potentially facilitating the execution of malicious code. Additionally, security vulnerabilities have been identified within the Sitefinity Next.js SDK. Users and administrators are advised to upgrade Telerik Fiddler Classic to version 6.0.20262.10021 or later, and the Sitefinity Next.js SDK to version 15.4.8638 or later. These updates are critical to prevent potential exploitation of the identified security weaknesses in these products.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized code execution or the bypassing of security controls within affected environments. The specific impact depends on the environment in which these tools are deployed, particularly for administrative or development workstations running Fiddler or web applications utilizing the vulnerable SDK.

## Recommendation

Prioritized actions for security and IT operations teams:

- Upgrade all instances of Telerik Fiddler Classic to version 6.0.20262.10021 or later immediately to mitigate CVE-2026-77805.
- Upgrade the @progress/sitefinity-nextjs-sdk dependency to version 15.4.8638 or later in all active projects.
- Review the Progress Trust Center for further details on mitigation and configuration changes required to secure affected deployments.
