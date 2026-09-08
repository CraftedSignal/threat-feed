---
title: Critical Security Updates for Ivanti Endpoint Manager Mobile, Neurons for ITSM, and Sentry
slug: 2026-09-08-ivanti-security-advisory
description: Ivanti released security patches for multiple products, including Endpoint Manager Mobile, Neurons for ITSM, and Sentry, addressing vulnerabilities identified as CVE-2026-18851 and CVE-2026-83527.
date: "2026-09-08T22:23:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - patch-management
  - security-advisory
vendors:
  - Ivanti
products:
  - Endpoint Manager Mobile (< 12.10.0.0, < 12.9.0.2, < 12.8.0.4)
  - Neurons for ITSM (Cloud/SaaS < mo2026.2)
  - Neurons for ITSM On-Prem (multiple versions < Sept 2026 patch)
  - Sentry (< R10.8.2, < R10.7.3, < R10.6.4)
cves:
  - id: CVE-2026-18851
    cvss: 8.8
  - id: CVE-2026-83527
    cvss: 8.1
references:
  - https://cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-897
  - https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Neurons-for-ITSM-Multiple-CVEs?language=en_US
  - https://hub.ivanti.com/s/article/Security-Advisory---Ivanti-Endpoint-Manager-Mobile-CVE-2026-18851?language=en_US
  - https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-83527?language=en_US
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable Ivanti products to the specified versions or higher
      owner: IT Operations
      due: 24h
      evidence: Source advisory dictates patching
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ivanti products to patched versions
      owner: IT Operations
      addresses: CVE-2026-18851, CVE-2026-83527
      evidence: Vendor security advisory
---

On September 8, 2026, Ivanti issued a comprehensive security advisory addressing multiple vulnerabilities across its product portfolio. The affected product families include Endpoint Manager Mobile, Neurons for ITSM (both Cloud/SaaS and On-Premises), and Sentry. Specific vulnerabilities disclosed include CVE-2026-18851, which impacts Endpoint Manager Mobile, and CVE-2026-83527, affecting Ivanti Sentry. These flaws pose significant security risks if left unpatched. Organizations are urged to review the vendor-provided advisories for each specific component and apply the necessary patches immediately to secure their infrastructure. The scope of affected versions is broad, necessitating a review of all current deployments to ensure they meet the minimum version requirements or include the September 2026 security patches.

## Impact

Successful exploitation of these vulnerabilities could result in unauthorized access, potential remote code execution, or service disruption depending on the specific vulnerability and the impacted product. These Ivanti products are frequently used in enterprise environments for device management and service orchestration, making them high-value targets for threat actors seeking lateral movement or persistence within a network.

## Recommendation

- Apply the September 2026 security patches to all affected Ivanti Neurons for ITSM (On-Prem) instances immediately.
- Upgrade Endpoint Manager Mobile to version 12.10.0.0, 12.9.0.2, or 12.8.0.4 or later.
- Update Ivanti Sentry environments to version R10.8.2, R10.7.3, or R10.6.4 or later.
- Ensure Neurons for ITSM (Cloud/SaaS) instances are at version mo2026.2 or later, as managed by the vendor.
- Monitor logs for the webserver category on these appliances for anomalous HTTP requests or unexpected system activity following the patch application.
