---
brief_id: brief-2026-10-27-craft-cms-updates
event_id: brief-2026-10-27-craft-cms-updates
revision: 1
activity_at: "2026-10-27T03:53:07Z"
title: Craft CMS Security Updates
slug: 2026-10-craft-cms-updates
description: Craft CMS has released security updates for multiple products to address vulnerabilities in the core CMS platform and the Commerce-mollie plugin.
date: "2026-10-27T03:53:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch management verification required.
tags:
  - vulnerability-management
  - cms
  - web-application
vendors:
  - Craft CMS
products:
  - CMS (< 4.18.9)
  - CMS (< 5.11.2)
  - Commerce-mollie (< 4.4.3)
references:
  - https://cyber.gc.ca/en/alerts-advisories/craft-cms-security-advisory-av26-1086
  - https://github.com/craftcms/cms
  - https://github.com/craftcms/commerce-mollie
  - https://github.com/craftcms/cms/security/advisories
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade CMS to 4.18.9 or 5.11.2 and Commerce-mollie to 4.4.3
      owner: IT Operations
      addresses: Vulnerabilities in Craft CMS core and Commerce-mollie plugin
      evidence: Source identifies these versions as the threshold for remediation.
---

Craft CMS has released security updates to address multiple vulnerabilities affecting the core CMS platform and the Commerce-mollie plugin. Administrators are advised to update their installations to the specified versions to mitigate potential security risks. The specific nature of the vulnerabilities remains undisclosed in the current advisory.

## Recommendation

- Upgrade CMS installations to version 4.18.9 or 5.11.2 immediately.
- Upgrade the Commerce-mollie plugin to version 4.4.3.
- Review the official Craft CMS security advisory page for future disclosures or technical details.
