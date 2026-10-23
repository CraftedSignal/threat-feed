---
brief_id: brief-2026-10-23-mediawiki-authorization-bypass
event_id: brief-2026-10-23-mediawiki-authorization-bypass
revision: 1
activity_at: "2026-10-23T16:37:17Z"
title: 'MediaWiki: API Email Authorization Hook Bypass (CVE-2026-102973)'
slug: 2026-10-mediawiki-authorization-bypass
description: An authorization bypass vulnerability in MediaWiki allows attackers to bypass EmailUserAuthorizeSend hooks via the action=emailuser API, potentially enabling unauthorized email transmission if specific security policies are implemented.
date: "2026-10-23T16:37:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified that the vulnerability requires specific configuration conditions.
cpes:
  - cpe:2.3:a:mediawiki:mediawiki:*:*:*:*:*:*:*:*
vendors:
  - MediaWiki
products:
  - MediaWiki (unspecified versions)
cves:
  - id: CVE-2026-102973
    kev_status: unknown
references:
  - https://bombobombone.github.io/posts/cve-2026-102973/
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-102973
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-BOMBOBOMBONE-CVE-2026-102973&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit MediaWiki configurations for custom implementations of the EmailUserAuthorizeSend hook.
      owner: IT Operations
      due: 72h
      evidence: The vulnerability is conditional upon the site having an active policy or extension that utilizes the EmailUserAuthorizeSend hook.
  hunt_leads:
    - lead: Monitor web access logs for high volumes of POST requests to /api.php with action=emailuser.
      technique_id: T1190
      data_needed:
        - Web server logs (access logs)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability is triggered via the action=emailuser API path.
  mitigation_plan:
    - priority: immediate
      action: Patch MediaWiki instances to the version containing the fix for CVE-2026-102973.
      owner: IT Operations
      addresses: CVE-2026-102973
      evidence: Public Phabricator report and fix tracking
---

MediaWiki contains an authorization bypass vulnerability (CVE-2026-102973) affecting the `action=emailuser` API path. The API fails to correctly invoke the `EmailUserAuthorizeSend` hook, which is intended to enforce access control policies for sending emails. Consequently, if a wiki administrator has implemented an extension or policy to restrict email sending via this hook, an attacker with the base `sendemail` permission can bypass those restrictions using the API. 

## Impact

The vulnerability is conditional; it only impacts environments where a custom policy or extension utilizes the `EmailUserAuthorizeSend` hook to explicitly deny email operations. It does not affect stock core MediaWiki configurations that lack such custom hooks. Successful exploitation allows unauthorized email delivery, which could be leveraged for spam or social engineering if the underlying policy is bypassed.

## Recommendation

- Inventory MediaWiki installations to identify if custom extensions or local policies are utilizing the `EmailUserAuthorizeSend` hook.
- Review the official Phabricator report and upstream vendor updates for the patch addressing CVE-2026-102973.
- Apply the vendor-provided patch to all MediaWiki instances identified as using security-critical email authorization hooks.
