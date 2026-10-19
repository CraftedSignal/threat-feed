---
title: Authorization Bypass in Craft CMS GraphQL Mutations
slug: 2026-10-craft-cms-auth-bypass
description: Craft CMS versions 5.0.0 through 5.10.9 contain an authorization bypass vulnerability allowing attackers with site-scoped tokens to manipulate content across unauthorized sites via GraphQL mutations.
date: "2026-10-19T22:23:26Z"
lastmod: "2026-10-19T22:23:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - cms
  - graphql
  - cve
  - rce
  - twig
vendors:
  - Craft CMS
products:
  - Craft CMS (5.0.0 <= 5.10.9)
  - Craft CMS (4.x < 4.18.8, 5.x < 5.11.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Craft CMS from 5.0.0 before 5.11.0 contains an authorization bypass vulnerability.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Attackers holding a site-A token can create entries in site B via supplied siteId.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: By manipulating these parameters, an attacker can write a malicious file (webshell) directly to the webroot, subsequently executing arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-112776
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112776
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112770
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Craft CMS instances to 5.11.0 or later to patch CVE-2026-112776.
      owner: IT Operations
      due: 24h
      evidence: Source notes version 5.11.0 as the remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Craft CMS 5.11.0 or higher.
      owner: IT Operations
      addresses: CVE-2026-112776
      evidence: NVD source advisory
updates:
  - at: "2026-10-19T22:23:40Z"
    level: L2
    summary: added coverage for Craft CMS (4.x < 4.18.8, 5.x < 5.11.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112770
---

Craft CMS versions 5.0.0 through 5.10.9 contain a critical authorization bypass vulnerability (CVE-2026-112776) stemming from an improperly enforced `requireAllowedSite()` check within the GraphQL API. The vulnerability allows an authenticated attacker, holding a legitimate GraphQL token scoped to a single site, to perform unauthorized mutations on content belonging to other sites within the same multi-site Craft CMS instance. 

By manipulating the `siteId` parameter in GraphQL requests, an attacker can create, modify, or delete entries, categories, tags, and assets that they should not have access to. Because this bypasses site-level access controls, it permits cross-site data corruption and potential unauthorized information exposure or service disruption. This vulnerability impacts installations utilizing multi-site configurations where strict tenant isolation is required. Organizations should update to version 5.11.0 or later to ensure that site-scoped tokens are correctly validated before mutation operations.

## Attack Chain

1. The attacker obtains a valid, site-scoped GraphQL API token for a specific site in a multi-site Craft CMS instance.
2. The attacker identifies the `siteId` of a target site that is not included in the scope of their current token.
3. The attacker crafts a GraphQL mutation request (e.g., `createEntry`, `deleteEntry`, or `saveAsset`) targeting the CMS GraphQL endpoint.
4. The attacker injects the `siteId` of the target site into the mutation parameters.
5. The server processes the GraphQL request without enforcing the `requireAllowedSite()` check for the provided `siteId`.
6. The CMS executes the mutation using the provided `siteId`, resulting in unauthorized data modification or deletion on the target site.

## Impact

Successful exploitation allows for arbitrary unauthorized mutations across sites within a single Craft CMS installation. This can result in the deletion of critical business content, unauthorized injection of data, and the compromise of categories, tags, and assets shared across sites. The vulnerability is assigned a CVSS score of 9.8, reflecting the significant risk of unauthorized modification and potential service disruption for enterprise environments utilizing multi-site CMS architectures.

## Recommendation

* Patch the instance by upgrading to Craft CMS version 5.11.0 or later immediately to resolve CVE-2026-112776.
* Audit application logs for `POST` requests to the GraphQL endpoint that contain unusual or unexpected `siteId` parameters associated with site-scoped tokens.
* Implement egress monitoring for the web server to detect unusual mutation patterns if patching is delayed.
* Review GraphQL token scope assignments to ensure the principle of least privilege is applied to all API keys and user tokens.
