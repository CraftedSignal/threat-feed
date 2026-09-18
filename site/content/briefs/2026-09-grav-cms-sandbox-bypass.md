---
title: Grav CMS Twig Sandbox Bypass via Configuration Exposure
slug: 2026-09-grav-cms-sandbox-bypass
description: CVE-2026-92917 allows an authenticated user with page-edit privileges in Grav CMS 2.0.0-rc.1 through 2.0.21 to bypass Twig sandboxing and exfiltrate the full application configuration, including API keys and credentials.
date: "2026-09-17T13:57:24Z"
lastmod: "2026-09-18T01:12:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - cms
  - web-application
  - security-misconfiguration
  - information-disclosure
vendors:
  - Grav
products:
  - Grav (2.0.0-rc.1 through 2.0.21)
  - Grav (<= 2.0.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user with page-edit rights can render {{ config|print_r }} in page content with Twig processing enabled.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
    evidence: dump Grav's entire merged configuration — print_r reflects the real Config object... exposing plugin secrets such as SMTP credentials, API tokens, webhook secrets and cache backend passwords.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Any user with page-edit permission can render the real Redis password directly into the page output using Twig templates.
    confidence_band: high
cves:
  - id: CVE-2026-92917
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92917
  - https://github.com/advisories/GHSA-xjw5-q542-3vmr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76846
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav CMS to version 2.0.22
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in 2.0.22
  mitigation_plan:
    - priority: immediate
      action: Rotate all API keys and credentials contained in the Grav configuration
      owner: IT Operations
      addresses: CVE-2026-92917
      evidence: Exposure of plugin secrets such as SMTP credentials, API tokens, webhook secrets and cache backend passwords.
updates:
  - at: "2026-09-18T01:12:38Z"
    level: L2
    summary: added coverage for Grav (<= 2.0.15)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-xjw5-q542-3vmr
---

Grav CMS, a popular flat-file content management system, contains a vulnerability (CVE-2026-92917) within its Twig content sandbox implementation in versions 2.0.0-rc.1 through 2.0.21. The vulnerability stems from an incorrect implementation of the sandbox security check in `GravExtension::assertSandboxDumpSafe()`. Instead of checking if specific filters like `print_r`, `json_encode`, or `yaml_encode` are sandboxed relative to the source, the extension queries the global sandbox flag, which remains permanently disabled in Grav. Consequently, the safety guards intended to restrict data dumping fail. An authenticated attacker with page-edit permissions can leverage this by embedding Twig template code within a page. When rendered, the application processes the request, ignores the sandbox restrictions, and outputs the entire internal `Config` object, including sensitive secrets stored in private properties that are normally redacted. This exposure allows attackers to harvest SMTP credentials, API tokens, webhook secrets, and cache backend passwords. The vulnerability is resolved in Grav version 2.0.22, where the filters are correctly registered with Twig’s `needs_is_sandboxed` flag.

## Impact

Successful exploitation allows an authenticated user to gain access to sensitive application configuration data. This includes administrative secrets required for third-party integrations and backend services. Exposure of these credentials can facilitate further compromise of internal infrastructure, external services, and data exfiltration, significantly increasing the attacker's footprint within the environment.

## Recommendation

* Upgrade all instances of Grav CMS to version 2.0.22 or later immediately to patch CVE-2026-92917.
* Audit web application logs for administrative users accessing Twig-related rendering functions, specifically looking for attempts to use `print_r`, `vardump`, or `json_encode` filters within page content updates.
* Revoke and rotate all secrets (SMTP, API tokens, webhooks) found in the Grav configuration if a compromise is suspected to have occurred between version 2.0.0-rc.1 and 2.0.22.
