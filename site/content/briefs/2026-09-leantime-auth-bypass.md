---
title: Authorization Bypass in Leantime HTMX Plugin Installation
slug: 2026-09-leantime-auth-bypass
description: Leantime versions prior to 3.9.6 contain an authorization bypass vulnerability in the HTMX plugin installation endpoint, allowing low-privileged authenticated users to deploy arbitrary plugins.
date: "2026-09-16T21:55:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:leantime:leantime:*:*:*:*:*:*:*:*
vendors:
  - Leantime
products:
  - Leantime (< 3.9.6)
cves:
  - id: CVE-2026-92772
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92772
rules:
  - title: Detect Leantime HTMX Plugin Installation Attempts
    description: Detects requests to the Leantime HTMX plugin installation endpoint which may indicate exploitation of CVE-2026-92772 by non-privileged users.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Leantime to 3.9.6 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-92772 patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Leantime to 3.9.6
      owner: IT Operations
      addresses: CVE-2026-92772
      evidence: NVD advisory for Leantime
---

Leantime versions prior to 3.9.6 are susceptible to an authorization bypass vulnerability (CVE-2026-92772) located within the HTMX plugin installation endpoint. The application fails to properly validate the permissions of users attempting to access the plugin installation interface. As a result, an authenticated user with limited role-based access can successfully interact with this endpoint to install marketplace plugins. An attacker can manipulate configuration properties, including plugin identifiers, versions, and license keys, to force the application to install unauthorized or malicious code. This vulnerability poses a significant risk to organizations as it enables attackers to move from a low-privileged account to achieving arbitrary code execution or persistence within the application environment. Defenders should prioritize patching Leantime to version 3.9.6 or later to enforce correct access control checks on the HTMX plugin installation process.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to deploy arbitrary plugins, leading to potential remote code execution, unauthorized data access, and persistent backdoors within the Leantime environment. This affects all organizations using Leantime versions earlier than 3.9.6 that permit standard user account creation or have exposed the application to untrusted internal actors.

## Recommendation

* Patch Leantime to version 3.9.6 or later immediately to resolve CVE-2026-92772.
* Audit application logs for unauthorized plugin installation requests, specifically monitoring access to the HTMX plugin installation endpoint for users without administrative privileges.
* Review existing plugin manifests to ensure no unauthorized or unrecognized plugins have been installed within the environment.
