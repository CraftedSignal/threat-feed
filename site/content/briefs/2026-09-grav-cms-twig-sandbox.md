---
title: Grav CMS Session Hijacking via Twig Sandbox Injection
slug: 2026-09-grav-cms-twig-sandbox
description: Grav CMS versions 1.7.x and 2.0.0 through 2.0.24 are vulnerable to session hijacking due to an improperly restricted get_cookie() function within the Twig rendering engine.
date: "2026-09-26T15:09:57Z"
lastmod: "2026-09-26T17:00:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - web-application
  - security-misconfiguration
  - cve-2026-100669
vendors:
  - Grav
products:
  - Grav (1.7.x)
  - Grav (2.0.0 through 2.0.24)
  - Grav (< 2.0.25)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A page published by a page-write user can therefore capture the session identifier of the next administrator who views it.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: The attacker can replay the cookie to authenticate as that administrator.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can vary the case of a folder name or file extension so that no deny rule matches and the IIS static file handler resolves and returns the underlying file.
    confidence_band: high
cves:
  - id: CVE-2026-100671
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100671
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100669
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Grav CMS to 2.0.25 or higher.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 2.0.25
  mitigation_plan:
    - priority: immediate
      action: Set security.twig_content.process_enabled to false in Grav configuration.
      owner: IT Operations
      addresses: CVE-2026-100671
      evidence: Twig content runs on every page with no frontmatter or operator action if enabled.
updates:
  - at: "2026-09-26T17:00:21Z"
    level: L2
    summary: added coverage for Grav (< 2.0.25)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100669
---

Grav CMS versions 1.7.x and 2.0.0 through 2.0.24 contain a vulnerability in the Twig sandbox configuration. Specifically, the get_cookie() function is allowlisted for use within page content. A user with page-write permissions can inject Twig template code to read arbitrary browser cookies from any user who visits the crafted page. This attack bypasses standard security protections such as the HttpOnly, Secure, and SameSite attributes because the extraction occurs server-side.

The vulnerability is compounded by the Grav page-content caching mechanism, which stores the processed output of Twig-enabled pages without scoping the cache to the viewing user's session or identity. When an administrator views the crafted page, their session cookie is captured and embedded into the cached version of the content. Subsequent unauthenticated visitors to that page receive the cached content containing the administrator's session identifier. This allows unauthorized attackers to replay the stolen session cookie to hijack administrative access. In version 2.0.19 and later, Twig content processing is enabled by default, increasing the exploit surface. The issue was addressed in version 2.0.25.

## Attack Chain

1. An attacker obtains or registers a user account with page-write privileges on the target Grav CMS.
2. The attacker navigates to the administrative interface to create or edit a page.
3. The attacker injects malicious Twig code containing `{{ get_cookie('session_cookie_name') }}` into the page content.
4. The attacker saves the page, triggering the server to render the Twig code during the next page load.
5. An administrator visits the crafted page, causing the server to execute the injected code and extract the administrator's session cookie.
6. The server stores the resulting rendered output in the system's global page cache, including the captured sensitive cookie data.
7. The attacker or another unauthenticated user requests the crafted page and receives the cached content containing the administrator's session token.
8. The attacker uses the intercepted session token to impersonate the administrator and gain unauthorized administrative control.

## Impact

Successful exploitation allows for complete administrative account takeover of the Grav CMS instance. This can lead to unauthorized modification of site content, configuration changes, and potential remote code execution depending on the privileges and plugins associated with the hijacked administrative session. The scope includes all Grav deployments running vulnerable versions where Twig content rendering is enabled.

## Recommendation

* Upgrade Grav CMS to version 2.0.25 or later immediately.
* Audit all pages authored by users with page-write permissions for the presence of Twig syntax or suspicious template code.
* Disable Twig content processing if it is not required for site functionality by setting `security.twig_content.process_enabled` to `false`.
* Review administrative access logs for unusual session activity or successful logins originating from disparate IP addresses following the period of exposure.
