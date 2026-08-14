---
title: Insecure SSO Cookie Configuration in OpenAM
slug: 2026-08-openam-cookie-insecurity
description: OpenAM Community Edition versions prior to 16.1.1 are vulnerable to session theft and unauthorized OAuth consent grants due to insecure SSO cookie initialization (CVE-2026-53660).
date: "2026-08-14T20:06:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Open Identity Platform
products:
  - OpenAM Community Edition
references:
  - https://github.com/advisories/GHSA-fpmh-vx4h-xc33
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch OpenAM Community Edition to version 16.1.1
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-53660 is addressed in 16.1.1
  mitigation_plan:
    - priority: immediate
      action: Identify and patch all existing XSS vulnerabilities in the OpenAM environment to mitigate potential session theft
      owner: Security Engineering
      addresses: CVE-2026-53660
      evidence: Source states XSS in the OpenAM origin is the primary vector for session theft
---

OpenAM Community Edition through version 16.0.6 contains an insecure default configuration regarding its session management, specifically identified as CWE-1188 (Insecure Default Initialization of Resource). The platform initializes the 'iPlanetDirectoryPro' SSO cookie with the 'HttpOnly' flag set to false and lacks the 'SameSite' attribute. This configuration makes the sensitive session identifier accessible to client-side scripts, facilitating session hijacking if an attacker identifies an existing Cross-Site Scripting (XSS) vulnerability within the OpenAM origin. Furthermore, because OpenAM relies on this same cookie as a CSRF token during OAuth and OIDC consent flows, an attacker can leverage a single XSS instance to both steal the user session and perform unauthorized OAuth consent grants on behalf of the victim. This vulnerability, tracked as CVE-2026-53660, was addressed in the 16.1.1 release of OpenAM Community Edition.

## Impact

Successful exploitation allows for full SSO session theft of any authenticated OpenAM console user. Because the vulnerable cookie serves a dual purpose as both a session identifier and a CSRF token for OAuth flows, a single attacker-controlled link can lead to unauthorized consent grants, potentially granting an attacker persistent access to third-party applications via the victim's account. This affects all deployments of OpenAM Community Edition prior to version 16.1.1.

## Recommendation

* Update OpenAM Community Edition to version 16.1.1 or later to apply the secure cookie configuration defaults.
* Audit existing web application environments for secondary XSS vulnerabilities that could be leveraged to access the 'iPlanetDirectoryPro' cookie.
* Review OAuth/OIDC implementation logs for unexpected consent grants or rapid re-authorization patterns associated with specific user sessions.
