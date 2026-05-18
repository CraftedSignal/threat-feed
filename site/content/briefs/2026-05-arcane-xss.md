---
title: Arcane Backend Unauthenticated Reflected XSS via SVG Color Parameter Enables Admin Account Takeover
slug: 2026-05-arcane-xss
description: Arcane Backend versions 1.18.1 and earlier are vulnerable to an unauthenticated reflected XSS (CVE-2026-45627) via the SVG color parameter, allowing attackers to inject executable script content and compromise admin accounts by enticing them to visit a malicious link.
date: "2026-05-18T14:19:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - reflected-xss
  - github
  - arcane-backend
  - cve-2026-45627
vendors:
  - GitHub
products:
  - Arcane Backend (<= 1.18.1)
  - github.com/getarcaneapp/arcane/backend
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/advisories/GHSA-q2pj-8v84-9mh5
rules:
  - title: Detect Arcane Backend CVE-2026-45627 XSS Attempt via App Images Logo
    description: Detects CVE-2026-45627 exploitation attempt — GET request to the /api/app-images/logo endpoint with a 'color' parameter containing HTML script tags, indicating a reflected XSS attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect Arcane Backend Admin Account Creation via Malicious Script
    description: Detects suspicious admin account creation activity via a POST request to /api/users with elevated privileges.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
      - T1134
    data_sources:
      - webserver
rules_count: 2
---

Arcane Backend versions 1.18.1 and earlier are vulnerable to an unauthenticated reflected cross-site scripting (XSS) vulnerability via the `color` query parameter in the `/api/app-images/logo` endpoint. The vulnerability allows an attacker to inject arbitrary JavaScript code into the application's origin by crafting a malicious SVG image. Because the application lacks proper input validation, sanitization, and Content-Security-Policy (CSP) headers, an attacker can exploit this vulnerability to steal sensitive information such as admin JWT cookies, create new admin accounts, and gain full control over the Arcane Backend. The vulnerability is due to the direct use of user-controlled input within an SVG style tag without proper escaping.

## Attack Chain

1. An attacker crafts a malicious URL targeting the `/api/app-images/logo` endpoint, embedding XSS payload within the `color` query parameter, such as `color=red}</style><script>fetch('/api/users',...)</script><style>x{`.
2. The victim, a logged-in administrator, is enticed to visit the malicious URL through phishing or other social engineering techniques.
3. The Arcane Backend processes the request without authentication, as the `Security` parameter is explicitly empty for this route.
4. The backend's `applyAccentColorToSVG` function in `backend/internal/services/app_images_service.go` uses `strings.ReplaceAll` to inject the attacker-controlled `color` value into the `logo.svg` file.
5. The modified SVG image, containing the embedded XSS payload, is returned to the victim's browser with the `image/svg+xml` Content-Type.
6. The victim's browser executes the injected JavaScript code within the Arcane Backend's origin due to the absence of CSP and `X-Content-Type-Options` headers.
7. The injected script steals the administrator's `__Host-token` / `token` HttpOnly JWT cookie and uses it to make authenticated requests.
8. The attacker leverages the stolen cookie to create a new administrator account via `POST /api/users`, gaining persistent access to the Arcane Backend.

## Impact

Successful exploitation allows a remote attacker to execute arbitrary JavaScript code in the context of a logged-in Arcane Backend administrator. This can lead to complete account compromise, including the ability to create persistent attacker-controlled admin accounts. Given that Arcane manages Docker daemons, container exec, image registries, and GitOps repositories, the attacker can also read/modify secrets stored in environments, registries, and Git repositories the admin can access, start or exec into containers on connected Docker hosts, leading to a full compromise of the Arcane infrastructure.

## Recommendation

- Immediately upgrade to a patched version of Arcane Backend that addresses CVE-2026-45627.
- Deploy the Sigma rule `Detect Arcane Backend CVE-2026-45627 XSS Attempt via App Images Logo` to detect exploitation attempts targeting the vulnerable endpoint.
- Implement the following HTTP response headers on all responses, especially to `/api/app-images/*`: `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:`.
- Serve static images with `Content-Disposition: inline` and from a separate cookie-less origin to mitigate potential same-origin session riding.
- Enforce a strict allowlist on the settings write path (`SettingsService` → `AccentColor`) to prevent stored XSS variants.
