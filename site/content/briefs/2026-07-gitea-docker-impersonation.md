---
title: Gitea Docker Images Insecure Default Allows User Impersonation via X-WEBAUTH-USER
slug: 2026-07-gitea-docker-impersonation
description: Gitea Docker images ship with a critical misconfiguration, CVE-2026-20896, where `REVERSE_PROXY_TRUSTED_PROXIES = *` by default, enabling any client to bypass authentication and impersonate users via the `X-WEBAUTH-USER` HTTP header when reverse proxy authentication is enabled, leading to unauthorized access to user accounts, including administrative ones.
date: "2026-07-21T20:36:08Z"
lastmod: "2026-08-15T20:31:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=2E636F7C-D328-572A-AAAE-86B8C5A6D4B6&utm_source=rss&utm_medium=rss
tags:
  - misconfiguration
  - authentication-bypass
  - docker
  - gitea
  - web-application
  - cve
vendors:
  - Gitea
products:
  - gitea/gitea Docker images
  - go/code.gitea.io/gitea
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Gitea Docker image misconfiguration allows any source IP to impersonate any user via `X-WEBAUTH-USER` header.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'Attacker is logged in as alice with one header, no password, no cookie. Same payload with `X-WEBAUTH-USER: <any_existing_username>` impersonates that user.'
    confidence_band: high
cves:
  - id: CVE-2026-20896
    cvss: 9.8
    epss: 0.31809
references:
  - https://github.com/advisories/GHSA-f75j-4cw6-rmx4
  - https://sploitus.com/exploit?id=2E636F7C-D328-572A-AAAE-86B8C5A6D4B6&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-20896 Exploitation - Gitea Impersonation via X-WEBAUTH-USER
    description: Detects exploitation of CVE-2026-20896 where a misconfigured Gitea Docker instance, with `REVERSE_PROXY_TRUSTED_PROXIES = *` and `ENABLE_REVERSE_PROXY_AUTHENTICATION = true`, receives an `X-WEBAUTH-USER` header from a non-loopback IP, indicating an authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-15T20:31:53Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=2E636F7C-D328-572A-AAAE-86B8C5A6D4B6&utm_source=rss&utm_medium=rss
---

Gitea Docker images (versions prior to 1.26.3) contain a critical security misconfiguration, CVE-2026-20896, where the `app.ini` template hard-codes `REVERSE_PROXY_TRUSTED_PROXIES = *`. This default deviates from the secure documented standard of `127.0.0.0/8,::1/128` (loopback only). When `ENABLE_REVERSE_PROXY_AUTHENTICATION` is set to `true` in a vulnerable Gitea Docker deployment, any process or attacker capable of directly reaching the Gitea container's HTTP port can impersonate any user. This is achieved by simply supplying an `X-WEBAUTH-USER` HTTP header with a known or guessable username, bypassing standard authentication mechanisms like passwords or session cookies. This vulnerability affects `gitea/gitea` Docker images up to version 1.26.2 and poses a significant risk for unauthorized access.

## Attack Chain

1. **Deployment of Vulnerable Gitea Container**: An organization deploys a `gitea/gitea` Docker image (version prior to 1.26.3) configured with `ENABLE_REVERSE_PROXY_AUTHENTICATION = true`, retaining the image's default `REVERSE_PROXY_TRUSTED_PROXIES = *`.
2. **Network Exposure**: The Gitea container's HTTP port (e.g., 3000) is directly accessible to an attacker, potentially bypassing any intended authenticating reverse proxy.
3. **User Enumeration/Knowledge**: The attacker identifies or guesses valid usernames within the Gitea instance (e.g., 'admin', 'alice').
4. **Crafting Malicious HTTP Request**: The attacker crafts an HTTP GET or POST request targeting the vulnerable Gitea instance, including the `X-WEBAUTH-USER` header set to an identified username.
5. **Authentication Bypass**: The misconfigured Gitea instance, treating all incoming connections as trusted proxies, accepts the `X-WEBAUTH-USER` header from the attacker's source IP as a legitimate authentication credential.
6. **Account Impersonation**: The attacker's request is processed with the privileges of the user specified in the `X-WEBAUTH-USER` header, granting unauthorized access to that user's account.
7. **Impact**: The attacker gains full control over the impersonated user's Gitea account, allowing actions such as repository modification, unauthorized access to code, or privilege escalation if an administrative account was targeted, leading to full control of the Git hosting platform.

## Impact

Successful exploitation of CVE-2026-20896 allows any process that can directly access the Gitea Docker container's HTTP port to completely bypass authentication and impersonate any existing user. This includes highly privileged accounts like administrators (e.g., 'admin', 'gitea_admin'), leading to full compromise of the Gitea instance. Attackers can gain unauthorized access to source code repositories, manipulate project data, create new users, delete existing content, or achieve complete control over the Git hosting platform. While specific victim counts are not available, all deployments using vulnerable Gitea Docker images with `ENABLE_REVERSE_PROXY_AUTHENTICATION` enabled are at critical risk.

## Recommendation

* **Patch CVE-2026-20896** by upgrading `gitea/gitea` Docker images to version 1.26.3 or newer immediately to address the insecure default configuration.
* **Manually Configure Trusted Proxies**: If immediate upgrade is not feasible, modify the `REVERSE_PROXY_TRUSTED_PROXIES` setting in `app.ini` to explicitly list only the IP addresses of trusted reverse proxies (e.g., `127.0.0.0/8,::1/128`) and restart the Gitea container.
* **Deploy the Sigma rule** titled "Detect CVE-2026-20896 Exploitation - Gitea Impersonation via X-WEBAUTH-USER" to your SIEM and tune it for your environment.
* **Enable comprehensive web server logging** to capture HTTP request headers and client IP addresses, which are critical log sources for detecting the exploitation behavior described.
