---
brief_id: brief-2026-11-04-symfony-vulnerabilities
event_id: brief-2026-11-04-symfony-vulnerabilities
revision: 1
activity_at: "2026-11-04T16:20:52Z"
title: 'Symfony: Multiple Component Vulnerabilities (CVE-2026-118516)'
slug: 2026-11-symfony-vulnerabilities
description: Multiple vulnerabilities across Symfony components, including filesystem, http-client, and security-http, allow for remote denial of service, data confidentiality compromise, and security policy bypass.
date: "2026-11-04T16:20:52Z"
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
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - php
  - web-framework
vendors:
  - Symfony
products:
  - filesystem (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - http-client (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - http-foundation (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - json-path (7.3.0 to 7.4.x < 7.4.23, 8.x < 8.1.11)
  - routing (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - security-http (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - serializer (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - symfony (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
  - yaml (< 5.4.56, 6.4.50, 7.4.23, 8.1.11)
cves:
  - id: CVE-2026-118516
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1460/
  - https://github.com/symfony/symfony/security/advisories/GHSA-3h27-hjv7-fqjx
  - https://github.com/symfony/symfony/security/advisories/GHSA-5mx8-mwrp-5693
  - https://github.com/symfony/symfony/security/advisories/GHSA-6prc-h956-hxjq
  - https://github.com/symfony/symfony/security/advisories/GHSA-8f57-m8wj-x65w
  - https://github.com/symfony/symfony/security/advisories/GHSA-c7hm-wqwp-f9v8
  - https://github.com/symfony/symfony/security/advisories/GHSA-cpww-5vpx-72x7
  - https://github.com/symfony/symfony/security/advisories/GHSA-hwfg-qwvh-2wfx
  - https://github.com/symfony/symfony/security/advisories/GHSA-pxj9-jh84-vhm5
  - https://github.com/symfony/symfony/security/advisories/GHSA-xqw3-x93m-887x
  - https://www.cve.org/CVERecord?id=CVE-2026-118516
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Symfony components to the specified secure versions (e.g., 5.4.56, 6.4.50, 7.4.23, or 8.1.11)
      owner: IT Operations
      addresses: CVE-2026-118516
      evidence: Symfony security advisories dated 04 November 2026
---

The French CERT (ANSSI) has reported multiple vulnerabilities affecting several core components of the Symfony PHP framework. These vulnerabilities impact various versions of the filesystem, http-client, http-foundation, json-path, routing, security-http, serializer, and yaml components. The reported risks include remote denial of service, unauthorized access to sensitive data, and bypass of configured security policies. Users should refer to the individual GitHub Security Advisories linked below to determine the specific impact on their environment and apply the necessary patches.

## Impact

Successful exploitation may result in remote denial of service, compromise of data confidentiality, or security policy bypass, depending on the specific component and configuration involved.

## Recommendation

- Identify all instances of the Symfony framework and its components within the organization's infrastructure.
- Update all affected Symfony components to the versions specified as fixed in the security advisories (e.g., 5.4.56, 6.4.50, 7.4.23, or 8.1.11, depending on the release branch).
- Review the GitHub security advisories for each affected component (referenced below) to assess specific technical impact and remediation requirements.
