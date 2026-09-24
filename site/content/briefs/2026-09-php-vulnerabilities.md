---
title: Multiple Vulnerabilities in PHP Runtime Environment
slug: 2026-09-php-vulnerabilities
description: Multiple vulnerabilities across several PHP versions allow remote attackers to cause denial-of-service, access sensitive data, and compromise data integrity.
date: "2026-09-24T13:57:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - web-application
  - patch-management
vendors:
  - PHP
products:
  - PHP (8.2.x < 8.2.34, 8.3.x < 8.3.35, 8.4.x < 8.4.26, 8.5.x < 8.5.11)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1227/
  - https://www.php.net/ChangeLog-8.php#8.3.35
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade PHP runtime environments to versions 8.2.34, 8.3.35, 8.4.26, or 8.5.11.
      owner: IT Operations
      addresses: All CVEs listed in the brief
      evidence: Source documentation for PHP security updates
---

The PHP Group has released security updates addressing multiple vulnerabilities across several active PHP release branches. These vulnerabilities, identified as CVE-2025-1218, CVE-2025-14181, CVE-2026-17545, CVE-2026-6103, CVE-2026-91765, CVE-2026-91766, CVE-2026-91767, CVE-2026-91768, CVE-2026-91769, CVE-2026-92842, and CVE-2026-93682, impact versions of PHP 8.2.x, 8.3.x, 8.4.x, and 8.5.x. Depending on the specific flaw, exploitation may lead to remote denial-of-service (DoS) conditions, unauthorized disclosure of sensitive information, or the modification of application data. These issues represent a significant risk for any organization hosting PHP-based web applications, as the runtime environment is a core component of many enterprise web stacks. Defenders must prioritize upgrading to the patched versions: 8.2.34, 8.3.35, 8.4.26, and 8.5.11 to remediate these security gaps.

## Impact

Successful exploitation of these vulnerabilities can lead to service outages, exposure of proprietary or PII data, and unauthorized alteration of application state. Given the ubiquitous nature of PHP in web server environments, these flaws affect a broad range of sectors including e-commerce, content management systems, and custom internal web applications. Failure to patch may allow unauthenticated or remote attackers to disrupt business operations or gain deeper insight into sensitive back-end infrastructure.

## Recommendation

Prioritized actions for detection and remediation teams:

- Upgrade all PHP instances to the following patched versions immediately: 8.2.34, 8.3.35, 8.4.26, or 8.5.11.
- Review web server logs for irregular traffic patterns or excessive error spikes that may indicate exploitation attempts against the PHP engine.
- Patch CVE-2025-1218, CVE-2025-14181, CVE-2026-17545, CVE-2026-6103, CVE-2026-91765, CVE-2026-91766, CVE-2026-91767, CVE-2026-91768, CVE-2026-91769, CVE-2026-92842, and CVE-2026-93682 by applying the latest vendor updates.
