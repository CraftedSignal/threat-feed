---
title: Multiple Vulnerabilities in PHP (CVE-2026-12184, CVE-2026-14355)
slug: 2026-07-php-multiple-vulnerabilities
description: Multiple critical vulnerabilities (CVE-2026-12184, CVE-2026-14355) have been discovered in various PHP versions, allowing an attacker to cause an unspecified security issue, as reported by CERT-FR on July 7, 2026.
date: "2026-07-07T13:55:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - php
  - web-application
  - server-side
vendors:
  - PHP
products:
  - PHP 8.2.x
  - PHP 8.3.x
  - PHP 8.4.x
  - PHP 8.5.x
cves:
  - id: CVE-2026-14355
    cvss: 5.6
    epss: 0.00276
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0843/
  - https://www.php.net/ChangeLog-8.php#8.2.32
  - https://www.php.net/ChangeLog-8.php#8.3.32
  - https://www.php.net/ChangeLog-8.php#8.4.23
  - https://www.php.net/ChangeLog-8.php#8.5.8
  - https://www.cve.org/CVERecord?id=CVE-2026-12184
  - https://www.cve.org/CVERecord?id=CVE-2026-14355
---

CERT-FR has issued an advisory (CERTFR-2026-AVI-0843) concerning multiple vulnerabilities impacting several versions of PHP, a widely used server-side scripting language. These vulnerabilities, identified as CVE-2026-12184 and CVE-2026-14355, affect PHP versions 8.2.x prior to 8.2.32, 8.3.x prior to 8.3.32, 8.4.x prior to 8.4.23, and 8.5.x prior to 8.5.8. The official PHP security bulletins for these fixes were released on July 2, 2026. While the specific nature and potential impact of these issues are not detailed by the publisher, the presence of multiple unpatched vulnerabilities in a core web technology poses a significant risk. Attackers could potentially leverage these flaws to compromise web servers, leading to data breaches, denial of service, or remote code execution, making timely patching crucial for defenders.

## Impact

The CERT-FR advisory indicates that these multiple vulnerabilities allow an attacker to cause "unspecified security issues." While exact details are not provided, flaws in PHP can frequently lead to severe consequences for affected systems. Potential impacts include remote code execution (RCE) on the server, information disclosure, privilege escalation, or denial of service conditions. Web applications and backend services running vulnerable PHP versions are at risk of compromise, which could result in unauthorized access to sensitive data, defacement of websites, or disruption of critical business operations. No specific victim count or targeted sectors were provided in the advisory, but the widespread use of PHP implies broad potential exposure.

## Recommendation

*   Prioritize patching all affected PHP installations immediately to versions 8.2.32, 8.3.32, 8.4.23, or 8.5.8 as per the PHP security bulletins referenced.
*   Review web server logs for unusual activity following patch deployment, specifically looking for HTTP requests that might indicate exploitation attempts related to CVE-2026-12184 and CVE-2026-14355, although specific patterns are not available.
*   Consult the official PHP changelogs (e.g., https://www.php.net/ChangeLog-8.php#8.2.32) for detailed information regarding the fixes and any potential configuration changes.
