---
brief_id: brief-2026-10-21-php-rce-vulnerabilities
event_id: brief-2026-10-21-php-rce-vulnerabilities
revision: 1
activity_at: "2026-10-21T20:09:50Z"
title: 'PHP: Multiple vulnerabilities allowing remote code execution'
slug: 2026-10-php-rce-vulnerabilities
description: Multiple vulnerabilities in PHP could allow unauthenticated remote code execution across various server-side interfaces, potentially leading to unauthorized system actions depending on service account privileges.
date: "2026-10-21T20:09:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
vendors:
  - PHP Group
products:
  - PHP
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Successful exploitation of the most severe of these vulnerabilities could allow for unauthenticated remote code execution.
    confidence_band: high
references:
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-php-could-allow-for-remote-code-execution_2026-119
---

Multiple vulnerabilities have been discovered in PHP, the most severe of which could allow for unauthenticated remote code execution. All PHP installations serving web requests, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP, and LiteSpeed, are considered at risk. Exploitation occurs in the context of the affected service account. Depending on the privileges associated with the service account, an attacker could install programs; view, change, or delete data; or create new accounts with full user rights.
