---
title: PHP Object Injection in FacturaScripts via WidgetSelect
slug: 2026-10-facturascripts-php-injection
description: Authenticated attackers can exploit a PHP object injection vulnerability in FacturaScripts versions prior to 2026.7 by injecting serialized objects into WidgetSelect multiple-select fields, leading to arbitrary file deletion.
date: "2026-10-05T18:48:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:facturascripts:facturascripts:*:*:*:*:*:*:*:*
tags:
  - web-application
  - php
  - rce
  - file-deletion
vendors:
  - FacturaScripts
products:
  - FacturaScripts (< 2026.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: The attacker can force a re-initialization of the application installation process.
    confidence_band: med
cves:
  - id: CVE-2026-104905
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104905
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade FacturaScripts to 2026.7 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-104905 remediation advice
  mitigation_plan:
    - priority: immediate
      action: Upgrade FacturaScripts to version 2026.7
      owner: IT Operations
      addresses: CVE-2026-104905
      evidence: NVD vulnerability disclosure
---

FacturaScripts versions prior to 2026.7 are susceptible to an insecure PHP object injection vulnerability located within the `WidgetSelect::processFormData()` method. The vulnerability arises because the application utilizes the `unserialize()` function on raw POST data submitted through multiple-select fields without implementing an `allowed_classes` filter. 

An authenticated attacker can craft a malicious serialized `XLSXWriter` object and provide it as a field value during a POST request. Upon processing, the application deserializes the input, which triggers the `__destruct()` magic method of the `XLSXWriter` class. If leveraged correctly, this mechanism allows the attacker to delete arbitrary files on the web server, specifically targeting configuration files like `config.php` or sensitive backup data. This leads to a persistent denial of service or enables the attacker to hijack the application installation process by forcing a re-initialization of the system. This vulnerability highlights the significant risks associated with using `unserialize()` on untrusted input in PHP applications.

## Impact

Successful exploitation allows for the deletion of critical application files, including `config.php`. This results in immediate denial of service (DoS) and potentially allows an attacker to hijack the FacturaScripts installation flow to gain unauthorized administrative access. The vulnerability requires authenticated access, limiting the scope to users with valid session credentials.

## Recommendation

* Update FacturaScripts to version 2026.7 or later to incorporate the patch for CVE-2026-104905.
* Restrict administrative or privileged access to the application to prevent low-privileged users from reaching vulnerable input fields.
* Review server-side file integrity and monitor for unexpected deletion events in the application's base directory.
