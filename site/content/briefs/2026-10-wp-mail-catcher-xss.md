---
title: Stored XSS in WP Mail Catcher WordPress Plugin
slug: 2026-10-wp-mail-catcher-xss
description: The WP Mail Catcher plugin for WordPress is vulnerable to stored cross-site scripting (XSS) via inadequate sanitization of PHPMailer error messages, allowing unauthenticated attackers to execute arbitrary scripts in the context of administrative sessions.
date: "2026-10-03T08:54:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:mail_logging_wp_mail_catcher:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - xss
vendors:
  - WordPress
products:
  - Mail logging – WP Mail Catcher (<= 2.1.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can leverage other plugins, such as Contact Form 7, to inject malicious scripts into mail fields, which are then rendered and executed.
    confidence_band: high
cves:
  - id: CVE-2026-93889
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93889
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade WP Mail Catcher to a version beyond 2.1.12
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability exists in all versions up to and including 2.1.12
  mitigation_plan:
    - priority: immediate
      action: Disable WP Mail Catcher if update cannot be applied
      owner: IT Operations
      addresses: CVE-2026-93889
      evidence: Source identifies plugin as the root cause of the vulnerability
---

The Mail logging - WP Mail Catcher plugin for WordPress, in versions up to and including 2.1.12, contains a stored cross-site scripting (XSS) vulnerability. The issue stems from insufficient input sanitization and output escaping within the 'wp_mail_failed' hook, which handles PHPMailer error messages. 

Attackers can leverage this vulnerability by injecting malicious scripts into mail fields via other plugins, such as Contact Form 7, that pass unauthenticated, user-controlled input to the WordPress mail system. When PHPMailer fails to send an email, it includes the malicious payload within the error message, which is subsequently logged by the WP Mail Catcher plugin. When an administrator or authorized user views the mail logs within the WordPress dashboard, the injected script executes in their browser. This allows for session hijacking, administrative action manipulation, or further credential theft within the WordPress environment.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of any user who views the mail logs. In typical WordPress deployments, this targets administrative users, potentially leading to full site compromise, unauthorized configuration changes, or the installation of malicious plugins.

## Recommendation

Update the WP Mail Catcher plugin to a version released after 2.1.12 that includes proper sanitization of the 'wp_mail_failed' error output. If an update is not immediately available, disable the plugin or restrict access to the mail logs page to only highly trusted administrative users.
