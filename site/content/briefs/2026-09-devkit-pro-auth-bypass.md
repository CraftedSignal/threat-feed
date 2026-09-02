---
title: Unauthorized Remote Code Execution in DevKit Pro Plugin for WordPress
slug: 2026-09-devkit-pro-auth-bypass
description: The DevKit Pro plugin for WordPress versions 2.3.0 and earlier contains an authorization vulnerability that allows authenticated attackers to perform remote code execution via arbitrary theme installation.
date: "2026-09-02T07:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:devkit_pro:devkit_pro:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - rce
  - webserver
vendors:
  - DevKit Pro
products:
  - DevKit Pro (<= 2.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to install arbitrary theme ZIP packages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: extracted into the web-accessible wp-content/themes/ directory, which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-14357
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14357
rules:
  - title: Detects CVE-2026-14357 Exploitation - WordPress Admin Ajax Theme Installation
    description: Detects potential exploitation of CVE-2026-14357 by monitoring for AJAX calls to the install themes function.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update DevKit Pro plugin on all WordPress instances to version > 2.3.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-14357 advisory
    - action: Deploy WAF rule to block unauthorized DPDEV_install_themes actions
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies the specific AJAX action triggering the flaw
  mitigation_plan:
    - priority: immediate
      action: Upgrade DevKit Pro to version above 2.3.0
      owner: IT Operations
      addresses: CVE-2026-14357
      evidence: NVD advisory
---

The DevKit Pro plugin for WordPress is vulnerable to an authorization flaw identified as CVE-2026-14357. The vulnerability exists within the DPDEV_install_themes_func() function, which is registered to the wp_ajax_DPDEV_install_themes action. The function lacks proper capability checks and nonce validation, allowing any authenticated user - including those with low-privilege 'Subscriber' access - to trigger the theme installation process. By submitting a crafted request, an attacker can upload and extract an arbitrary ZIP package containing PHP files directly into the web-accessible 'wp-content/themes/' directory of the WordPress instance. Because these files are then accessible via the web server, this flaw directly facilitates remote code execution (RCE). This issue affects all versions of the DevKit Pro plugin up to and including 2.3.0.

## Impact

Successful exploitation allows an unprivileged attacker to achieve remote code execution on the WordPress server. This could lead to full site compromise, data exfiltration, or lateral movement within the hosting environment. Organizations using affected versions of the DevKit Pro plugin are at high risk of unauthorized administrative control over their web infrastructure.

## Recommendation

1. Immediately update the DevKit Pro plugin to the latest available version beyond 2.3.0 to patch CVE-2026-14357.
2. Implement a Web Application Firewall (WAF) rule to monitor or block POST requests to 'wp-admin/admin-ajax.php' containing the 'action=DPDEV_install_themes' parameter if the update cannot be applied immediately.
3. Audit the 'wp-content/themes/' directory for any unauthorized or suspicious subdirectories or PHP files added by low-privileged user accounts.
