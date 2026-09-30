---
title: Local File Inclusion in Simply Schedule Appointments WordPress Plugin
slug: 2026-09-lfi-simply-schedule-appointments
description: An unauthenticated Local File Inclusion (LFI) vulnerability in the Simply Schedule Appointments WordPress plugin allows attackers to execute arbitrary PHP code.
date: "2026-09-30T08:33:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:simply_schedule_appointments:simply_schedule_appointments:*:*:*:*:*:wordpress:*:*
vendors:
  - Simply Schedule Appointments
products:
  - Simply Schedule Appointments (<= 1.6.12.27)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This makes it possible for authenticated attackers... to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-89294
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89294
rules:
  - title: Detects CVE-2026-89294 Exploitation - Unauthenticated LFI via ssa_locale
    description: Detects attempts to exploit CVE-2026-89294 by identifying suspicious directory traversal characters in the ssa_locale parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1210
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Simply Schedule Appointments to version > 1.6.12.27
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 1.6.12.27
  hunt_leads:
    - lead: Search logs for ssa_locale parameter with directory traversal sequences.
      technique_id: T1210
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-89294 LFI vulnerability
  mitigation_plan:
    - priority: immediate
      action: Disable Simply Schedule Appointments if patching is not possible.
      owner: IT Operations
      addresses: CVE-2026-89294
      evidence: LFI allows arbitrary code execution
---

The Simply Schedule Appointments plugin for WordPress is vulnerable to Local File Inclusion (LFI) in all versions up to and including 1.6.12.27. The flaw originates from the 'ssa_locale' parameter, which is processed by a locale filter installed during the 'plugins_loaded' hook. Crucially, the plugin implementation fails to perform any nonce or capability validation on this parameter, processing it unconditionally on every incoming request. This design failure allows an unauthenticated remote attacker to manipulate the file inclusion path, potentially enabling the inclusion and execution of arbitrary .php files residing on the server. Successful exploitation can lead to full remote code execution, unauthorized access to sensitive application data, and the bypass of established WordPress access controls. Defenders should prioritize patching or disabling the plugin until an update is confirmed, as the lack of authentication requirements significantly lowers the barrier for exploitation.

## Attack Chain

1. Attacker identifies a WordPress site running the vulnerable Simply Schedule Appointments plugin (<= 1.6.12.27).
2. Attacker crafts an HTTP GET or POST request targeting the site, injecting a malicious path into the 'ssa_locale' parameter.
3. The 'plugins_loaded' hook fires upon the request reaching the WordPress server.
4. The vulnerable filter processes the 'ssa_locale' value without authorization checks, resolving the path to a local target file.
5. The server attempts to include the specified file as a PHP script.
6. The attacker leverages a previously uploaded or existing local .php file (e.g., via a separate file upload vulnerability or log injection) to achieve arbitrary code execution.
7. Attacker executes system commands to exfiltrate database credentials or establish a persistent backdoor.

## Impact

The vulnerability poses a severe threat to any WordPress installation using affected versions of Simply Schedule Appointments. Successful exploitation results in remote code execution, allowing attackers to compromise the underlying web server, steal sensitive configuration data, or gain administrative access to the WordPress environment. Given the ubiquity of WordPress plugins, this flaw represents a significant risk to organizations across all sectors that rely on this plugin for scheduling or appointment management.

## Recommendation

- Immediately update the Simply Schedule Appointments plugin to a patched version once released by the vendor.
- Until a patch is applied, disable the Simply Schedule Appointments plugin to mitigate the risk of unauthenticated LFI.
- Deploy Web Application Firewall (WAF) rules to detect and block requests containing suspicious paths or directory traversal sequences (e.g., ../, /etc/passwd) in the 'ssa_locale' parameter.
- Review web server access logs for any anomalous requests involving the 'ssa_locale' parameter targeting system-level files or hidden directories.
