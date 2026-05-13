---
title: RTMKit Addons for Elementor WordPress Plugin LFI Vulnerability (CVE-2026-3425)
slug: 2026-05-rtmkit-lfi
description: The RTMKit Addons for Elementor plugin for WordPress is vulnerable to local file inclusion (LFI) via the 'path' parameter in the 'get_content' AJAX action, allowing authenticated attackers with Author-level access or higher to include and execute arbitrary PHP files, leading to potential code execution.
date: "2026-05-13T15:51:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lfi
  - wordpress
  - plugin
  - cve-2026-3425
vendors:
  - WordPress
products:
  - RTMKit Addons for Elementor plugin <= 2.0.2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3425
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3425
rules:
  - title: Detect CVE-2026-3425 Exploitation — RTMKit LFI Attempt
    description: Detects CVE-2026-3425 exploitation — Local File Inclusion attempt via the 'path' parameter in the RTMKit Addons for Elementor plugin's 'get_content' AJAX action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The RTMKit Addons for Elementor plugin, a popular WordPress extension, contains a local file inclusion vulnerability (CVE-2026-3425) affecting versions up to and including 2.0.2. This flaw resides within the 'get_content' AJAX action, specifically through the 'path' parameter. Authenticated users with Author-level privileges or higher can exploit this vulnerability to include and execute arbitrary PHP files residing on the server. This can enable attackers to bypass access controls, obtain sensitive data, or ultimately achieve remote code execution by including uploaded PHP files. This vulnerability poses a significant risk to WordPress websites utilizing the affected plugin.

## Attack Chain

1. An attacker authenticates to the WordPress site with Author-level or higher privileges.
2. The attacker crafts a malicious HTTP request targeting the 'admin-ajax.php' endpoint.
3. The request includes the 'action' parameter set to 'get_content'.
4. The attacker manipulates the 'path' parameter within the request, setting it to point to a sensitive local file or an uploaded PHP file.
5. The server processes the request and includes the specified file.
6. If the included file is a PHP file, the server executes the PHP code.
7. The attacker can leverage this to read sensitive data from the server, such as configuration files.
8. Alternatively, the attacker could upload a PHP file (e.g., through a separate vulnerability or misconfiguration) and then include it using the LFI vulnerability, achieving arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-3425 allows attackers with Author-level access to bypass access controls and execute arbitrary PHP code on the WordPress server. This could lead to the compromise of sensitive data, defacement of the website, or complete takeover of the server. The number of potentially affected websites is significant, given the widespread use of WordPress and the RTMKit Addons for Elementor plugin.

## Recommendation

*   Upgrade the RTMKit Addons for Elementor plugin to a version greater than 2.0.2 to patch CVE-2026-3425.
*   Deploy the Sigma rule "Detect CVE-2026-3425 Exploitation — RTMKit LFI Attempt" to your SIEM and tune for your environment.
*   Monitor web server logs for requests to 'admin-ajax.php' with the 'action' parameter set to 'get_content' and suspicious values in the 'path' parameter, using the file paths and extensions in the detection rule as a reference.
