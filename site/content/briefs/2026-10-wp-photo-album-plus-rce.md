---
title: Authenticated Command Injection in WP Photo Album Plus
slug: 2026-10-wp-photo-album-plus-rce
description: Authenticated users with specific plugin privileges can achieve remote code execution in WP Photo Album Plus via command injection in the update-photo AJAX action.
date: "2026-10-16T08:25:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wppa:wp_photo_album_plus:*:*:*:*:*:wordpress:*:*
vendors:
  - WP Photo Album Plus
products:
  - WP Photo Album Plus (<= 9.3.02.002)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users with the wppa_upload capability can leverage this to execute arbitrary OS commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The attacker-controlled value parameter is concatenated raw into an ImageMagick command string before being passed to exec().
    confidence_band: high
cves:
  - id: CVE-2026-92115
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92115
rules:
  - title: Detect CVE-2026-92115 Exploitation - Command Injection via update-photo
    description: Detects potential command injection attempts targeting the WP Photo Album Plus update-photo AJAX action by identifying shell metacharacters in the value parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update WP Photo Album Plus to latest version
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 9.3.02.002
  mitigation_plan:
    - priority: immediate
      action: Review and restrict 'wppa_upload' user capability
      owner: IT Operations
      addresses: CVE-2026-92115
      evidence: Exploitation requires 'wppa_upload' capability
---

The WP Photo Album Plus plugin for WordPress contains an authenticated command injection vulnerability (CVE-2026-92115) affecting all versions up to and including 9.3.02.002. The flaw exists within the wppa_image_magick_a() function, which fails to apply proper shell escaping when processing the 'value' parameter of the 'update-photo' AJAX action. Instead of using escapeshellarg(), the application concatenates attacker-supplied input directly into an ImageMagick command string executed via the exec() function. Furthermore, the wppa_decode() utility restores percent-encoded shell metacharacters, allowing payloads to break out of the intended argument context. Any user assigned the wppa_upload capability, which can be granted to lower-privileged roles by site administrators, can exploit this flaw to run OS commands as the web-server process. This impact is contingent on the server having ImageMagick installed and active.

## Impact

Successful exploitation allows authenticated attackers to gain remote code execution on the underlying server. Depending on server configuration, this may lead to full site compromise, lateral movement within the network, or unauthorized data access. The breadth of potential attackers is increased because the 'wppa_upload' capability is not restricted solely to WordPress administrators.

## Recommendation

* Update the WP Photo Album Plus plugin to a version released after 9.3.02.002 immediately to remediate CVE-2026-92115.
* Review WordPress user roles and capabilities to identify accounts possessing the 'wppa_upload' privilege and revoke access for non-essential users.
* Monitor web server logs for HTTP POST requests to the 'update-photo' AJAX action containing unusual characters such as semicolons, pipes, or ampersands in the 'value' parameter.
