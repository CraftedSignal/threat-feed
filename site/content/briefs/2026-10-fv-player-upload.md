---
title: Arbitrary File Upload Vulnerability in FV Player 8 Plugin
slug: 2026-10-fv-player-upload
description: The FV Player 8 WordPress plugin is vulnerable to arbitrary file upload via the check_mimetype function, allowing authenticated subscribers to execute remote code via race condition exploitation.
date: "2026-10-10T07:51:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:foliovision:fv_player:*:*:*:*:*:wordpress:*:*
vendors:
  - Folio Vision
products:
  - FV Player 8 (<= 8.1.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-83526
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83526
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FV Player 8 to a version post-8.1.7
      owner: IT Operations
      due: 24h
      evidence: Source identifies 8.1.7 as the vulnerable version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade FV Player 8 to a version post-8.1.7
      owner: IT Operations
      addresses: CVE-2026-83526
      evidence: Vulnerability exists in all versions up to and including 8.1.7.
---

The FV Player 8 plugin for WordPress is vulnerable to an arbitrary file upload flaw affecting all versions up to and including 8.1.7. The vulnerability exists within the check_mimetype() function, which fails to adequately validate file types before writing user-supplied remote content to the public web-accessible uploads directory. Furthermore, the creation of new players lacks necessary capability checks, enabling authenticated attackers with subscriber-level permissions to trigger the upload process. By leveraging a race condition during the validation phase, an attacker can bypass security checks to upload executable files, ultimately achieving remote code execution (RCE) on the underlying server.

## Impact

Successful exploitation of this vulnerability allows authenticated users with minimal privileges (subscribers) to upload and execute arbitrary code on the web server. This can lead to full site compromise, unauthorized access to sensitive database information, and the potential for further lateral movement within the hosting environment.

## Recommendation

- Upgrade the FV Player 8 plugin to a version released after 8.1.7 immediately to mitigate this vulnerability.
- Review access control logs for users with 'subscriber' roles that have recently accessed the FV Player 8 plugin's player creation or file upload endpoints.
- Inspect the WordPress 'wp-content/uploads' directory for suspicious files, particularly those with executable extensions that do not align with expected media assets.
