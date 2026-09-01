---
title: Arbitrary File Upload in Master Addons for Elementor
slug: 2026-09-master-addons-rce
description: An improper authorization flaw in the Master Addons for Elementor WordPress plugin allows authenticated users with editor-level access to achieve remote code execution via arbitrary file uploads.
date: "2026-09-01T07:03:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:master-addons:master_addons_for_elementor:*:*:*:*:*:wordpress:*:*
vendors:
  - Master Addons
products:
  - Master Addons for Elementor (<= 3.1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with editor-level access and above, to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for authenticated attackers, with editor-level access and above, to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-75921
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75921
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Master Addons for Elementor to a version beyond 3.1.9.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-75921 vulnerability in versions <= 3.1.9
  mitigation_plan:
    - priority: immediate
      action: Review and downgrade permissions for users with 'editor' access until the patch is applied.
      owner: IT Operations
      addresses: CVE-2026-75921
      evidence: Exploit requires editor-level access
---

The Master Addons for Elementor plugin for WordPress (versions 3.1.9 and earlier) contains an arbitrary file upload vulnerability within the upload_template_kit AJAX handler. The vulnerability stems from insufficient authorization requirements; the handler checks for 'upload_files' capability rather than the stricter 'manage_options' required by other administrative handlers in the plugin. Furthermore, the handler fails to implement adequate file type validation after the extraction of uploaded ZIP archives. An attacker with editor-level privileges can obtain the necessary nonces from the pages list screen and subsequently upload arbitrary, potentially executable files. This vulnerability enables authenticated attackers to execute arbitrary code on the underlying WordPress server.

## Impact

Successful exploitation of CVE-2026-75921 grants an authenticated attacker with editor-level access the ability to execute remote code on the host server. This can lead to full site compromise, exfiltration of sensitive database information, or the establishment of persistent backdoors within the WordPress environment.

## Recommendation

- Upgrade the Master Addons for Elementor plugin to the latest available version (beyond 3.1.9) to patch the authorization logic and file validation routines.
- Review WordPress user accounts and restrict editor-level permissions to trusted individuals to mitigate the potential impact of this credential-dependent vulnerability.
- Audit web server logs for suspicious POST requests to the plugin's AJAX endpoints if indicators of compromise are suspected.
