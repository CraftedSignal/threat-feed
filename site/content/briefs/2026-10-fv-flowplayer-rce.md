---
title: Arbitrary File Upload in FV Flowplayer Video Player Plugin
slug: 2026-10-fv-flowplayer-rce
description: Authenticated users can achieve remote code execution in FV Flowplayer Video Player for WordPress <= 7.5.54.7212 by bypassing incomplete file type validation in the check_mimetype function.
date: "2026-10-14T18:45:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fv_flowplayer_video_player_project:fv_flowplayer_video_player:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - FV Flowplayer Video Player (<= 7.5.54.7212)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated attackers can upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for authenticated attackers... to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-86461
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86461
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update FV Flowplayer Video Player plugin to 7.5.54.7213 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-86461 requires patching the vulnerable check_mimetype function
  mitigation_plan:
    - priority: immediate
      action: Disable 'profile videos on bio' option
      owner: IT Operations
      addresses: CVE-2026-86461
      evidence: The exploit requires the 'profile videos on bio' option to be enabled
---

The FV Flowplayer Video Player plugin for WordPress, in versions up to and including 7.5.54.7212, is vulnerable to an arbitrary file upload flaw within the 'check_mimetype' function. The vulnerability arises from inadequate validation of user-supplied file uploads. Although the function implements basic extension checking, it lacks robust enforcement, allowing authenticated attackers with subscriber-level permissions to bypass security controls. 

To successfully exploit this vulnerability, the target WordPress instance must have the 'profile videos on bio' option enabled. This configuration forces the application to expose a required nonce on the user profile page, which is accessible to subscriber-level users. Without this nonce, unauthorized users cannot execute the upload request. If successful, an attacker can upload executable files to the server, ultimately resulting in remote code execution (RCE). The impact is significant as it allows low-privileged users to achieve full system compromise.

## Impact

Successful exploitation allows an authenticated user with subscriber-level access to gain remote code execution on the underlying server. This enables potential unauthorized access to sensitive site data, administrative control over the WordPress instance, and lateral movement within the hosting environment. This affects all WordPress instances using the vulnerable plugin version with the specific profile video feature enabled.

## Recommendation

* Immediately update the FV Flowplayer Video Player plugin to version 7.5.54.7213 or higher.
* Audit WordPress installations for active plugins with the 'profile videos on bio' option enabled; disable this feature until the plugin is patched.
* Review access control lists for subscriber-level users to ensure minimal permissions are granted on the target WordPress instance.
* Monitor web server logs for suspicious POST requests targeting plugin-specific upload endpoints, especially those involving non-image file extensions.
