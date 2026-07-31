---
title: Arbitrary File Upload Vulnerability in Realtyna Organic IDX Plugin
slug: 2026-07-realtyna-idx-upload
description: The Realtyna Organic IDX plugin for WordPress contains an arbitrary file upload vulnerability (CVE-2026-16236) due to improper validation and authentication, allowing remote attackers to achieve remote code execution.
date: "2026-07-31T07:36:25Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Realtyna
products:
  - Organic IDX (<= 5.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers, with subscriber-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for authenticated attackers... to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-16236
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16236
---

The Realtyna Organic IDX plugin for WordPress, in versions up to and including 5.3.0, is susceptible to an arbitrary file upload vulnerability. This vulnerability originates from the saveLiveImages() function, which fails to implement necessary file extension and content validation. Additionally, the plugin exhibits insufficient authorization checks within the get_keys() AJAX handler and a complete lack of authentication checks on the REST API import endpoint. 

These security flaws permit an authenticated attacker, holding at least subscriber-level privileges, to upload malicious files to the server. By bypassing these checks, an attacker can upload web shells or other malicious scripts, which can then be executed to gain remote code execution (RCE) on the underlying WordPress server. This poses a significant risk to the integrity and confidentiality of the host environment, as it effectively provides a pathway for unauthorized code execution within the web context.

## Attack Chain

1. Attacker registers or gains access to a subscriber-level account on a WordPress site utilizing Organic IDX <= 5.3.0.
2. Attacker targets the insecure REST API import endpoint or the get_keys() AJAX handler to initiate an interaction.
3. Attacker crafts a malicious payload, such as a PHP web shell, encapsulated within a file upload request.
4. Attacker sends an HTTP POST request to the vulnerable endpoint, bypassing the insufficient authentication controls.
5. The saveLiveImages() function fails to validate the file extension or content, allowing the server to save the malicious file to the web root.
6. Attacker navigates to the uploaded file path via a browser or script to trigger the execution of the embedded code.
7. The server executes the malicious script under the context of the web server user.
8. Attacker gains persistence or performs further post-exploitation activities such as data exfiltration.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to upload arbitrary files, leading to potential remote code execution. This can result in a full site compromise, sensitive data theft, and the ability to pivot into the underlying server network. All WordPress sites running the Organic IDX plugin version 5.3.0 or earlier are currently at risk.

## Recommendation

* Immediately update the Realtyna Organic IDX plugin to the latest version that patches CVE-2026-16236.
* Disable the Realtyna Organic IDX plugin until a security update is applied if patching cannot be performed immediately.
* Audit web server logs for suspicious POST requests targeting /wp-json/ or specific AJAX handler endpoints that result in file creation in public directories.
* Restrict access to the WordPress dashboard and administrative REST API endpoints to known, trusted IP addresses to prevent unauthorized access by potential attackers.
