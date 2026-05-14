---
title: Open WebUI Stored XSS Vulnerability via Audio Transcription Endpoint (CVE-2026-45315)
slug: 2026-05-open-webui-xss
description: Open WebUI is vulnerable to stored XSS via an attacker-controlled file extension in the /api/v1/audio/transcriptions endpoint (CVE-2026-45315), allowing a verified user with the chat.stt permission to upload a polyglot WAV+HTML file, tricking other users into executing arbitrary script code within the Open WebUI origin, leading to session token theft and full account takeover.
date: "2026-05-14T20:20:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - stored xss
  - open webui
  - cve-2026-45315
vendors:
  - Open WebUI
products:
  - open-webui (<= 0.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-m8f9-9whg-f4xr
  - CVE-2026-45315
rules:
  - title: Detect CVE-2026-45315 Exploitation Attempt — Open WebUI Audio Transcription XSS
    description: Detects attempts to exploit CVE-2026-45315, the Open WebUI audio transcription XSS vulnerability, by monitoring for uploads of files with HTML extensions to the audio transcription endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45315 Exploitation — Open WebUI Serving HTML from Cache Directory
    description: Detects potential exploitation of CVE-2026-45315 by monitoring for requests serving HTML files from the Open WebUI cache directory.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

Open WebUI version 0.9.2 and earlier is vulnerable to a stored cross-site scripting (XSS) attack. The vulnerability resides in the `/api/v1/audio/transcriptions` endpoint, which allows users to upload audio files for transcription. An attacker with a verified account and the default-enabled `chat.stt` permission can upload a specially crafted file disguised as audio but containing malicious HTML and JavaScript code. The server saves the file with an extension derived directly from the user-supplied filename without proper validation, enabling the stored XSS.

## Attack Chain

1. An attacker with a verified user account authenticates to the Open WebUI instance.
2. The attacker crafts a polyglot WAV+HTML file, containing both valid WAV audio data and embedded JavaScript code designed for XSS.
3. The attacker uploads the malicious file to the `/api/v1/audio/transcriptions` endpoint, naming the file with an `.html` extension (e.g., `pwn.html`).
4. The server saves the file to the `CACHE_DIR/audio/transcriptions/` directory, using the attacker-supplied `.html` extension.
5. The server generates a unique identifier (UUID) for the file and constructs the final file path using the UUID and the attacker-supplied extension.
6. A victim user clicks a link to the cached file served by the `/cache/{path}` route (e.g., `/cache/audio/transcriptions/<uuid>.html`).
7. The server serves the file with a `Content-Type: text/html` header based on the `.html` extension.
8. The victim's browser executes the embedded JavaScript code in the context of the Open WebUI origin, allowing the attacker to steal sensitive information, such as the JWT token stored in `localStorage`, leading to account takeover.

## Impact

This stored XSS vulnerability (CVE-2026-45315) allows an attacker to execute arbitrary JavaScript code within the Open WebUI application on behalf of a victim user. An attacker can steal the victim's session token (JWT), which is stored in `localStorage`, and the OAuth token cookie is non-HttpOnly, gaining complete control over the victim's account. This includes the ability to view sensitive data, modify settings, and perform actions as the compromised user. Exploitation requires only a single click by the victim.

## Recommendation

*   Apply the patch or upgrade to a version of Open WebUI greater than 0.9.2 to remediate CVE-2026-45315.
*   Implement strict validation of file extensions and MIME types on the `/api/v1/audio/transcriptions` endpoint to prevent uploading of malicious files.
*   Configure the `/cache/{path}` route to force `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` to prevent the browser from interpreting files based on their content.
*   Move the JWT token to an `HttpOnly` cookie to prevent JavaScript code from accessing it.
*   Set the `SameSite` attribute for the OAuth token cookie to `Lax` to mitigate cross-site request forgery (CSRF) attacks.
*   As a workaround, set `USER_PERMISSIONS_CHAT_STT=False` to revoke upload rights from non-administrators.
