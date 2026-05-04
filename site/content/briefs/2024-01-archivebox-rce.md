---
title: ArchiveBox RCE via Unvalidated Configuration Overrides
slug: 2024-01-archivebox-rce
description: ArchiveBox versions 0.8.6rc0 and earlier are vulnerable to remote code execution (RCE) due to unvalidated configuration overrides in the AddView (/add/ endpoint) allowing arbitrary command execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - archivebox
vendors:
  - ArchiveBox
products:
  - archivebox (<= 0.8.6rc0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-3h23-7824-pj8r
rules:
  - title: Detect ArchiveBox Configuration Injection
    description: Detects attempts to inject malicious configurations via the /add/ endpoint by looking for suspicious values in the config parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect ArchiveBox Suspicious Process Execution via YTDLP
    description: Detects suspicious process execution via yt-dlp with injected arguments after ArchiveBox exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

ArchiveBox versions up to and including 0.8.6rc0 are susceptible to a critical remote code execution (RCE) vulnerability. The vulnerability stems from the `/add/` endpoint (AddView in `core/views.py`), which accepts a `config` JSON field. This field is merged into the crawl configuration without proper validation. When `PUBLIC_ADD_VIEW=True`, this allows unauthenticated users to inject arbitrary tool arguments, leading to command execution on the server. This is achieved by manipulating environment variables used by archive plugins like yt-dlp and gallery-dl. The endpoint is also `@csrf_exempt`, further easing exploitation. Exploitation allows attackers to execute arbitrary commands on the ArchiveBox server, potentially leading to complete system compromise.

## Attack Chain

1. An unauthenticated attacker (when `PUBLIC_ADD_VIEW=True`) sends a POST request to the `/add/` endpoint.
2. The attacker includes a `config` parameter in the POST data containing a JSON object.
3. This JSON object includes a key like `YTDLP_ARGS_EXTRA` or `GALLERYDL_ARGS_EXTRA` with a crafted value.
4. The `AddView` in `core/views.py` extracts the `config` data without validation.
5. The extracted configuration is merged into the crawl configuration.
6. The crawl configuration is exported as environment variables.
7. The yt-dlp or gallery-dl plugin executes, using the injected environment variables as arguments.
8. The attacker-controlled arguments, such as `--exec "id > /tmp/pwned"`, are passed to yt-dlp or gallery-dl, resulting in arbitrary command execution.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary commands on the ArchiveBox server. The impact includes potential for complete system compromise, data exfiltration, or denial-of-service. This vulnerability is particularly critical when the `PUBLIC_ADD_VIEW` setting is enabled, which is a common configuration for bookmarklet usage, making the attack pre-authentication.

## Recommendation

*   Upgrade to a patched version of ArchiveBox beyond 0.8.6rc0 to remediate CVE-2026-42601.
*   As a temporary mitigation, disable the `PUBLIC_ADD_VIEW` setting to prevent unauthenticated access to the vulnerable endpoint.
*   Deploy the Sigma rule "Detect ArchiveBox Configuration Injection" to identify attempts to inject malicious configurations via the `/add/` endpoint.
*   Monitor web server logs for POST requests to `/add/` containing a `config` parameter with suspicious values in keys such as `YTDLP_ARGS_EXTRA` or `GALLERYDL_ARGS_EXTRA`.
