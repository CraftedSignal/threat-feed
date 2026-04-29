---
title: OpenClaw Information Disclosure via Telegram Bot Token Exposure
slug: 2026-03-openclaw-token-leak
description: OpenClaw before version 2026.3.13 exposes Telegram bot tokens in error messages due to the fetchRemoteMedia function embedding these tokens in MediaFetchError strings when media downloads fail.
date: "2026-03-31T12:16:29Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - information-disclosure
  - vulnerability
  - telegram
cves:
  - id: CVE-2026-32982
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32982
  - https://github.com/openclaw/openclaw/commit/7a53eb7ea8295b08be137e231c9a98c1a79b5cd5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xwcj-hwhf-h378
  - https://www.vulncheck.com/advisories/openclaw-telegram-bot-token-exposure-in-media-fetch-error-logs
rules:
  - title: Detect Telegram Bot Token Leak in Logs
    description: Detects potential exposure of Telegram bot tokens in log files based on the presence of 'MediaFetchError' and 'bot[0-9]+:[A-Za-z0-9_-]+' patterns.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
  - title: Detect Telegram Bot Token in URL
    description: Detects Telegram Bot Token being passed in a URL.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.13 are susceptible to an information disclosure vulnerability (CVE-2026-32982). The vulnerability resides within the `fetchRemoteMedia` function. When OpenClaw attempts to download media from Telegram and the download fails, the application generates an error message. Critically, the original Telegram file URL, which contains the Telegram bot token, is included in the `MediaFetchError` string. This error message is then logged and potentially displayed on error surfaces, leading to the exposure of sensitive bot tokens. This vulnerability was reported on March 31, 2026, and poses a risk to OpenClaw users who leverage Telegram bots, as compromised tokens could lead to unauthorized access and control of the bots.

## Attack Chain

1. An attacker identifies an OpenClaw instance running a version prior to 2026.3.13.
2. The attacker crafts a malicious request that triggers the `fetchRemoteMedia` function to download a non-existent or inaccessible media file from Telegram.
3. The `fetchRemoteMedia` function attempts to download the media from the provided Telegram URL, which includes the bot token.
4. The download fails due to the file not being found or being inaccessible.
5. The `fetchRemoteMedia` function generates a `MediaFetchError` string that includes the original Telegram URL, containing the bot token.
6. This error message, including the Telegram bot token, is written to application logs or displayed on error surfaces (e.g., web interface).
7. An attacker gains access to the logs or error surfaces and extracts the Telegram bot token.
8. The attacker uses the compromised Telegram bot token to perform unauthorized actions via the Telegram bot, potentially leading to data theft, service disruption, or other malicious activities.

## Impact

Successful exploitation of CVE-2026-32982 can lead to the exposure of Telegram bot tokens used by OpenClaw. Compromised bot tokens allow attackers to control the associated Telegram bots, potentially leading to unauthorized data access, message manipulation, or other malicious activities. The severity of the impact depends on the permissions and capabilities of the compromised bot. While the specific number of affected OpenClaw instances is unknown, any organization using OpenClaw with Telegram bot integration is potentially at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.13 or later to remediate CVE-2026-32982.
*   Review existing OpenClaw logs for any instances of `MediaFetchError` strings containing Telegram bot tokens.
*   Implement stricter access controls on OpenClaw logs to prevent unauthorized access to sensitive information.
*   Deploy the Sigma rule `Detect Telegram Bot Token Leak in Logs` to identify potential token exposure in log files.
