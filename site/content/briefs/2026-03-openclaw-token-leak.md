---
title: OpenClaw Information Disclosure via Telegram Bot Token Exposure
slug: 2026-03-openclaw-token-leak
description: OpenClaw before version 2026.3.13 exposes Telegram bot tokens in error messages due to the fetchRemoteMedia function embedding these tokens in MediaFetchError strings when media downloads fail.
date: "2026-03-31T12:16:29Z"
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

OpenClaw versions prior to 2026.3.13 are susceptible to an information disclosure vulnerability (CVE-2026-32982). The vulnerability resides within the `fetchRemoteMedia` function. When OpenClaw attempts to download media from Telegram and the download fails, the application generates an error message. Critically, the original Telegram file URL, which contains the Telegram bot token, is included in the `MediaFetchError` string. This error message is then logged and potentially displayed on error…
