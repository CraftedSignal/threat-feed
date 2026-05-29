---
title: Koel SSRF Vulnerability via Podcast Episode Enclosure URLs (CVE-2026-47260)
slug: 2026-05-koel-ssrf
description: Koel is vulnerable to Server-Side Request Forgery (SSRF) due to insufficient validation of podcast episode enclosure URLs, allowing a remote attacker to inject a malicious URL into the enclosure field of a podcast RSS feed, leading to internal network reconnaissance and potential credential theft; this issue is tracked as CVE-2026-47260.
date: "2026-05-29T19:56:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - koel
  - podcast
  - cloud
vendors:
  - composer
products:
  - koel (<= 9.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-7j2f-6h2r-6cqc
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  - type: url
    value: https://evil.com/feed.xml
  - type: url
    value: https://attacker.com/feed.xml
ioc_counts:
  url: 3
rules:
  - title: Detect Koel SSRF via AWS Metadata Endpoint
    description: Detects CVE-2026-47260 exploitation — Attempts to access AWS metadata endpoint via podcast enclosure URL
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Koel SSRF via Podcast Subscription to External Domain
    description: Detects CVE-2026-47260 exploitation — Subscription to a podcast feed from a non-internal IP address or domain.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Koel, a personal music streaming server, is vulnerable to Server-Side Request Forgery (SSRF) due to a flaw in how podcast episode enclosure URLs are handled. Specifically, while the podcast feed URL itself is validated, the individual episode enclosure URLs extracted from the RSS XML are stored and later used without proper validation. This allows an attacker to host a malicious RSS feed with enclosure URLs pointing to internal resources. When a user plays an episode from this feed, the Koel server attempts to download the full content from the attacker-specified URL, which can be an internal service. The server then streams the response back to the user, effectively granting the attacker full-read SSRF capabilities. This vulnerability affects Koel versions 9.3.4 and earlier. An additional SSRF bypass exists via the AI radio station tool, requiring a Plus license.

## Attack Chain

1.  Attacker registers an account on the Koel server.
2.  Attacker crafts a malicious RSS feed hosted on a public server, containing an episode with an enclosure URL pointing to an internal resource (e.g., AWS metadata endpoint at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
3.  Attacker subscribes to the malicious podcast feed by sending a `POST` request to `/api/podcasts` with the `url` parameter set to the malicious feed URL (e.g., `https://evil.com/feed.xml`). This step passes the `SafeUrl` validation, which only checks the feed URL itself.
4.  Koel parses the malicious feed and stores the episode with the attacker-controlled `path`.
5.  A user, or the attacker, attempts to play the episode by sending a `GET` request to `/play/{episode_id}`.
6.  The server executes `Http::sink($file)->get("http://169.254.169.254/...")`, attempting to download the full content from the malicious enclosure URL.
7.  The response from the internal resource (e.g., AWS metadata) is downloaded to a temporary file.
8.  The contents of the file are streamed back to the user, enabling the attacker to access sensitive information.

## Impact

Successful exploitation of this SSRF vulnerability can lead to:
- Theft of cloud credentials by reading AWS/GCP/Azure metadata endpoints.
- Internal network reconnaissance by scanning ports and enumerating internal HTTP services.
- Data exfiltration by reading responses from internal APIs, admin panels, and databases with HTTP interfaces.
- The entire response body from the internal service is returned to the attacker, providing more comprehensive access compared to blind SSRF.

## Recommendation

- Deploy the Sigma rule `Detect Koel SSRF via AWS Metadata Endpoint` to identify attempts to access the AWS metadata endpoint via the podcast enclosure URL.
- Block the malicious RSS feed URLs observed in the `iocs` section at the network perimeter.
- Apply the remediation steps outlined in the source to validate episode enclosure URLs in `synchronizeEpisodes()` and add defense-in-depth validation at playback time in `EpisodePlayable::createForEpisode()`.
- Apply `SafeUrl` validation in `AddRadioStation` AI tool to prevent SSRF via the AI assistant.
