---
title: AudioIgniter WordPress Plugin Vulnerable to Insecure Direct Object Reference (CVE-2026-8679)
slug: 2026-05-audioigniter-idor
description: The AudioIgniter plugin for WordPress is vulnerable to Insecure Direct Object Reference (CVE-2026-8679) in versions up to 2.0.2, allowing unauthenticated attackers to view track metadata of any playlist, regardless of its status.
date: "2026-05-22T09:18:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - idor
  - wordpress
  - plugin
  - cve-2026-8679
  - vulnerability
vendors:
  - WordPress
products:
  - AudioIgniter plugin for WordPress <= 2.0.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8679
rules:
  - title: Detect AudioIgniter Playlist IDOR Attempt via URL
    description: Detects CVE-2026-8679 exploitation — attempts to access AudioIgniter playlists via URL IDOR vulnerability by monitoring requests to the /audioigniter/playlist/{id}/ endpoint
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect AudioIgniter Playlist IDOR Attempt via Query Parameter
    description: Detects CVE-2026-8679 exploitation — attempts to access AudioIgniter playlists via query parameter IDOR vulnerability by monitoring requests using the audioigniter_playlist_id query parameter
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

The AudioIgniter plugin for WordPress, in versions up to and including 2.0.2, suffers from an Insecure Direct Object Reference (IDOR) vulnerability identified as CVE-2026-8679. This flaw resides within the `handle_playlist_endpoint()` function, which is hooked to `template_redirect`. The function accepts a user-controlled playlist ID either through the `audioigniter_playlist_id` query variable or via the `/audioigniter/playlist/{id}/` rewrite rule. The vulnerability stems from the lack of authentication, capability, or post status checks within this function, only validating the post type. Consequently, unauthenticated attackers can retrieve sensitive track metadata, including titles, artists, audio URLs, buy links, download URLs, and cover images, for any playlist on the site, even those marked as draft, private, pending, or trashed.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the AudioIgniter plugin (<= 2.0.2).
2. The attacker crafts a malicious URL targeting the `/audioigniter/playlist/{id}/` endpoint or by providing the `audioigniter_playlist_id` query parameter.
3. The attacker guesses or discovers the ID of a playlist on the targeted WordPress site. This could be achieved through brute-force or by examining publicly accessible playlist pages.
4. The attacker sends an HTTP GET request to the crafted URL, including the targeted playlist ID.
5. The `handle_playlist_endpoint()` function processes the request without proper authorization checks.
6. The function retrieves track metadata associated with the specified playlist ID from the WordPress database.
7. The metadata, including titles, artists, audio URLs, buy links, download URLs, and cover images, is returned to the attacker in the HTTP response.
8. The attacker gains unauthorized access to sensitive playlist information, even for playlists that should be restricted.

## Impact

Successful exploitation of CVE-2026-8679 allows unauthenticated attackers to access sensitive track metadata associated with any playlist on the vulnerable WordPress site. This includes information about draft, private, or trashed playlists that should not be publicly accessible. The exposure of audio URLs and download URLs could lead to unauthorized access and distribution of copyrighted content. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity. The number of affected sites is dependent on the adoption rate of the vulnerable AudioIgniter plugin version.

## Recommendation

*   Deploy the Sigma rule `Detect AudioIgniter Playlist IDOR Attempt via URL` to identify suspicious requests to the `/audioigniter/playlist/{id}/` endpoint (see "rules" section).
*   Deploy the Sigma rule `Detect AudioIgniter Playlist IDOR Attempt via Query Parameter` to identify suspicious requests using the `audioigniter_playlist_id` query parameter (see "rules" section).
*   Upgrade the AudioIgniter plugin to a version greater than 2.0.2 to patch CVE-2026-8679.
*   Monitor web server logs for requests to the `/audioigniter/playlist/{id}/` endpoint or using the `audioigniter_playlist_id` query parameter with unusual playlist IDs (see "references" section for URL).
