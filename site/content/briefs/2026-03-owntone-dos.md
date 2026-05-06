---
title: OwnTone Server DAAP Request NULL Pointer Dereference Denial-of-Service (CVE-2026-26828)
slug: 2026-03-owntone-dos
description: A NULL pointer dereference vulnerability in the daap_reply_playlists function of owntone-server allows attackers to cause a Denial of Service (DoS) by sending a crafted DAAP request.
date: "2026-03-24T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-26828
  - denial-of-service
  - owntone-server
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26828
  - https://github.com/archersec/security-advisories/blob/master/owntone-server/owntone-server-advisory-2026.md
  - https://github.com/owntone/owntone-server/commit/9ac54f0b42491c4862791db4c5368ff80c4000d3
  - https://github.com/owntone/owntone-server/issues/1961
rules:
  - title: Detect Suspicious DAAP Requests
    description: Detects suspicious DAAP requests based on HTTP request characteristics.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed HTTP Requests to owntone server
    description: Detects multiple failed HTTP requests to owntone server, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-26828 describes a NULL pointer dereference vulnerability in the `daap_reply_playlists` function (src/httpd_daap.c) of owntone-server. The vulnerability resides in commit 3d1652d of the owntone-server project. Attackers can exploit this vulnerability by sending a crafted Digital Audio Access Protocol (DAAP) request to the server, leading to a denial-of-service (DoS) condition. This vulnerability allows unauthenticated remote attackers to disrupt the availability of the owntone-server…
