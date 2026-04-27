---
title: OpenSSH GSSAPI Vulnerability Leads to Potential Denial-of-Service
slug: 2026-04-openssh-gssapi-dos
description: A remote, anonymous attacker can exploit a vulnerability in OpenSSH GSSAPI and Ubuntu Linux to trigger undefined behavior or a potential denial-of-service attack.
date: "2026-04-07T10:16:06Z"
severities:
  - medium
tags:
  - openssh
  - gssapi
  - denial-of-service
  - linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0716
rules:
  - title: Detect Suspicious SSH GSSAPI Authentication
    description: Detects SSH connections using GSSAPI authentication, which might indicate exploitation attempts targeting the OpenSSH GSSAPI vulnerability.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.002
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenSSH GSSAPI Authentication Failures
    description: Detects failed GSSAPI authentication attempts in OpenSSH logs, which could be a sign of vulnerability exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists within the GSSAPI implementation of OpenSSH, potentially affecting Ubuntu Linux systems. According to the BSI advisory published on April 7, 2026, an anonymous remote attacker can exploit this vulnerability. The specifics of the vulnerability are not detailed in the advisory, but successful exploitation could lead to undefined behavior or a denial-of-service condition on the targeted system. This is a significant concern for organizations relying on OpenSSH for secure…
