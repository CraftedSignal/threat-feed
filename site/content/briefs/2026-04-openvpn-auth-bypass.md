---
title: OpenVPN-auth-oauth2 Authentication Bypass in Plugin Mode
slug: 2026-04-openvpn-auth-bypass
description: A critical authentication bypass vulnerability exists in openvpn-auth-oauth2 versions 1.26.3 through 1.27.2 when deployed in the experimental plugin mode; clients that do not support WebAuth/SSO are incorrectly granted VPN access without completing OIDC authentication.
date: "2026-04-22T14:29:22Z"
severities:
  - critical
tags:
  - openvpn
  - authentication-bypass
  - vpn
vendors:
  - jkroepke
products:
  - openvpn-auth-oauth2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-246w-jgmq-88fg
  - https://github.com/jkroepke/openvpn-auth-oauth2/commit/36f69a6c67c1054da7cbfa04ced3f0555127c8f2
  - https://github.com/jkroepke/openvpn-auth-oauth2/pull/829
rules:
  - title: Detect OpenVPN Connections Without WebAuth/SSO Support
    description: Detects OpenVPN connections from clients that do not advertise WebAuth/SSO support, which is indicative of a potential authentication bypass if the vulnerable plugin mode is enabled.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - firewall
      - linux
  - title: Detect OpenVPN Auth File Write Deny
    description: Detects attempts to write "0" to the auth_control_file which should trigger additional scrutiny if the plugin is misconfigured.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenVPN-auth-oauth2, a plugin for OpenVPN, is susceptible to an authentication bypass vulnerability in versions 1.26.3 through 1.27.2 when deployed in the experimental plugin mode. This flaw allows unauthenticated VPN access for clients that do not support WebAuth/SSO. Specifically, standard OpenVPN clients like the Linux CLI `openvpn`, which do not advertise WebAuth/SSO support (`IV_SSO=webauth`), can bypass OIDC authentication and gain full network access. The default management-interface…
