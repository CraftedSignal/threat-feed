---
title: Suspicious Windows Public IP Address Discovery via DNS
slug: 2026-07-windows-ip-discovery
description: Adversaries frequently use public IP lookup services to perform network reconnaissance and verify egress connectivity prior to establishing C2 channels, a behavior detectable via DNS query analysis from suspicious processes.
date: "2026-07-30T13:32:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - c2
  - windows
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: Identifies DNS queries to known public IP address lookup web services from suspicious Windows processes, which can reveal external IP or internet-connectivity discovery before follow-on activity.
    confidence_band: high
iocs:
  - type: domain
    value: ip-api.com
  - type: domain
    value: checkip.dyndns.org
  - type: domain
    value: api.ipify.org
  - type: domain
    value: api.ipify.com
  - type: domain
    value: whatismyip.akamai.com
  - type: domain
    value: bot.whatismyipaddress.com
  - type: domain
    value: ifcfg.me
  - type: domain
    value: ident.me
  - type: domain
    value: ipof.in
  - type: domain
    value: ip.tyk.nu
  - type: domain
    value: icanhazip.com
  - type: domain
    value: curlmyip.com
  - type: domain
    value: wgetip.com
  - type: domain
    value: eth0.me
  - type: domain
    value: ipecho.net
  - type: domain
    value: ip.appspot.com
  - type: domain
    value: api.myip.com
  - type: domain
    value: geoiptool.com
  - type: domain
    value: api.2ip.ua
  - type: domain
    value: api.ip.sb
  - type: domain
    value: ipinfo.io
  - type: domain
    value: checkip.amazonaws.com
  - type: domain
    value: wtfismyip.com
  - type: domain
    value: freegeoip.net
  - type: domain
    value: freegeoip.app
  - type: domain
    value: geoplugin.net
  - type: domain
    value: myip.dnsomatic.com
  - type: domain
    value: api64.ipify.org
  - type: domain
    value: ip4.seeip.org
  - type: domain
    value: api.db-ip.com
  - type: domain
    value: geolocation-db.com
  - type: domain
    value: httpbin.org
  - type: domain
    value: myip.opendns.com
ioc_counts:
  domain: 33
rules:
  - title: Detect Public IP Discovery via DNS Query
    description: Detects DNS queries to common public IP address lookup services by LOLBins or suspicious processes running from user-writable paths.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - dns_query
      - windows
rules_count: 1
---

This threat brief focuses on the behavioral pattern of Windows-based processes querying public IP address discovery web services. Threat actors utilize these lookups as an initial reconnaissance step to confirm network connectivity, determine their egress IP, or identify network environment restrictions before initiating command-and-control (C2) operations. 

The activity is particularly concerning when performed by Living-off-the-Land binaries (LOLBins) such as `powershell.exe`, `bitsadmin.exe`, or `rundll32.exe`, as well as unsigned binaries or processes executing from high-risk user-writable directories (e.g., `\Users\Public` or `\ProgramData`). Defenders must distinguish between this malicious reconnaissance and routine administrative tasks performed by managed system updaters or endpoint security agents. Because both benign and malicious software leverage the same common public IP services, detection engineering teams must utilize process lineage, code signing status, and network connection correlation to reduce false positives.

## Attack Chain

1. An attacker gains initial access or code execution on a Windows host.
2. The attacker selects a LOLBin or drops an unsigned malicious binary into a writable directory.
3. The process initiates a DNS lookup for a public IP discovery service (e.g., `api.ipify.org` or `checkip.amazonaws.com`).
4. The operating system resolves the domain via DNS, leaving an artifact in host-level network logs or Sysmon Event ID 22.
5. The process receives the resolution, verifying external internet connectivity.
6. The attacker establishes a network connection to a C2 infrastructure or exfiltrates data, often using the previously verified egress path.

## Impact

Successful reconnaissance via IP discovery services indicates that an attacker has achieved a foothold and is actively preparing for further malicious operations. If left undetected, this stage often leads to full C2 communication, internal network scanning, lateral movement, and data exfiltration. The impact varies depending on the attacker's objective, but identifying this stage provides a critical window to disrupt the attack chain before significant damage occurs.

## Recommendation

- Deploy the provided Sigma rule to detect DNS queries to known IP lookup services from suspicious processes and tune based on internal administrative software profiles.
- Enable Sysmon (specifically Event ID 22) or equivalent DNS telemetry to capture `dns.question.name` and process association.
- Correlate DNS query events with child process creation and network connection logs to identify C2 initiation.
- Do not create exceptions based solely on the IP lookup domain or process name; require verification of the process hash, code signing certificate, and parent process lineage.
