---
title: Phishing Campaign Abusing Google Cloud Storage Redirectors
slug: 2026-03-google-cloud-storage-redirector
description: A phishing campaign leverages Google Cloud Storage as a redirect layer to serve victims scam pages related to surveys, giveaways, rewards, alerts, and job lures, primarily hosted on .autos domains.
date: "2026-03-15T12:00:00Z"
severities:
  - high
tags:
  - phishing
  - redirect
  - google-cloud-storage
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.reddit.com/r/netsec/comments/1rt112d/phishing_campaign_abusing_google_cloud_storage/
ioc_counts:
  domain: 2
rules:
  - title: Detect Redirects from Google Cloud Storage to .autos Domains
    description: Detects network connections where Google Cloud Storage redirects to a domain ending in .autos, indicating potential phishing activity.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Accessing Domains ending in .autos
    description: Detects processes making network connections to domains ending in .autos
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

An ongoing phishing campaign observed in March 2026 abuses Google Cloud Storage (storage.googleapis.com) as a redirector. Attackers are using this service to proxy victims to various scam pages. These scam pages are primarily hosted on domains ending in .autos. The campaign employs various phishing themes, including fake Walmart surveys, Dell giveaways, Netflix rewards, antivirus renewal alerts, storage full warnings, and fake job lures. This tactic allows attackers to obfuscate the final…
