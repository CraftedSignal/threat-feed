---
title: Phishing Campaign Abusing Google Cloud Storage Redirectors
slug: 2026-03-google-cloud-storage-redirector
description: A phishing campaign leverages Google Cloud Storage as a redirect layer to serve victims scam pages related to surveys, giveaways, rewards, alerts, and job lures, primarily hosted on .autos domains.
date: "2026-03-15T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: .autos
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

An ongoing phishing campaign observed in March 2026 abuses Google Cloud Storage (storage.googleapis.com) as a redirector. Attackers are using this service to proxy victims to various scam pages. These scam pages are primarily hosted on domains ending in .autos. The campaign employs various phishing themes, including fake Walmart surveys, Dell giveaways, Netflix rewards, antivirus renewal alerts, storage full warnings, and fake job lures. This tactic allows attackers to obfuscate the final destination of the phishing link, making it harder for victims to identify malicious content before they are redirected to a scam page. Defenders should monitor for unusual redirects originating from Google Cloud Storage to untrusted domains.

## Attack Chain

1.  The attacker sends a phishing email to potential victims.
2.  The email contains a link that appears legitimate, hosted on Google Cloud Storage (storage.googleapis.com).
3.  The victim clicks on the link, initiating a request to the specified Google Cloud Storage URL.
4.  Google Cloud Storage, configured by the attacker, redirects the victim to a malicious domain, typically ending in .autos.
5.  The victim's browser is redirected to the scam page hosted on the .autos domain.
6.  The scam page presents a fake survey, giveaway, reward, alert, or job lure designed to trick the victim.
7.  The victim enters personal information or credentials into the fake form.
8.  The attacker harvests the stolen information for malicious purposes, such as identity theft or financial fraud.

## Impact

This phishing campaign can lead to the theft of personal and financial information. Victims who interact with the scam pages may experience financial losses, identity theft, or malware infections. The use of Google Cloud Storage as a redirector makes it harder to detect and block these phishing attacks, potentially impacting a large number of users. Sectors targeted include retail customers (Walmart), technology consumers (Dell, Netflix), and job seekers.

## Recommendation

*   Monitor network traffic for redirects originating from `storage.googleapis.com` to suspicious domains, particularly those ending in `.autos`.
*   Implement the Sigma rule to detect redirects from Google Cloud Storage to .autos domains.
*   Educate users about phishing tactics and the dangers of clicking on suspicious links.
*   Consider blocking or sandboxing domains ending in `.autos` if they are not part of your organization's trusted ecosystem.
