---
title: Self-Hosted Email Threat Detection Tool
slug: 2026-03-verdictmail
description: A user created a self-hosted email threat detection tool, named VerdictMail, employing IMAP IDLE for real-time monitoring and multi-stage enrichment via SPF, DKIM, DMARC, DNSBL, WHOIS, URLhaus, and VirusTotal, coupled with an LLM for threat assessment.
date: "2026-03-18T10:00:00Z"
severities:
  - medium
actors:
  - Individual Developer
tags:
  - email-security
  - threat-detection
  - imap
references:
  - https://www.reddit.com/r/netsec/comments/1rw5j1d/built_a_selfhosted_email_threat_daemon_imap_idle/
  - https://scarolas.com/dev#verdictmail
rules:
  - title: Detect Suspicious Email Subject Keywords
    description: Detects emails with suspicious subject keywords often used in phishing or spam campaigns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - mailserver
  - title: Detect Email from Newly Registered Domain
    description: Detects emails originating from domains registered within the last 24 hours, which may indicate phishing or spam activity.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - mailserver
rules_count: 2
---

A security-conscious individual has developed a self-hosted email threat detection tool, "VerdictMail," designed to enhance email security through real-time analysis and machine learning. Released in March 2026, the tool leverages IMAP IDLE to monitor incoming emails. VerdictMail then performs a series of enrichment steps, including SPF, DKIM, and DMARC validation to verify sender authenticity. DNSBL lookups identify potential spam sources, while WHOIS queries provide registrant information…
