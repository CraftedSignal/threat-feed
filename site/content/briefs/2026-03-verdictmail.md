---
title: Self-Hosted Email Threat Detection Tool
slug: 2026-03-verdictmail
description: A user created a self-hosted email threat detection tool, named VerdictMail, employing IMAP IDLE for real-time monitoring and multi-stage enrichment via SPF, DKIM, DMARC, DNSBL, WHOIS, URLhaus, and VirusTotal, coupled with an LLM for threat assessment.
date: "2026-03-18T10:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
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

A security-conscious individual has developed a self-hosted email threat detection tool, "VerdictMail," designed to enhance email security through real-time analysis and machine learning. Released in March 2026, the tool leverages IMAP IDLE to monitor incoming emails. VerdictMail then performs a series of enrichment steps, including SPF, DKIM, and DMARC validation to verify sender authenticity. DNSBL lookups identify potential spam sources, while WHOIS queries provide registrant information. Additionally, the tool integrates with URLhaus and VirusTotal to assess the reputation of embedded URLs and attachments. Finally, VerdictMail employs a provider-agnostic Large Language Model (LLM) to render a final verdict on the email's threat level, providing a comprehensive security layer for personal or small-scale email infrastructure.

## Attack Chain

This tool is a defensive measure, not an attack. The below steps describe how the tool functions to analyze potential attacks.

1.  **Email Reception:** VerdictMail monitors a designated IMAP mailbox using the IMAP IDLE protocol for real-time email arrival.
2.  **Header Analysis:** Upon receiving a new email, the tool extracts relevant headers, including Sender, From, Reply-To, and Message-ID.
3.  **Authentication Checks:** VerdictMail performs SPF, DKIM, and DMARC checks to validate the sender's authenticity and domain reputation.
4.  **Reputation Lookups:** The tool queries DNSBLs (DNS Blacklists) to identify known spam sources and malicious IPs associated with the sender.
5.  **WHOIS Enrichment:** WHOIS lookups are conducted on the sender's domain to gather registrant information and assess the domain's legitimacy.
6.  **URL and Attachment Scanning:** URLs within the email body are extracted and checked against URLhaus for known malicious URLs. Attachments are submitted to VirusTotal for malware scanning.
7.  **LLM Verdict Generation:** All gathered data is fed into a provider-agnostic Large Language Model (LLM), which analyzes the information and generates a threat verdict.
8.  **Alerting/Quarantine:** Based on the LLM's verdict, VerdictMail can flag the email as suspicious, quarantine it, or generate an alert for further investigation.

## Impact

VerdictMail aims to reduce the risk of successful phishing attacks, malware infections, and business email compromise (BEC). By automatically analyzing emails and providing a threat verdict, it helps users identify and avoid potentially harmful messages. While the exact number of users is unknown, the tool could prevent financial losses, data breaches, and reputational damage for individuals and small organizations adopting it.

## Recommendation

*   Consider implementing similar multi-stage enrichment techniques in existing email security solutions by incorporating SPF, DKIM, and DMARC validation (Attack Chain Step 3).
*   Integrate threat intelligence feeds like URLhaus (Attack Chain Step 6) and VirusTotal (Attack Chain Step 6) into email security workflows to identify malicious URLs and attachments.
*   Explore using LLMs for email threat assessment as an additional layer of security (Attack Chain Step 7).
