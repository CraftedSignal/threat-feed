---
title: New Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-07-new-abuse-of-clickonce-part-1
description: CrowdStrike details how Microsoft's ClickOnce deployment technology, designed for simplified application installation, is being abused by threat actors to spread malware, enabling malicious application execution on Windows endpoints with minimal user interaction and without requiring administrative privileges.
date: "2026-07-04T07:32:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - initial-access
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: threat actors with an easy way of spreading malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: These deployment files can be hosted on the vendor's website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike recently detailed a new method of abusing Microsoft's ClickOnce technology, a deployment mechanism designed for simplified application distribution and updates on Windows systems. While ClickOnce offers developers an easy way to deploy software with minimal user interaction and without requiring administrative privileges, threat actors are exploiting these very features to spread malware. This initial part of a two-part series (published June 18, 2026) explains the underlying mechanics of ClickOnce, from application publishing to installation, highlighting its user-friendly deployment journey. For defenders, this research is crucial as it details how a legitimate Windows feature can be weaponized for initial access and execution of malicious payloads, potentially bypassing traditional security controls due to its inherent design.

## Impact

The primary impact of ClickOnce abuse is the facilitated distribution and execution of malware on Windows endpoints. By leveraging ClickOnce, threat actors can bypass traditional application installation hurdles, potentially leading to widespread compromise across various sectors. The technology's design, which allows deployment without elevated privileges and minimal user interaction, lowers the barrier for attackers to establish initial access and execute arbitrary code, leading to data exfiltration, ransomware deployment, or further system compromise. The article does not specify victim counts or targeted sectors, but the nature of the abuse suggests broad applicability for any organization using Windows systems.

## Recommendation

*   Ensure comprehensive `process_creation` and `file_event` logging is enabled on `windows` endpoints to capture ClickOnce application deployment activities, as described in this brief.
*   Review your current application deployment policies to identify and mitigate risks associated with unsigned or untrusted ClickOnce applications, specifically those that leverage the features of ClickOnce as described in the 'Overview' section of this brief.
