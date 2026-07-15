---
title: Information Disclosure in Capgo Supabase Integration via RPC Function
slug: 2026-07-information-disclosure-capgo
description: An information disclosure vulnerability in Capgo (Cap-go/capgo) before version 12.128.2 allows unauthenticated attackers to enumerate organization existence. This flaw resides within the Supabase PostgREST SECURITY DEFINER RPC function 'public.rescind_invitation', which returns distinct error messages (NO_ORG vs. NO_RIGHTS) when called with only a publishable API key. This enables attackers to discover valid organization IDs, increasing the attack surface for targeted phishing or social engineering campaigns.
date: "2026-07-15T12:21:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - supabase
vendors:
  - Capgo
  - Supabase
products:
  - Cap-go/capgo (< 12.128.2)
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: allows unauthenticated attackers to enumerate organization existence. The function returns distinct error messages (NO_ORG vs NO_RIGHTS) ... enabling attackers to discover valid organization IDs
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: increase the attack surface for targeted phishing or social engineering campaigns.
    confidence_band: high
cves:
  - id: CVE-2026-56339
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56339
---

A critical information disclosure vulnerability, tracked as CVE-2026-56339, affects Capgo (Cap-go/capgo) versions prior to 12.128.2. This flaw is located within the `public.rescind_invitation` RPC function of the integrated Supabase PostgREST instance, specifically when configured as a SECURITY DEFINER. Unauthenticated attackers can exploit this vulnerability by observing distinct error messages returned by the function when attempting to rescind an invitation using only a publishable API key. A "NO_ORG" error indicates an invalid organization ID, while a "NO_RIGHTS" error signifies a valid organization ID for which the provided API key lacks sufficient permissions. This distinction allows attackers to enumerate valid organization IDs, thereby expanding the attack surface for subsequent targeted phishing or social engineering campaigns. The vulnerability poses a significant risk by enabling sophisticated reconnaissance against Capgo users.

## Attack Chain

1. An unauthenticated attacker identifies a Capgo instance that utilizes the vulnerable Supabase PostgREST RPC function.
2. The attacker obtains a valid, publishable API key for the Capgo instance.
3. The attacker crafts an RPC request targeting the `public.rescind_invitation` function, supplying the publishable API key and a guessed organization ID.
4. The attacker sends a series of these crafted requests, systematically varying the guessed organization ID.
5. Upon receiving an API response containing a "NO_ORG" error message, the attacker identifies that the submitted organization ID is invalid or does not exist.
6. Upon receiving an API response containing a "NO_RIGHTS" error message, the attacker identifies that the submitted organization ID is valid, despite the API key lacking specific rights for that organization.
7. By analyzing the distinct error messages, the attacker effectively enumerates all valid organization IDs within the Capgo instance.
8. The attacker then leverages these confirmed valid organization IDs to conduct highly targeted phishing, social engineering, or other reconnaissance activities against the identified organizations.

## Impact

Successful exploitation of CVE-2026-56339 leads to the unauthorized enumeration of valid organization IDs within affected Capgo instances. This information disclosure provides attackers with critical data for reconnaissance, significantly increasing the success rate of subsequent targeted phishing, social engineering, or other attack vectors. While the vulnerability itself does not grant direct access to sensitive data or systems, it dramatically lowers the barrier for attackers to launch more sophisticated and personalized attacks against specific organizations. The scope of targeting is limited only by the attacker's ability to guess or systematically iterate through potential organization IDs.

## Recommendation

* Patch CVE-2026-56339 by upgrading Capgo (Cap-go/capgo) to version 12.128.2 or later immediately.
* Review access logging for the Supabase PostgREST RPC endpoint for `public.rescind_invitation` for unusual patterns or high volumes of requests indicating reconnaissance activity.
* Implement API gateway rate limiting or Web Application Firewall (WAF) rules to restrict the frequency of requests to the `public.rescind_invitation` function if logs are not available for real-time monitoring.
