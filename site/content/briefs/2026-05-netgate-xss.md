---
title: Netgate pfSense XSS Vulnerability
slug: 2026-05-netgate-xss
description: A cross-site scripting (XSS) vulnerability affects Netgate pfSense CE (<= 2.8.1) and pfSense Plus (<= 26.03), potentially allowing attackers to inject malicious code.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - vulnerability
  - pfSense
vendors:
  - Netgate
products:
  - pfSense CE (<= 2.8.1)
  - pfSense Plus (<= 26.03)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0516/
  - https://docs.netgate.com/downloads/pfSense-SA-26_05.webgui.asc
rules:
  - title: Detect Suspicious URI Access to pfSense Web GUI
    description: Detects potentially malicious URI access to pfSense web GUI indicative of XSS attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Request to pfSense Web GUI
    description: Detects potentially malicious POST request to pfSense web GUI indicative of XSS attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability has been discovered in Netgate's pfSense products. This vulnerability, a cross-site scripting (XSS) flaw, can be exploited by an attacker to inject arbitrary web scripts into a trusted website. The vulnerability affects pfSense CE versions 2.8.1 and earlier, as well as pfSense Plus versions 26.03 and earlier. The CERT-FR advisory was published on April 30, 2026, referencing Netgate security bulletin pfSense-SA-26_05, dated April 29, 2026. Successful exploitation of this vulnerability could allow an attacker to execute malicious code in the context of a user's browser, potentially leading to session hijacking, defacement, or redirection to malicious sites.

## Attack Chain

1.  Attacker identifies a vulnerable pfSense CE or Plus instance (<=2.8.1 or <=26.03 respectively).
2.  Attacker crafts a malicious URL containing a cross-site scripting payload.
3.  The URL is delivered to a targeted pfSense user, typically via phishing or social engineering.
4.  The user clicks the malicious link while authenticated to the pfSense web GUI.
5.  The pfSense web application fails to properly sanitize the attacker's input.
6.  The malicious XSS payload is reflected back to the user's browser.
7.  The user's browser executes the attacker-supplied JavaScript code.
8.  The attacker gains control of the user's session or redirects the user to a malicious site.

## Impact

Successful exploitation of the XSS vulnerability in Netgate pfSense could allow an attacker to execute arbitrary code in a user's browser, potentially leading to session hijacking and unauthorized access to the pfSense system. While the number of affected installations is not specified, pfSense is widely used in small to medium-sized businesses as a firewall and routing solution. A successful attack could compromise network security, leading to data breaches, service disruption, or further lateral movement within the network.

## Recommendation

*   Apply the security patches outlined in Netgate's security bulletin pfSense-SA-26_05 to remediate the XSS vulnerability on all affected pfSense CE (<= 2.8.1) and pfSense Plus (<= 26.03) instances.
*   Deploy the Sigma rule "Detect Suspicious URI Access to pfSense Web GUI" to identify potential XSS exploitation attempts targeting the pfSense web interface.
*   Educate users about the dangers of clicking suspicious links, especially those received via email or other untrusted sources, to mitigate phishing attacks that could lead to XSS exploitation (Attack Chain step 3).
