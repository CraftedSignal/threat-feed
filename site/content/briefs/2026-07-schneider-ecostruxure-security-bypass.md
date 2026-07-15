---
title: Vulnerability in Schneider Electric EcoStruxure Allows Security Policy Bypass
slug: 2026-07-schneider-ecostruxure-security-bypass
description: A vulnerability, identified as CVE-2026-14354, exists in Schneider Electric EcoStruxure Cybersecurity Admin Expert versions prior to or equal to 4.2.0, allowing an attacker to bypass the product's security policy, potentially leading to unauthorized access or actions.
date: "2026-07-15T14:33:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - industrial-control-system
  - operational-technology
  - vulnerability
  - defense-evasion
vendors:
  - Schneider Electric
products:
  - EcoStruxure Cybersecurity Admin Expert <= 4.2.0
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0881/
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-195-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-195-02.pdf
  - https://www.cve.org/CVERecord?id=CVE-2026-14354
iocs:
  - type: url
    value: https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-195-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-195-02.pdf
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-14354
ioc_counts:
  url: 2
---

A high-severity vulnerability (CVE-2026-14354) has been discovered in Schneider Electric EcoStruxure Cybersecurity Admin Expert, affecting all versions up to and including 4.2.0. This flaw allows an attacker to bypass the product's security policy, which could lead to unauthorized actions or access within the environment managed by EcoStruxure. EcoStruxure is a critical software suite often used in industrial control systems (ICS) and operational technology (OT) environments, making this bypass particularly concerning for critical infrastructure and manufacturing sectors. The vulnerability was publicly disclosed by CERT-FR on July 15, 2026, referencing Schneider Electric's security bulletin SEVD-2026-195-02. While specific exploitation details are not yet public, any successful bypass of security policies in such sensitive environments can have significant operational and safety impacts.

## Attack Chain

Specific exploitation steps for CVE-2026-14354 have not been detailed in the public advisory. The vulnerability is described as enabling a "security policy bypass" within EcoStruxure Cybersecurity Admin Expert. Defenders should assume that an attacker, once exploiting this vulnerability, could circumvent existing security controls and potentially gain unauthorized access or manipulate system configurations. Further technical details on the precise method of exploitation are required to describe a concrete attack chain.

## Impact

The successful exploitation of CVE-2026-14354 could allow an attacker to bypass the security policies enforced by EcoStruxure Cybersecurity Admin Expert. In an operational technology (OT) or industrial control system (ICS) environment, this can lead to unauthorized modification of configurations, denial of service, or even remote code execution, potentially disrupting critical operations, causing safety hazards, or leading to significant financial losses. While the specific number of affected organizations is not disclosed, Schneider Electric products are widely used across manufacturing, energy, and infrastructure sectors globally.

## Recommendation

* Patch CVE-2026-14354 immediately by upgrading Schneider Electric EcoStruxure Cybersecurity Admin Expert to a version greater than 4.2.0, as recommended in the Schneider Electric Security Bulletin SEVD-2026-195-02.
* Refer to the Schneider Electric Security Bulletin SEVD-2026-195-02 (available at https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-195-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-195-02.pdf) for detailed patching instructions and additional mitigation strategies.
