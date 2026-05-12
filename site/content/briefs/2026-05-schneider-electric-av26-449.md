---
title: Schneider Electric Security Advisory AV26-449 Addressing Multiple Vulnerabilities
slug: 2026-05-schneider-electric-av26-449
description: Schneider Electric published advisories on May 12, 2026, addressing vulnerabilities in multiple products including Ecostruxure Machine Expert HVAC, Easergy MiCOM C264, Easergy C5, Easergy MiCOM P30, Easergy MiCOM P40, EcoStruxure Power Automation System, iPMFLS, PowerLogic, Saitel DP, EasyLogic T150, EasyLogic T150 Remote Terminal Unit and Controller, Saitel DP Remote Terminal Unit and Controller, EcoStruxure Panel Server PAS400, PAS600, PAS600V2, PAS800, PAS800V2 and Easergy MiCOM Px40 Series related to clear text storage, insufficient entropy, improper path restrictions and insecure defaults.
date: "2026-05-12T14:44:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - scada
  - ics
  - ot
vendors:
  - Schneider Electric
products:
  - Ecostruxure Machine Expert HVAC
  - Easergy MiCOM C264
  - Easergy C5
  - Easergy MiCOM P30
  - Easergy MiCOM P40
  - EcoStruxure Power Automation System
  - iPMFLS
  - PowerLogic
  - Saitel DP
  - EasyLogic T150
  - EasyLogic T150 Remote Terminal Unit and Controller
  - Saitel DP Remote Terminal Unit and Controller
  - EcoStruxure Panel Server PAS400
  - EcoStruxure Panel Server PAS600
  - EcoStruxure Panel Server PAS600V2
  - EcoStruxure Panel Server PAS800
  - EcoStruxure Panel Server PAS800V2
  - Easergy MiCOM Px40 Series
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-schneider-electric-security-advisory-av26-449
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-132-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-132-01.pdf
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-132-02&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-132-02.pdf
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-132-03&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-132-03.pdf
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-132-04&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-132-04.pdf
  - https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp
rules:
  - title: Detect Potential Path Traversal Attempts in Web Server Logs
    description: Detects potential path traversal attempts by looking for '..' sequences in web server logs.  May indicate attempts to exploit improper limitation of a pathname vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Clear Text Configuration File Access
    description: Detects access to common configuration file extensions that might contain sensitive information stored in clear text.  May indicate attempts to exploit clear text storage vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On May 12, 2026, Schneider Electric released security advisories addressing vulnerabilities affecting a range of its industrial control system (ICS) and power management products. These vulnerabilities, detailed in Schneider Electric security notification SEVD-2026-132-01 through SEVD-2026-132-04, span multiple product lines including EcoStruxure, Easergy, PowerLogic, and Saitel DP. The affected products are used in various industrial and building automation environments. Successful exploitation of these vulnerabilities could lead to unauthorized access, information disclosure, or disruption of critical services. Defenders need to apply the provided mitigations and updates promptly to minimize the risk. The affected versions include those prior to 1.10.0 for EcoStruxure Machine Expert HVAC and multiple versions for other products as specified in the advisory.

## Attack Chain

Due to the generic nature of the advisory and lack of specific CVE details, the following is a generalized attack chain based on the vulnerability types described (clear text storage, insufficient entropy, path traversal, insecure defaults).

1. **Initial Access (assumed):** Attacker gains initial access to the network through unspecified means (e.g., phishing, compromised credentials, or network vulnerability).
2. **Reconnaissance:** Attacker identifies vulnerable Schneider Electric devices within the network (e.g., EcoStruxure Panel Server) using network scanning or by analyzing network traffic.
3. **Exploitation (Cleartext Storage):** Attacker exploits the clear text storage of sensitive information vulnerability to obtain credentials or other sensitive data. This might involve accessing configuration files or memory dumps.
4. **Exploitation (Insufficient Entropy):** Attacker exploits the insufficient entropy vulnerability to predict or brute-force cryptographic keys or session tokens, potentially gaining unauthorized access to systems.
5. **Exploitation (Path Traversal):** Attacker leverages the improper limitation of a pathname vulnerability to access files or directories outside of the intended scope, potentially leading to information disclosure or arbitrary code execution.
6. **Exploitation (Insecure Defaults):** Attacker exploits the initialization of a resource with an insecure default (e.g., default password) to gain unauthorized access to the EcoStruxure Panel Server.
7. **Lateral Movement:** Using the obtained credentials or access, the attacker moves laterally within the network to access other critical systems or data.
8. **Impact:** The attacker disrupts operations, exfiltrates sensitive data, or causes physical damage to the controlled systems.

## Impact

Successful exploitation of these vulnerabilities could have significant consequences for organizations relying on Schneider Electric products. Potential impacts include unauthorized access to sensitive data, disruption of critical industrial processes, and financial losses due to downtime and recovery efforts. The number of victims and the extent of damage would vary depending on the specific vulnerabilities exploited and the security posture of the affected organizations. Sectors heavily reliant on industrial control systems (ICS) and building automation systems (BAS) are particularly at risk.

## Recommendation

*   Immediately review Schneider Electric security notification [SEVD-2026-132-01 through SEVD-2026-132-04](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) and identify affected products and versions in your environment.
*   Apply the recommended updates and mitigations provided by Schneider Electric for each affected product to address the identified vulnerabilities.
*   Implement strong password policies and enforce multi-factor authentication to prevent unauthorized access.
*   Segment the network to isolate critical systems and limit the potential impact of a successful attack.
*   Monitor network traffic for suspicious activity, such as unauthorized access attempts or data exfiltration, using a network intrusion detection system (NIDS).
*   Deploy the Sigma rules provided below to your SIEM and tune them for your specific environment.
