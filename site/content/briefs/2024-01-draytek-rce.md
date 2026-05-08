---
title: DrayTek Vigor 2960 Unauthenticated Remote Command Execution via CVE-2022-50994
slug: 2024-01-draytek-rce
description: DrayTek Vigor 2960 firmware versions prior to 1.5.1.4 are vulnerable to OS command injection (CVE-2022-50994) in the CGI login handler, allowing unauthenticated remote attackers to execute arbitrary commands by injecting shell metacharacters into the formpassword parameter if the target account has MOTP enabled.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - command injection
  - rce
  - network device
vendors:
  - DrayTek
products:
  - Vigor 2960 firmware
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2022-50994
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-50994
rules:
  - title: Detect CVE-2022-50994 Exploitation — DrayTek Vigor CGI Login Attempt
    description: Detects CVE-2022-50994 exploitation — suspicious HTTP POST requests to `/cgi-bin/loginCGI` with shell metacharacters in the `formpassword` parameter, indicating a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1547.004
    data_sources:
      - webserver
  - title: Detect CVE-2022-50994 Exploitation - DrayTek Vigor CGI Login Error Responses
    description: Detects CVE-2022-50994 exploitation attempts that result in a server error (5xx) after a POST request to /cgi-bin/loginCGI potentially indicating failed exploitation due to input validation or other error handling.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1547.004
    data_sources:
      - webserver
rules_count: 2
---

DrayTek Vigor 2960 devices running firmware versions prior to 1.5.1.4 are susceptible to a critical OS command injection vulnerability, tracked as CVE-2022-50994. This flaw resides in the CGI login handler and allows unauthenticated remote attackers to inject arbitrary commands by manipulating the `formpassword` parameter. Successful exploitation requires knowledge of a valid username and that the target account has MOTP authentication enabled. This vulnerability poses a significant risk as it enables attackers to execute commands with web server privileges, potentially leading to full system compromise.

## Attack Chain

1. The attacker identifies a DrayTek Vigor 2960 device running a vulnerable firmware version (prior to 1.5.1.4).
2. The attacker discovers or obtains a valid username for the target device.
3. The attacker determines that the target account has MOTP authentication enabled.
4. The attacker crafts a malicious HTTP POST request to the CGI login handler, injecting shell metacharacters into the `formpassword` parameter.
5. The crafted request is sent to the `/cgi-bin/loginCGI` endpoint.
6. The vulnerable `otp_check.sh` script receives the unsanitized input from the `formpassword` parameter.
7. The injected shell metacharacters are interpreted by the script, executing arbitrary OS commands with the privileges of the web server.
8. The attacker achieves remote code execution, potentially gaining complete control of the affected device.

## Impact

Successful exploitation of CVE-2022-50994 allows an unauthenticated remote attacker to execute arbitrary commands on the DrayTek Vigor 2960 device. This can lead to complete system compromise, including data exfiltration, configuration changes, and denial of service. Given that DrayTek Vigor devices are often used in small to medium-sized businesses, a successful attack could disrupt network operations and lead to significant financial losses.

## Recommendation

*   Upgrade DrayTek Vigor 2960 devices to firmware version 1.5.1.4 or later to patch CVE-2022-50994.
*   Deploy the Sigma rule "Detect CVE-2022-50994 Exploitation — DrayTek Vigor CGI Login Attempt" to your SIEM to identify potential exploitation attempts against the `/cgi-bin/loginCGI` endpoint.
*   Enable logging for web server requests to capture relevant data for the Sigma rule and future investigations.
*   Review user accounts and disable MOTP authentication where it is not required to reduce the attack surface.
