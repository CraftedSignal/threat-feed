---
title: Multiple Vulnerabilities in Microsoft .Net (CVE-2026-45491, CVE-2026-45591)
slug: 2026-06-microsoft-dotnet-vulns
description: Multiple vulnerabilities, CVE-2026-45491 and CVE-2026-45591, have been discovered in Microsoft .Net and ASP.NET Core versions, allowing a remote attacker to cause a denial of service and compromise data integrity across Windows, Linux, and macOS platforms.
date: "2026-06-14T09:19:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - data-integrity
  - dotnet
  - microsoft
vendors:
  - Microsoft
products:
  - .NET 10.0
  - .NET 8.0
  - .NET 9.0
  - ASP.NET Core 10.0
  - ASP.NET Core 8.0
  - ASP.NET Core 9.0
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-45491
    cvss: 6.2
    epss: 0.00092
  - id: CVE-2026-45591
    cvss: 7.5
    epss: 0.01663
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0729/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45491
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45591
  - https://www.cve.org/CVERecord?id=CVE-2026-45491
  - https://www.cve.org/CVERecord?id=CVE-2026-45591
rules:
  - title: Detect Suspicious Child Process from Dotnet Host
    description: Detects CVE-2026-45491 and CVE-2026-45591 exploitation — Identifies potential code execution or data integrity compromise by detecting suspicious child processes spawned by dotnet.exe or IIS w3wp.exe processes, which should typically not execute shell commands or remote access tools.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1071
      - T1565
    data_sources:
      - process_creation
      - windows
  - title: Detect Excessive Web Server 5xx Errors from ASP.NET Core
    description: Detects CVE-2026-45491 and CVE-2026-45591 exploitation — Identifies potential remote Denial of Service (DoS) attempts or application instability by monitoring for a high volume of HTTP 5xx errors from an ASP.NET Core application, which can indicate resource exhaustion or crashes.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

On June 10, 2026, the CERT-FR issued an advisory detailing multiple vulnerabilities, CVE-2026-45491 and CVE-2026-45591, affecting various versions of Microsoft .Net and ASP.NET Core. These vulnerabilities enable a remote attacker to achieve a denial of service (DoS) state, rendering applications and services unavailable, and to compromise the integrity of data processed by vulnerable applications. The affected scope is broad, encompassing .Net 8.0, 9.0, and 10.0, as well as ASP.NET Core 8.0, 9.0, and 10.0, running on Windows, Linux, and macOS environments. These flaws pose a significant risk to organizations relying on vulnerable .Net applications, as they can lead to operational disruption and untrusted data, underscoring the importance of prompt patching.

## Attack Chain

1.  Attacker identifies a public-facing application or service built with a vulnerable Microsoft .Net or ASP.NET Core version (e.g., .NET 10.0 < 10.0.9, ASP.NET Core 8.0 < 8.0.28).
2.  The attacker crafts a malicious input or request specifically designed to exploit CVE-2026-45491 or CVE-2026-45591, targeting the application's processing logic.
3.  The vulnerable .Net or ASP.NET Core runtime processes the malformed data, triggering the vulnerability.
4.  For denial of service (DoS) attacks, the vulnerability causes the application or underlying service to crash, hang, or consume excessive resources, making it unresponsive to legitimate users.
5.  For data integrity compromise, the vulnerability allows unauthorized modification or corruption of data handled by the application, potentially leading to incorrect computations, unauthorized state changes, or other forms of data manipulation.
6.  The application either becomes unavailable, experiences significant performance degradation, or operates with compromised data, directly impacting business operations and trust.

## Impact

The successful exploitation of these vulnerabilities can lead to significant operational disruption and data reliability issues. A remote denial of service attack can render critical applications and services inaccessible, leading to financial losses, reputational damage, and inability to conduct business. Data integrity compromise can result in corrupted databases, inaccurate financial records, or manipulated user data, undermining trust and potentially leading to compliance violations or incorrect decision-making. While specific victim counts or targeted sectors are not detailed, any organization utilizing affected .Net or ASP.NET Core versions is at risk, particularly those with internet-facing applications.

## Recommendation

*   Immediately apply the security updates provided by Microsoft for all affected .NET and ASP.NET Core versions as referenced in the CERTFR-2026-AVI-0729 advisory and the MSRC bulletins for CVE-2026-45491 and CVE-2026-45591.
*   Deploy the provided Sigma rules to your SIEM/EDR to detect potential exploitation attempts or post-exploitation activities related to the observed vulnerabilities.
*   Enable comprehensive logging for web servers (like IIS or Kestrel) and application runtimes (`dotnet.exe` process creation) to capture anomalies that the rules are designed to detect.
*   Monitor for excessive 5xx HTTP status codes in web server logs, which can indicate ongoing denial of service attempts or application crashes as per the `Detect Excessive Web Server 5xx Errors` rule.
*   Enable process creation logging, especially for `dotnet.exe` or `w3wp.exe`, to detect suspicious child processes as per the `Detect Suspicious Child Process from Dotnet Host` rule.
