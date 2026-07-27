---
title: Web Server Outbound Connections to File Sharing Services
slug: 2026-07-webserver-download-from-file-sharing-website
description: Attackers compromise web servers (Apache, Nginx, Tomcat, PHP) and leverage them to make unexpected outbound network connections to public file-sharing or content hosting services, indicating post-exploitation activity for ingress tool transfer and further compromise.
date: "2026-07-27T18:13:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - post-exploitation
  - ingress-tool-transfer
  - webshell
  - web-server
  - c2
  - windows
vendors:
  - Apache
  - Nginx
  - Apache Software Foundation
  - PHP Group
products:
  - Apache HTTP Server
  - Nginx
  - Apache Tomcat
  - PHP
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This behavior is often associated with server compromise, where an attacker uses a reverse shell, webshell, or injected task to fetch malware or tools post-exploitation.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This analytic detects unexpected outbound network connections initiated by known webserver processes... to common file sharing or public content hosting services... This behavior is often associated with server compromise, where an attacker uses a reverse shell, webshell, or injected task to fetch malware or tools post-exploitation.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/alerts/2023/04/13/cisa-adds-3-known-exploited-vulnerabilities-kev-catalog
  - https://www.microsoft.com/en-us/security/blog/2024/01/17/new-ttps-observed-in-mint-sandstorm-campaign-targeting-high-profile-individuals-at-universities-and-research-orgs/
  - https://research.splunk.com/endpoint/4e8391eb-527e-4e39-9a17-c5bde2f89158/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/cisco_nvm___webserver_download_from_file_sharing_website.yml
iocs:
  - type: domain
    value: '*.githubusercontent.com'
  - type: domain
    value: '*.anonfiles.com'
  - type: domain
    value: '*.cdn.discordapp.com'
  - type: domain
    value: '*.ddns.net'
  - type: domain
    value: '*.dl.dropboxusercontent.com'
  - type: domain
    value: '*.ghostbin.co'
  - type: domain
    value: '*.glitch.me'
  - type: domain
    value: '*.gofile.io'
  - type: domain
    value: '*.hastebin.com'
  - type: domain
    value: '*.mediafire.com'
  - type: domain
    value: '*.mega.nz'
  - type: domain
    value: '*.onrender.com'
  - type: domain
    value: '*.pages.dev'
  - type: domain
    value: '*.paste.ee'
  - type: domain
    value: '*.pastetext.net'
  - type: domain
    value: '*.send.exploit.in'
  - type: domain
    value: '*.sendspace.com'
  - type: domain
    value: '*.storage.googleapis.com'
  - type: domain
    value: '*.storjshare.io'
  - type: domain
    value: '*.supabase.co'
  - type: domain
    value: '*.temp.sh'
  - type: domain
    value: '*.transfer.sh'
  - type: domain
    value: '*.trycloudflare.com'
  - type: domain
    value: '*.ufile.io'
  - type: domain
    value: '*.w3spaces.com'
  - type: domain
    value: '*.workers.dev'
ioc_counts:
  domain: 26
rules:
  - title: Web Server Outbound Download From File Sharing Website
    description: Detects unexpected outbound network connections initiated by common web server processes to known public file-sharing or content hosting services, indicating post-exploitation ingress tool transfer.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - ingress_tool_transfer
      - initial_access
    techniques:
      - T1105
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

This threat brief details a common post-exploitation technique where attackers, after compromising a web server, utilize the web server's process to download additional malicious tools or payloads from public file-sharing and content hosting websites. The observed behavior involves legitimate web server processes such as `httpd.exe`, `nginx.exe`, `tomcat.exe`, `php.exe`, or `php-cgi.exe` initiating outbound network connections to domains like `githubusercontent.com`, `cdn.discordapp.com`, `pastebin.*`, `transfer.sh`, and `mega.nz`. This activity is highly suspicious as web servers typically do not require outbound internet access to these types of dynamic or anonymous file hosting services for legitimate operations. Such behavior strongly indicates a prior server compromise, likely through a webshell, reverse shell, or injected task, with the objective of furthering the attacker's foothold and capabilities within the victim's environment. This technique facilitates stealthy ingress tool transfer, bypassing direct download restrictions and leveraging trusted web server processes.

## Attack Chain

1. **Initial Access (T1190 - Exploit Public-Facing Application)**: Attackers exploit a vulnerability in a public-facing web server or web application (e.g., Apache HTTP Server, Nginx, Apache Tomcat, PHP application) to gain unauthorized access.
2. **Establish Foothold (T1505.003 - Server Software Component: Web Shell)**: The attacker deploys a webshell or establishes a reverse shell on the compromised web server to maintain persistent access and execute commands.
3. **Command and Control (T1071 - Application Layer Protocol)**: The attacker interacts with the established webshell or reverse shell to issue commands and control the compromised server, often using common application layer protocols like HTTP/S.
4. **Ingress Tool Transfer (T1105)**: The compromised web server process (e.g., `httpd.exe`, `nginx.exe`, `tomcat.exe`) is instructed by the attacker to initiate outbound connections to public file-sharing or content hosting websites (e.g., `cdn.discordapp.com`, `pastebin.com`, `transfer.sh`, `githubusercontent.com`) to download additional malware, scripts, or post-exploitation tools.
5. **Execution (T1059 - Command and Scripting Interpreter)**: The attacker then executes the newly downloaded tools or malware on the compromised server using various command and scripting interpreters available on the system.
6. **Further Objectives (e.g., T1041 - Exfiltration Over C2 Channel, T1486 - Data Encrypted for Impact)**: The downloaded tools are used to achieve the attacker's ultimate objectives, which may include further lateral movement, data exfiltration, system impact (such as ransomware deployment), or establishing long-term persistence.

## Impact

Successful exploitation leading to this behavior signifies a compromised web server, which can have severe consequences. Attackers gain the ability to introduce arbitrary malware, reconnaissance tools, or ransomware onto the server, potentially leading to data breaches, complete system takeover, or disruption of services. The use of web server processes for downloading attacker tools makes detection challenging as it blends with legitimate network traffic. The impact can extend to internal networks if the compromised server provides a pivot point for lateral movement. The number of victims and sectors targeted can vary widely depending on the initial access vector, but web servers are critical assets across almost all organizations.

## Recommendation

* Deploy the Sigma rule "Web Server Outbound Download From File Sharing Website" to your SIEM and tune for your environment to detect unexpected outbound connections from web server processes.
* Monitor network connections, specifically outbound traffic originating from web server processes, and review connections to domains listed in the IOC table for suspicious activity.
* Implement strict outbound firewall rules for web servers, allowing connections only to known, legitimate endpoints required for business operations, and block access to the domains listed in the IOC table.
* Ensure Cisco Network Visibility Module flow data is ingested into your SIEM for comprehensive network connection logging to enable the rule above.
* Regularly patch all public-facing web applications and servers to prevent initial access via vulnerabilities like those mentioned in CISA's KEV catalog.
