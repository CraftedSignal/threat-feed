---
title: Remote Stack-Based Buffer Overflow in Wavlink Networking Devices
slug: 2026-08-wavlink-buffer-overflow
description: Multiple Wavlink networking devices are vulnerable to a remote stack-based buffer overflow in the lighttpd component due to insecure use of strcpy in the upload.cgi script via the HTTP_COOKIE header.
date: "2026-08-03T18:06:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - network-infrastructure
vendors:
  - Wavlink
products:
  - WN572
  - WN570H
  - WN573
  - WN529
  - WN530
  - WN531
  - WN535
  - WN536
  - WN551
  - WN557
  - NU516
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-18607
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18607
  - https://vuldb.com/vuln/385530
  - https://github.com/0xcc12138/WAVLINK-vul
iocs:
  - type: url
    value: https://github.com/0xcc12138/WAVLINK-vul
ioc_counts:
  url: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory Wavlink devices and verify firmware versions against affected list.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18607 affects specific model versions.
  mitigation_plan:
    - priority: immediate
      action: Block access to web management interface from external networks.
      owner: IT Operations
      addresses: CVE-2026-18607
      evidence: Exploit targets remotely accessible upload.cgi.
---

A critical security vulnerability, tracked as CVE-2026-18607, affects numerous Wavlink networking devices including the WN572, WN570H, WN573, WN529, WN530, WN531, WN535, WN536, WN551, WN557, and NU516 series. The vulnerability is located within the 'upload.cgi' script utilized by the embedded lighttpd web server. An unauthenticated remote attacker can trigger a stack-based buffer overflow by sending a specially crafted 'HTTP_COOKIE' header to the device. The issue stems from the unsafe implementation of the 'strcpy' function when processing this cookie input. Publicly available proof-of-concept exploits exist, increasing the risk of exploitation by threat actors targeting embedded devices.

## Attack Chain

1. Attacker performs network reconnaissance to identify vulnerable Wavlink devices exposed to the internet.
2. Attacker crafts a malicious HTTP request targeting the /upload.cgi endpoint on the target device.
3. Attacker embeds an oversized string within the 'HTTP_COOKIE' header of the malicious request.
4. The lighttpd component receives the request and invokes the vulnerable 'upload.cgi' script.
5. The 'strcpy' function copies the excessive cookie data into an undersized stack buffer.
6. The stack-based buffer overflow results in memory corruption, overwriting return addresses.
7. The attacker redirects control flow to injected shellcode or payload.
8. Remote Code Execution (RCE) is achieved on the affected device.

## Impact

Successful exploitation of CVE-2026-18607 allows an attacker to achieve remote code execution on affected Wavlink networking devices. This compromises the integrity and availability of the network appliance. Given the nature of these devices, such a compromise could facilitate man-in-the-middle attacks, credential harvesting, or lateral movement into the protected internal network environment.

## Recommendation

1. Identify and inventory all Wavlink networking devices within the enterprise network to determine if any of the affected models are in use.
2. Restrict access to the web management interface of these devices by limiting access to trusted IP ranges via firewall rules.
3. Implement strict monitoring of HTTP requests targeting '/upload.cgi' endpoints, particularly looking for anomalous or oversized 'Cookie' headers.
4. Engage with the vendor to obtain firmware updates that resolve the unsafe use of 'strcpy' in 'upload.cgi'.
5. If patching is not immediately available and the device is exposed to the internet, disable the web-based management interface or isolate the device from external network access.
