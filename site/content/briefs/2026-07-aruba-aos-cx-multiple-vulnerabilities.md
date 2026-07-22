---
title: 'Aruba AOS-CX: Multiple Vulnerabilities'
slug: 2026-07-aruba-aos-cx-multiple-vulnerabilities
description: Multiple vulnerabilities in Aruba AOS-CX can be exploited by an attacker to bypass security measures, execute arbitrary code, and manipulate files, which could lead to compromise of the network device.
date: "2026-07-22T12:05:14Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - network
  - vulnerability
  - rce
  - file-manipulation
  - aruba
vendors:
  - Aruba
products:
  - AOS-CX
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: um beliebigen Programmcode auszuführen
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2473
---

A security advisory from the German Federal Office for Information Security (BSI) highlights multiple critical vulnerabilities affecting Aruba AOS-CX network operating systems. An unauthenticated attacker can exploit these vulnerabilities to bypass existing security measures, execute arbitrary program code on affected devices, and manipulate files. While the advisory does not specify the exact methods of exploitation or the specific components affected within AOS-CX, successful exploitation could lead to full compromise of the network device. The advisory does not mention any specific threat actors or observed in-the-wild exploitation. These vulnerabilities pose a significant risk to the integrity and availability of network infrastructure utilizing Aruba AOS-CX, enabling attackers to gain unauthorized control over critical network equipment.

## Impact

Successful exploitation of these vulnerabilities could result in a complete compromise of affected Aruba AOS-CX network devices. An attacker would be able to bypass existing security controls, achieve arbitrary code execution, and manipulate files on the device. This could lead to a range of severe consequences, including unauthorized network access, data exfiltration from or manipulation of the network device's configuration, disruption of network services, or using the compromised device as a pivot point for further attacks within the network infrastructure. The advisory does not provide specific numbers of affected organizations or observed incidents.

## Recommendation

* Consult the Aruba security advisory referenced in this brief for specific patch information and apply all available security updates to Aruba AOS-CX devices immediately.
* Monitor network device logs for unusual activity, such as unauthorized login attempts, unexpected file modifications, or process executions that could indicate exploitation attempts against Aruba AOS-CX.
