---
title: Remote Server-Side Request Forgery in Sipeed PicoClaw (CVE-2026-16084)
slug: 2026-07-sipeed-picoclaw-ssrf
description: A server-side request forgery (SSRF) vulnerability, CVE-2026-16084, has been identified in Sipeed PicoClaw versions up to 0.2.9, allowing remote exploitation due to a weakness in the `web_fetch` function of `pkg/tools/integration/web.go`, with a public exploit available.
date: "2026-07-18T09:18:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - remote-exploitation
  - sipeed
  - picoclaw
vendors:
  - Sipeed
products:
  - PicoClaw (0.2.9 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This manipulation causes server-side request forgery... The attacker leverages the server's access to enumerate internal network resources, identify accessible services, or bypass firewall restrictions.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: The server acts as an unwitting proxy, making a request on behalf of the attacker to the target resource.
    confidence_band: high
cves:
  - id: CVE-2026-16084
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16084
  - https://github.com/sipeed/picoclaw/
  - https://github.com/sipeed/picoclaw/commit/c15aac21fe05ee103a470e1104bc891754e83392
  - https://github.com/sipeed/picoclaw/issues/3074
  - https://github.com/sipeed/picoclaw/pull/3143
  - https://vuldb.com/cve/CVE-2026-16084
  - https://vuldb.com/submit/852946
  - https://vuldb.com/vuln/379796
  - https://vuldb.com/vuln/379796/cti
iocs:
  - type: url
    value: https://github.com/sipeed/picoclaw/
  - type: url
    value: https://github.com/sipeed/picoclaw/commit/c15aac21fe05ee103a470e1104bc891754e83392
  - type: hash_sha1
    value: c15aac21fe05ee103a470e1104bc891754e83392
  - type: url
    value: https://github.com/sipeed/picoclaw/issues/3074
  - type: url
    value: https://github.com/sipeed/picoclaw/pull/3143
  - type: url
    value: https://vuldb.com/cve/CVE-2026-16084
  - type: url
    value: https://vuldb.com/submit/852946
  - type: url
    value: https://vuldb.com/vuln/379796
  - type: url
    value: https://vuldb.com/vuln/379796/cti
ioc_counts:
  hash_sha1: 1
  url: 8
rules:
  - title: Detect Possible SSRF Outbound Connection from Sipeed PicoClaw (CVE-2026-16084)
    description: Detects CVE-2026-16084 exploitation by identifying suspicious outbound network connections initiated by the Sipeed PicoClaw application, potentially indicating server-side request forgery (SSRF). This rule assumes the executable name for PicoClaw is 'picoclaw' and it may run on Linux or Windows.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1090.003
      - T1595.001
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

A high-severity server-side request forgery (SSRF) vulnerability, tracked as CVE-2026-16084, has been discovered in Sipeed PicoClaw, affecting all versions up to and including 0.2.9. The weakness resides within the `web_fetch` function located in the `pkg/tools/integration/web.go` file, allowing for remote exploitation without authentication. Attackers can manipulate server-side requests to access internal network resources or bypass external restrictions. A public exploit for this vulnerability is available, increasing the immediate risk of exploitation. Defenders should prioritize patching this vulnerability to prevent potential network compromise and data exposure.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to a vulnerable Sipeed PicoClaw server, specifically targeting the `web_fetch` function.
2. The attacker embeds a malicious URL, which could point to an internal network resource (e.g., `192.168.1.100`, `localhost`) or a controlled external service, within the request parameters.
3. The `web_fetch` function in `pkg/tools/integration/web.go` processes this attacker-controlled input without sufficient validation or sanitization.
4. As a result, the Sipeed PicoClaw server's process (e.g., `picoclaw`) initiates an unexpected outbound network connection to the URL specified by the attacker.
5. The server acts as an unwitting proxy, making a request on behalf of the attacker to the target resource.
6. The response from the target resource is then transmitted back to the Sipeed PicoClaw server, which may relay it to the attacker, potentially exposing sensitive information.
7. The attacker leverages the server's elevated access to perform actions such as internal network enumeration, port scanning, accessing sensitive services, or bypassing firewall rules.

## Impact

Successful exploitation of CVE-2026-16084 can lead to significant network exposure and potential data exfiltration. Attackers can use the vulnerable PicoClaw server to access services and systems on internal networks that are otherwise inaccessible from the internet. This includes scanning internal ports, accessing internal APIs, or retrieving sensitive data from other internal applications. The public availability of an exploit significantly increases the likelihood of widespread attacks, making unpatched systems prime targets for network reconnaissance and further compromise.

## Recommendation

* Immediately apply the patch associated with commit `c15aac21fe05ee103a470e1104bc891754e83392` to all Sipeed PicoClaw installations to mitigate CVE-2026-16084.
* Deploy the Sigma rule "Detect Possible SSRF Outbound Connection from Sipeed PicoClaw (CVE-2026-16084)" to your SIEM to identify suspicious outbound network connections originating from the `picoclaw` process.
* Enable comprehensive network connection logging for all servers running Sipeed PicoClaw to monitor for unexpected outbound traffic to internal or unusual external IP addresses.
