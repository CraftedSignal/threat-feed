---
title: Public Exploit for Zephyr RTOS LwM2M Out-of-Bounds Read (CVE-2026-10672)
slug: 2026-07-zephyr-lwm2m-oob-read-poc
description: A public Proof of Concept (PoC) is available for CVE-2026-10672, an out-of-bounds read vulnerability in the LwM2M firmware update component of Zephyr RTOS versions 3.0.0 through 4.4.0, allowing an attacker to exfiltrate up to 13 bytes of sensitive data from adjacent memory via crafted CoAP requests, significantly elevating risk for unpatched IoT and embedded systems.
date: "2026-07-18T10:02:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - out-of-bounds-read
  - data-exfiltration
  - firmware
  - rtos
  - iot
  - embedded
vendors:
  - Zephyr Project
products:
  - Zephyr RTOS (v3.0.0)
  - Zephyr RTOS (v3.1.0)
  - Zephyr RTOS (v3.2.0)
  - Zephyr RTOS (v3.3.0)
  - Zephyr RTOS (v3.4.0)
  - Zephyr RTOS (v3.5.0)
  - Zephyr RTOS (v4.0.0)
  - Zephyr RTOS (v4.1.0)
  - Zephyr RTOS (v4.2.0)
  - Zephyr RTOS (v4.3.0)
  - Zephyr RTOS (v4.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public exploit or PoC has been published on Sploitus for CVE-2026-10672. The availability of a working exploit significantly elevates the risk for unpatched systems.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: The over-read bytes are exfiltrated in the outbound CoAP request.
    confidence_band: high
cves:
  - id: CVE-2026-10672
    cvss: 8.2
    epss: 0.00277
references:
  - https://sploitus.com/exploit?id=6F71ACF5-6AA8-5E0B-A9B4-09D9091D7204
  - https://www.hunt-benito.com/blog/zephyr-lwm2m-firmware-update-oob-read-cve-2026-10672-truncated-package-uri/
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=6F71ACF5-6AA8-5E0B-A9B4-09D9091D7204
  - type: url
    value: https://www.hunt-benito.com/blog/zephyr-lwm2m-firmware-update-oob-read-cve-2026-10672-truncated-package-uri/
ioc_counts:
  url: 2
---

A public Proof of Concept (PoC) has been released for **CVE-2026-10672**, an out-of-bounds read vulnerability impacting the LwM2M firmware-update pull client within Zephyr RTOS. Specifically, the flaw exists in the `lwm2m_pull_context_start_transfer()` function in `subsys/net/lib/lwm2m/lwm2m_pull_context.c`. Affected versions include Zephyr v3.0.0 through v4.4.0. An attacker can exploit this by supplying an oversized Package URI (128 bytes or more) during a firmware update over CoAP, causing the system to read past an allocated 128-byte buffer. This leads to the exfiltration of up to 13 bytes of sensitive data from adjacent memory locations within the `firmware_pull_context` struct, such as `is_firmware_uri` flags or function pointers, which are then included in outbound CoAP requests. The public availability of this PoC significantly increases the risk for unpatched embedded and IoT devices utilizing the vulnerable Zephyr RTOS component.

## Attack Chain

1. An attacker establishes network access to a vulnerable Zephyr RTOS device running the LwM2M pull client, potentially as a malicious LwM2M management server or an on-path adversary.
2. The attacker sends a CoAP PUT request to the LwM2M Package URI resource (`/5/0/1`) on the vulnerable device.
3. The PUT request includes a crafted, oversized Package URI payload (≥ 128 bytes), which is not NUL-terminated by the server.
4. The attacker then sends a CoAP POST request to the LwM2M Execute Update resource (`/5/0/2`), triggering the firmware update process on the client.
5. During the update process, the `lwm2m_pull_context_start_transfer()` function in `lwm2m_pull_context.c` performs a `memcpy` of the oversized URI into `context.uri` (a 128-byte buffer) without NUL-termination.
6. Subsequent operations, such as `strlen(context.uri)`, `http_parser_parse_url()`, and appending the CoAP `PROXY_URI` option, attempt to read beyond the `context.uri` buffer.
7. This out-of-bounds read accesses adjacent memory locations, such as `is_firmware_uri`, struct padding, and `result_cb`/`write_cb` function pointers.
8. The over-read bytes, including the sensitive data, are then exfiltrated within the outbound CoAP request sent by the vulnerable Zephyr device.

## Impact

The successful exploitation of CVE-2026-10672 leads to the leakage of sensitive data from the memory of vulnerable Zephyr RTOS devices. While the exploit demonstrates the exfiltration of 13 bytes, this information could include critical configuration flags, memory addresses of function pointers, or other internal state, which might be leveraged in subsequent attacks to bypass Address Space Layout Randomization (ASLR), gain code execution, or further compromise the device. Given that Zephyr RTOS is commonly used in IoT and embedded systems, successful attacks could expose proprietary device configurations, compromise device integrity, or facilitate deeper access to constrained environments where these devices operate.

## Recommendation

* **Patch CVE-2026-10672** immediately by upgrading Zephyr RTOS to version v4.4.1 or v4.3.1 or newer.
* Monitor network traffic for unusual CoAP traffic patterns, specifically inbound CoAP PUT requests to `/5/0/1` or POST requests to `/5/0/2` with unusually large URI payloads, or outbound CoAP requests containing `PROXY_URI` options with unusual lengths (e.g., >128 bytes), as indicated by the exploit for **CVE-2026-10672**.
* Implement strong network segmentation for IoT and embedded devices to limit exposure to untrusted networks, particularly for devices running Zephyr RTOS, to prevent attackers from sending crafted CoAP requests.
* Ensure proper authentication and encryption (DTLS) are enforced for LwM2M server communication, as detailed in the source's `lwm2m_evil_server.py` script.
