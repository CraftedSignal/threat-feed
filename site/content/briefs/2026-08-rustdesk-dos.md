---
title: Uncontrolled Memory Allocation in RustDesk BytesCodec
slug: 2026-08-rustdesk-dos
description: RustDesk versions before 1.4.7 are susceptible to a denial-of-service attack where unauthenticated attackers trigger memory exhaustion through malformed TCP frame headers.
date: "2026-08-26T16:21:48Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - RustDesk
products:
  - RustDesk (< 1.4.7)
cves:
  - id: CVE-2026-73108
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73108
---

RustDesk versions prior to 1.4.7 contain a vulnerability in the BytesCodec component related to uncontrolled speculative memory allocation. The vulnerability occurs because the decoder process fails to validate the payload length field contained within a four-byte frame header before authentication occurs. By sending a crafted header indicating an excessively large payload size, an attacker can force the application to reserve up to 1,073,741,823 bytes (1 GB) of memory per connection. An attacker can leverage multiple concurrent TCP connections to rapidly exhaust host system memory, leading to a denial-of-service condition. The vendor addressed this issue in version 1.4.7 by implementing a hard limit on preallocation requests, capping them at 256 KiB. This vulnerability is significant for organizations relying on RustDesk for remote access, as it allows unauthenticated remote adversaries to crash host instances without requiring existing credentials.

## Attack Chain

1. Attacker establishes a TCP connection to the target RustDesk listener port.
2. Attacker transmits a crafted four-byte frame header preceding any authentication handshake.
3. The BytesCodec component reads the payload length field from the header.
4. The component incorrectly trusts the length field and attempts to allocate memory for the entire payload.
5. The OS memory manager reserves up to 1 GB of RAM based on the malicious header.
6. Attacker initiates high volumes of concurrent TCP connections with similar headers.
7. System resources are depleted, resulting in process crash or host instability (Denial of Service).

## Impact

Successful exploitation results in a denial-of-service, rendering the RustDesk remote access service unavailable. This impacts internal operations or managed remote support capabilities. Depending on host resources, this can lead to service instability or total system crash, requiring manual intervention to restore service availability.

## Recommendation

Prioritize the upgrade of all RustDesk instances to version 1.4.7 or later to implement the 256 KiB preallocation cap. Monitor host memory utilization for anomalous spikes associated with the RustDesk process, particularly originating from unauthenticated source IPs, to identify potential exploitation attempts.
