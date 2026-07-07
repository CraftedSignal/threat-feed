---
title: OpenRemote Incomplete Fix for XXE in KNXProtocol Leads to Arbitrary File Read (CVE-2026-54640)
slug: 2026-07-openremote-xxe-incomplete-fix
description: An incomplete fix for CVE-2026-40882 in OpenRemote's KNXProtocol module (specifically in versions <= 1.24.1 of the agent module) allows authenticated users to perform an XML External Entity (XXE) injection, enabling arbitrary file read from the server's filesystem, including sensitive configuration files and potentially leading to server-side request forgery (SSRF) against cloud metadata endpoints or internal services, without requiring administrator access.
date: "2026-07-06T20:59:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openremote:openremote:*:*:*:*:*:*:*:*
tags:
  - xxe
  - arbitrary-file-read
  - ssrf
  - openremote
  - iot
  - vulnerability
  - incomplete-fix
vendors:
  - OpenRemote
products:
  - OpenRemote Agent (<= 1.24.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: allows any authenticated user to read arbitrary files from the server filesystem (e.g. `/etc/passwd`, `openmrs-runtime.properties`, cloud credential files)
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: POST /api/{realm}/agent/{agentId}/import (authenticated user, PR:L) ... → KNXProtocol.startAssetImport(byte[] fileData)
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: cloud provider metadata endpoints via SSRF (`http://169.254.169.254/...`)
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1090
    technique_name: Proxy
    evidence: potential server-side request forgery (SSRF) ... Internal service endpoints reachable from the server
    confidence_band: med
cves:
  - id: CVE-2026-40882
    cvss: 7.6
    epss: 0.00249
references:
  - https://github.com/advisories/GHSA-7v6w-c3f4-9wpq
iocs:
  - type: filepath
    value: /etc/passwd
  - type: filepath
    value: openmrs-runtime.properties
  - type: url
    value: http://169.254.169.254/...
ioc_counts:
  filepath: 2
  url: 1
---

OpenRemote, an open-source IoT platform, has an incomplete fix for a previously identified XML External Entity (XXE) vulnerability, CVE-2026-40882. The original patch for CVE-2026-40882 only secured the Velbus asset import handler, leaving the `KNXProtocol` handler vulnerable to arbitrary file read. Versions up to and including 1.24.1 of the `openremote-agent` module are affected by this newly identified vulnerability, tracked as CVE-2026-54640. An authenticated, non-administrative user can exploit this flaw by uploading a specially crafted ETS project ZIP file containing malicious XML. This allows attackers to read arbitrary files from the server's filesystem, including `/etc/passwd`, application configuration files with credentials, or even leverage Server-Side Request Forgery (SSRF) to access internal network resources or cloud metadata endpoints. This poses a significant risk to the confidentiality of sensitive data and can lead to further compromise of the OpenRemote instance and its underlying infrastructure.

## Attack Chain

1.  An authenticated, non-administrative attacker sends an HTTP POST request to the `/api/{realm}/agent/{agentId}/import` endpoint with a malicious ETS project ZIP file as `fileData`.
2.  The OpenRemote `AgentResourceImpl.doProtocolAssetImport()` method receives the `fileData` and passes it to `KNXProtocol.startAssetImport()`.
3.  `KNXProtocol` extracts the `0.xml` file from the attacker-controlled ZIP archive using a `ZipInputStream`.
4.  The content of `0.xml` is processed by the Saxon `TransformerFactoryImpl.newTransformer()` and `transform()` methods without XXE protection, allowing external entities to be resolved.
5.  Separately, `XMLInputFactory.newInstance().createXMLStreamReader()` also processes the `0.xml` content without XXE protection.
6.  Both XML parsers resolve an external entity defined in the malicious `0.xml` (e.g., `<!ENTITY xxe SYSTEM "file:///etc/passwd">`), leading to arbitrary file read.
7.  The contents of the arbitrary file are returned to the attacker within the response of the import process or are processed in a way that allows exfiltration.
8.  Successful exploitation results in the attacker obtaining sensitive information from the server filesystem or probing internal network resources via SSRF.

## Impact

This vulnerability allows any authenticated user, even without administrative privileges, to read arbitrary files from the server filesystem. This includes critical system files like `/etc/passwd`, enabling user enumeration and reconnaissance. More significantly, it allows access to application configuration files (e.g., `openmrs-runtime.properties`) that might contain sensitive database credentials, API keys, or other secrets. The potential for Server-Side Request Forgery (SSRF) further broadens the attack surface, allowing attackers to query cloud provider metadata endpoints (e.g., `http://169.254.169.254/`) for cloud credentials or access internal services reachable from the vulnerable OpenRemote server. The vulnerability is present in a core protocol handler (`KNXProtocol`) shipped with the OpenRemote agent module, making all default installations running affected versions susceptible to this critical data exfiltration risk.

## Recommendation

*   **Patch CVE-2026-54640 immediately:** Upgrade the `io.openremote:openremote-agent` module to a version patched against CVE-2026-54640.
*   **Review and audit configurations:** Conduct an audit of all OpenRemote instances to identify any running `openremote-agent` modules and verify their versions, applying the necessary updates.
*   **Implement network segmentation:** Restrict network access to cloud metadata endpoints and internal services from OpenRemote servers to mitigate the impact of potential SSRF exploitation, as mentioned in the Impact section.
*   **Enable webserver logging for API POST requests:** Implement detailed logging for POST requests to `/api/{realm}/agent/{agentId}/import` on your web servers (e.g., NGINX, Apache, IIS). Monitor for unusually large or malformed XML payloads within the fileData parameter that might indicate attempted XXE exploitation, although this may require deep packet inspection or WAF capabilities.
*   **Apply WAF rules for XXE:** Configure your Web Application Firewall (WAF) to detect and block XML External Entity (XXE) injection attempts in XML content submitted to the affected `/api` endpoints, specifically looking for `<!DOCTYPE` declarations containing `SYSTEM` or `PUBLIC` identifiers.
