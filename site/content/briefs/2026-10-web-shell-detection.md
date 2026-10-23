---
brief_id: brief-2026-10-23-web-shell-detection
event_id: brief-2026-10-23-web-shell-detection
revision: 1
activity_at: "2026-10-23T08:17:54Z"
title: 'Web Shell Detection: Script Process Child of Common Web Processes'
slug: 2026-10-web-shell-detection
description: Identifies suspicious commands executed via a web server, which may suggest a vulnerability and remote shell access.
date: "2026-10-23T08:17:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
cpes:
  - cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:cx_cloud_agent:*:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_automated_test_suite:1.9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_automated_test_suite:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_console:1.9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_console:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_exposure_function:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_function_cloud_native_environment:1.10.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_function_cloud_native_environment:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:1.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_repository_function:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_slice_selection_function:1.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_slice_selection_function:1.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_network_slice_selection_function:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_policy:1.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_policy:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_security_edge_protection_proxy:1.7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_security_edge_protection_proxy:22.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_unified_data_repository:1.15.0:*:*:*:*:*:*:*
  - cpe:2.3:a:oracle:communications_cloud_native_core_unified_data_repository:22.1.0:*:*:*:*:*:*:*
cves:
  - id: CVE-2022-22965
    cvss: 9.8
    epss: 0.99638
    kev_status: "false"
references:
  - https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/
  - https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_webshell_detection.toml
---

This rule identifies suspicious processes (e.g., cmd.exe, powershell.exe, wmic.exe, curl.exe) 
launched by common web server applications such as w3wp.exe, httpd.exe, nginx.exe, and others. 
Such behavior may indicate the exploitation of a vulnerability and the presence of a web shell 
providing remote access.

False positives may occur during security audits, maintenance, or administrative scripting. 
Legitimacy should be evaluated by aligning parent context, child identity, command scope, 
service identity, and available artifact/destination evidence.
