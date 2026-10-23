---
brief_id: brief-2026-10-23-linux-web-server-child-execution
event_id: brief-2026-10-23-linux-web-server-child-execution
revision: 1
activity_at: "2026-10-23T14:42:06Z"
title: 'Linux Web Server: Suspicious Child Process Execution'
slug: 2026-10-linux-web-server-child-execution
description: This rule identifies suspicious child processes executed via a web server, which may indicate web shell usage, vulnerability exploitation, or unauthorized command execution for persistence.
date: "2026-10-23T14:42:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
tags:
  - persistence
  - initial-access
  - web-shell
  - linux
cves:
  - id: CVE-2022-22965
    cvss: 9.8
    epss: 0.99638
    kev_status: "false"
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_suspicious_child_execution.toml
  - https://pentestlab.blog/tag/web-shell/
  - https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965
---

Adversaries may exploit vulnerabilities in web applications to execute commands via a web server or deploy web shells to establish persistent access. This detection monitors for web server processes (such as Nginx, Apache, or Java-based application servers) spawning script interpreters, command-line interface programs, or tools associated with reverse shells and system enumeration.
