---
title: CVE-2026-31609 SMB Client Double-Free Vulnerability
slug: 2024-01-24-smb-double-free
description: CVE-2026-31609 is a critical double-free vulnerability in the SMB client, specifically within the smbd_free_send_io() function after smbd_send_batch_flush(), potentially leading to arbitrary code execution.
date: "2024-01-24T12:00:00Z"
severities:
  - critical
tags:
  - smb
  - double-free
  - cve-2026-31609
  - rce
vendors:
  - Microsoft
cves:
  - id: CVE-2026-31609
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-31609
rules:
  - title: Detect Potential SMB Double Free Exploitation via Unusual Process
    description: Detects processes making SMB connections from unusual locations, potentially indicative of exploitation attempts related to CVE-2026-31609.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - network_connection
      - windows
  - title: Detect SMB Client Executing from Suspicious Folders
    description: This rule detects SMB client binaries executing from folders commonly associated with malware or temporary files, which could indicate exploitation of CVE-2026-31609.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-31609 is a double-free vulnerability affecting the SMB (Server Message Block) client. The vulnerability resides in the `smbd_free_send_io()` function, which is called after `smbd_send_batch_flush()`. A double-free vulnerability occurs when memory is freed twice, potentially leading to corruption of the heap and potentially allowing an attacker to execute arbitrary code. The specifics of exploitation are not detailed in the initial advisory but successful exploitation could lead to a…
