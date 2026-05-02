---
title: Salon Booking System WordPress Plugin Arbitrary File Read Vulnerability
slug: 2026-05-wordpress-arbitrary-file-read
description: The Salon Booking System WordPress plugin is vulnerable to arbitrary file read, allowing unauthenticated attackers to exfiltrate local files by manipulating file-field values in booking confirmation emails.
date: "2026-05-02T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-read
  - wordpress
  - plugin-vulnerability
  - cve
vendors:
  - WordPress
products:
  - Salon Booking System – Free Version plugin for WordPress <= 10.30.25
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-6320
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6320
  - https://plugins.trac.wordpress.org/changeset/3512110/salon-booking-system
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e91b8082-e1c7-4989-82db-20e255b52854?source=cve
rules:
  - title: Detect WordPress Plugin Arbitrary File Read Attempt via URI
    description: Detects attempts to exploit arbitrary file read vulnerabilities in WordPress plugins by identifying requests with suspicious file paths in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Arbitrary File Read in POST Request
    description: Detects attempts to exploit arbitrary file read vulnerabilities in WordPress plugins by identifying requests with suspicious file paths in POST data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Salon Booking System – Free Version plugin for WordPress, versions up to and including 10.30.25, contains an arbitrary file read vulnerability. This flaw stems from the plugin's public booking flow, where it accepts attacker-controlled file-field values. These values are subsequently used as trusted paths when creating email attachments for booking confirmations. This allows an unauthenticated attacker to supply a path to any file accessible to the web server, triggering its inclusion as an attachment in the booking confirmation email, effectively enabling arbitrary file exfiltration. Exploitation requires no authentication and can be triggered remotely.

## Attack Chain

1.  An unauthenticated attacker accesses the public booking form of a WordPress site running the vulnerable Salon Booking System plugin.
2.  The attacker crafts a malicious request to the booking form, injecting a file path (e.g., `/etc/passwd`) into a file-field parameter.
3.  The plugin processes the booking request and stores the attacker-supplied file path.
4.  The plugin generates a booking confirmation email.
5.  The plugin uses the stored, attacker-controlled file path to attach the specified file to the confirmation email.
6.  The booking confirmation email, now containing the arbitrary file as an attachment, is sent to the user who initiated the booking (which could be the attacker or an unwitting third party).
7.  The attacker retrieves the email (if sent to the attacker) or intercepts it (if sent to a third party) and extracts the attached file.
8.  The attacker gains unauthorized access to the contents of the exfiltrated file.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to read arbitrary files from the affected WordPress server. This could lead to the disclosure of sensitive information, such as configuration files, database credentials, or other confidential data. The vulnerability affects versions of the Salon Booking System plugin up to and including 10.30.25. The number of affected WordPress installations is unknown, but could be substantial given the plugin's popularity.

## Recommendation

*   Upgrade the Salon Booking System plugin to the latest version to patch CVE-2026-6320.
*   Monitor web server logs (category `webserver`, product `linux`) for suspicious requests containing absolute or relative file paths in file-field parameters, using a detection rule similar to the ones provided below.
*   Implement strict input validation and sanitization for all user-supplied data, especially file paths.
*   Review and restrict file system permissions to limit the files accessible to the web server process.
