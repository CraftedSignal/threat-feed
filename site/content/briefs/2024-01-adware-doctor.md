---
title: Adware Doctor Steals and Exfiltrates Browser History from Mac App Store Users
slug: 2024-01-adware-doctor
description: Adware Doctor, a popular app available on the Mac App Store, surreptitiously steals user's browsing history from Safari and Chrome, compresses the data into a password-protected zip archive, and exfiltrates it to a remote server.
date: "2026-05-07T07:33:40Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - adware
  - exfiltration
  - macos
vendors:
  - Apple
products:
  - Adware Doctor
  - Mac App Store
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Gather Victim Host Information
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://objective-see.org/blog/blog_0x37.html
iocs:
  - type: domain
    value: adwareres.securemacos.com
  - type: domain
    value: adscan.yelabapp.com
  - type: hash_md5
    value: 48a96e1c00be257debc9c9c58fafaffe
  - type: hash_md5
    value: f1a19b8929ec88a81a6bdce6d5ee66e6
  - type: hash_md5
    value: 3e653285b290c12d40982e6bb65928c1
  - type: hash_md5
    value: 801e59290d99ecb39fd218227674646e
  - type: hash_md5
    value: 8d0cd4565256a781f73aa1e68e2a63de
  - type: hash_md5
    value: e233edd82b3dffd41fc9623519ea281b
  - type: hash_md5
    value: 1db830f93667d9c38dc943595dcc2d85
ioc_counts:
  domain: 2
  hash_md5: 7
rules:
  - title: Detect Adware Doctor History Zip
    description: Detects the use of zip to archive browser history with a hardcoded password, a technique used by Adware Doctor.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1560.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Adware Doctor History Access
    description: Detects processes accessing browser history files outside of known browser applications.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1560.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

Adware Doctor, a top-grossing application found on the official Mac App Store, has been observed surreptitiously exfiltrating highly sensitive user information, specifically browser history, to a remote server. Discovered in August 2018 by @privacyis1st and further analyzed by Objective-See, the application claims to remove adware but in reality, it gathers browsing history from Safari and Chrome, zips the data, passwords it with "webtool," and uploads it to adscan.yelabapp.com. This behavior bypasses user expectations of privacy within the Apple ecosystem, especially given Apple's claims of rigorous app review. The application was sold for $4.99, potentially impacting a large number of users. Adware Doctor also has a history of using deceptive tactics and was previously known as "Adware Medic," which was pulled from the store and quickly reappeared under a different name.

## Attack Chain

1.  User downloads and installs "Adware Doctor" from the official Mac App Store.
2.  The user clicks the "Clean" button within the application's UI, initiating the data collection process.
3.  Adware Doctor accesses and reads browser history databases, including `~/Library/Safari/History.db` and `~/Library/Application Support/Google/Chrome/Default/History`.
4.  The application creates a directory `~/Library/Containers/com.yelab.Browser-Sweeper/Data/Library/Application Support/com.yelab.Browser-Sweeper/history` to store gathered history data.
5.  Adware Doctor uses the built-in `zip` utility to compress the collected browser history into `history.zip`, protected with the password "webtool."
6.  The application attempts to upload the `history.zip` file to the domain `adscan.yelabapp.com` via a POST request to the `/1/checkadware` endpoint.
7.  The exfiltrated data includes browsing history from Safari, Chrome, and potentially other browsers installed on the system.

## Impact

The successful exfiltration of browser history allows the attacker to gain insight into a user's browsing habits, visited websites, search queries, and potentially login credentials stored within browser data. Given Adware Doctor's popularity as a top-grossing app in the Mac App Store at the time, a significant number of users were likely affected. This data could be used for targeted advertising, identity theft, or other malicious purposes. The incident undermines user trust in the Mac App Store's security measures and Apple's review process.

## Recommendation

*   Monitor process creations for the execution of `/bin/bash` with command-line arguments indicative of zip archive creation with a hardcoded password as shown in the Sigma rule "Detect Adware Doctor History Zip".
*   Monitor network connections to `adscan.yelabapp.com` to identify potential exfiltration attempts, as detailed in the IOC list.
*   Implement the Sigma rule "Detect Adware Doctor History Access" to detect suspicious file access patterns to browser history databases by processes outside the expected browser applications.
