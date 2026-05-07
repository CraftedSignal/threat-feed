---
title: ToTok iOS Application Used for Government Surveillance
slug: 2024-01-totok-spyware
description: The ToTok iOS application, developed by Breej Holding Ltd., was identified as a spying tool used by the government of the United Arab Emirates (UAE) to track users' conversations, movements, and relationships by collecting sensitive user data and transmitting it to servers using self-signed certificates.
date: "2024-01-27T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - spyware
  - ios
  - surveillance
  - totok
vendors:
  - Apple
  - Breej Holding Ltd.
  - Facebook
products:
  - ToTok
  - iOS App Store
affected_os:
  - ios
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
references:
  - https://objective-see.org/blog/blog_0x52.html
  - https://www.nytimes.com/2019/12/22/us/politics/totok-app-uae.html
iocs:
  - type: domain
    value: im.totok.ai
  - type: hash_sha256
    value: c92730ccd5fec0463de85aa66dfaab2f3b924e04c51e0b6fa431fe783348b574
ioc_counts:
  domain: 1
  hash_sha256: 1
rules:
  - title: Detect iOS App Requesting Excessive Permissions
    description: Detects iOS applications that request a combination of sensitive permissions, such as microphone, camera, location, photos, contacts, siri integration, and calendar, which is indicative of potentially malicious data collection.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - app_permissions
      - ios
  - title: Detect iOS App Connecting to Host with UAE Self-Signed Certificate
    description: Detects iOS applications connecting to hosts using self-signed certificates where the issuing country is the United Arab Emirates (AE).
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1573.002
    data_sources:
      - network_connection
      - ios
rules_count: 2
---

The ToTok application, developed by Breej Holding Ltd., gained popularity in the United Arab Emirates (UAE) due to the blocking of other VoIP services like Skype and WhatsApp. However, American officials identified ToTok as a spying tool used by the UAE government to track users. The application collects extensive user data, including microphone, calendar, location, photos, contacts, and camera information. This data is transmitted over the network, with traffic primarily routed through the capi.im.totok.ai server. The application's Info.plist reveals it requests permissions for accessing sensitive user information, and uses HTTP, which is atypical for iOS applications, as iOS typically enforces HTTPS only. The application has since been removed from the iOS App Store after these concerns were raised.

## Attack Chain

1. User downloads and installs the ToTok application from the iOS App Store.
2. The application requests permissions to access microphone, calendar, location, photos, contacts, camera, and Siri integration.
3. User grants the application permissions to access their data.
4. The application collects user data, including contacts, location, and communications.
5. The application transmits collected data to the capi.im.totok.ai server.
6. Network communications are encrypted via SSL, but the application uses a self-signed certificate, potentially undermining trust.
7. The UAE government leverages the collected data for surveillance purposes.
8. The application runs in the background due to UIBackgroundModes, continuously collecting and transmitting data.

## Impact

The ToTok application enabled mass surveillance by the UAE government, impacting tens of thousands of users. User privacy was compromised, with conversations, movements, relationships, appointments, sounds, and images being tracked. The application's ability to run in the background allowed for continuous data collection, and the use of a self-signed certificate raises concerns about the security and integrity of the transmitted data. The removal of the app from the iOS App Store indicates a recognition of the severe security and privacy risks posed by ToTok.

## Recommendation

*   Monitor network traffic for connections to the domain `im.totok.ai` and block if found, as this was the primary communication channel (IOC table).
*   Implement a detection rule to identify applications using self-signed certificates issued from the United Arab Emirates (AE), as observed with the ToTok application (see rule: "Detect iOS App Connecting to Host with UAE Self-Signed Certificate").
*   Develop a Sigma rule to detect iOS applications requesting access to microphone, camera, location, photos, contacts, siri integration, and calendar permissions simultaneously, as this is indicative of potentially malicious data collection (see rule: "Detect iOS App Requesting Excessive Permissions").
