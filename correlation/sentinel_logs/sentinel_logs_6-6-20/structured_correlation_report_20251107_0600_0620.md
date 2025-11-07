# 🔒 Security Correlation Analysis Report

**Generated:** 2025-11-07T17:33:33.629215  
**Analysis Engine:** CrewAI + Gemini 2.0 Flash (Optimized)  
**Total Events Analyzed:** 18

---

## 📊 Executive Summary

Identified impossible travel scenarios and unusual sign-in patterns for guest users. MFA enforcement gaps for guest users increase risk. Prioritize investigation of high-severity events and remediation of MFA policy.

---

## 📈 Summary Statistics

- 🔴 **High Priority Events:** 3
- 🟡 **Medium Priority Events:** 4
- 🟢 **Low Priority Events:** 1

---

## 🔴 HIGH PRIORITY EVENTS (Immediate Action Required)

### 🚨 Event 1: Impossible Travel - Himanshu S

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 10/10

#### 👤 User Information
- **User:** himanshu.s@yashtechnologies841.onmicrosoft.com
- **User ID:** `Unknown`
- **Type:** Member
- **Display Name:** Himanshu S

#### 📍 Location & Network
- **Location:** Ahmedabad, India
- **IP Address:** `49.249.104.218`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** MFA satisfied by claim in token
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Account Takeover (ATO), Session Hijacking, Credential Theft, use of proxy/VPN by an attacker

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** Rapid geographical change (Ahmedabad to Navi Mumbai in 8 seconds). MFA satisfied by token, CA policy in reportOnlySuccess mode.

---

### 🚨 Event 2: Impossible Travel - Prakhar Vyas (Member Account)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 10/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Member
- **Display Name:** Prakhar Vyas

#### 📍 Location & Network
- **Location:** New Delhi, India
- **IP Address:** `125.23.93.22`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** MFA satisfied by claim in token
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Account Takeover (ATO), Session Hijacking, Credential Theft, use of proxy/VPN by an attacker

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** Rapid geographical change (New Delhi to Mumbai in under 3 minutes). MFA satisfied by token, CA policy in reportOnlySuccess mode.

---

### 🚨 Event 3: Multiple First-time and Uncommonly Used Browser - Salunke Ajinkya Bhagwat (Guest User)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 9/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Salunke Ajinkya Bhagwat

#### 📍 Location & Network
- **Location:** Chhindwara, India
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ✅
- Investigation Priority: 1

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Account Takeover (ATO), Credential Theft, Reconnaissance (testing different access methods/browsers), bypassing security controls

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** FirstTimeUserConnectedViaBrowser: True AND BrowserUncommonlyUsedInTenant: True. FailedLogOn event just before successful one.

---

## 🟡 MEDIUM PRIORITY EVENTS (Investigation Recommended)

### ⚠️ Event 1: First-time ISP connection for Rohan Karekar (Guest User)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 6/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Rohan Karekar

#### 📍 Location & Network
- **Location:** Thathawade, India
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Azure DevOps
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ✅
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Initial Access (if compromised credentials were used), Reconnaissance, Policy Evasion (due to lack of enforced MFA)

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** FirstTimeUserConnectedViaISP: True (ISP not uncommonly used in tenant). Successful sign-in to Azure DevOps.

---

### ⚠️ Event 2: First-time ISP connection for Manisha Anil Thete (Guest User)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 6/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Manisha Anil Thete

#### 📍 Location & Network
- **Location:** Chhindwara, India
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Azure DevOps
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ✅
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Initial Access (if compromised credentials were used), Reconnaissance, Policy Evasion (due to lack of enforced MFA)

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** FirstTimeUserConnectedViaISP: True (ISP not uncommonly used in tenant). Successful sign-in to Azure DevOps.

---

### ⚠️ Event 3: First-time ISP connection for Lakhan Patidar (Guest User)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 6/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Lakhan Patidar

#### 📍 Location & Network
- **Location:** New Delhi, India
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** YASH-SPN-UES-Azure-App
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ✅
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Initial Access (if compromised credentials were used), Reconnaissance, Policy Evasion (due to lack of enforced MFA)

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** FirstTimeUserConnectedViaISP: True (ISP not uncommonly used in tenant). Successful sign-in to YASH-SPN-UES-Azure-App.

---

### ⚠️ Event 4: First-time ISP connection for Prakhar Vyas (Guest Account)

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 6/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Guest
- **Display Name:** Prakhar Vyas

#### 📍 Location & Network
- **Location:** New Delhi, India
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `Success`
- **Result:** Successful sign-in

#### 💻 Application & Resource
- **Application:** Azure DevOps
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ✅
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** Initial Access (if compromised credentials were used), Reconnaissance, Policy Evasion (due to lack of enforced MFA)

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** FirstTimeUserConnectedViaISP: True (ISP not uncommonly used in tenant). Successful sign-in to Azure DevOps.

---

## 🟢 LOW PRIORITY EVENTS (Informational)

### ℹ️ Event 1: Failed Logon for Salunke Ajinkya Bhagwat

**Event ID:** `Unknown`  
**Timestamp:** `Unknown`  
**Risk Score:** 3/10

#### 👤 User Information
- **User:** Unknown
- **User ID:** `Unknown`
- **Type:** Unknown
- **Display Name:** Salunke Ajinkya Bhagwat

#### 📍 Location & Network
- **Location:** Unknown, Unknown
- **IP Address:** `Unknown`
- **ISP:** Unknown

#### 🔐 Authentication Details
- **Method:** Unknown
- **Requirement:** Unknown
- **MFA Detail:** N/A
- **Result Code:** `50140`
- **Result:** 'Keep me signed in' interrupt

#### 💻 Application & Resource
- **Application:** Unknown
- **App ID:** `Unknown`
- **Resource:** Unknown

#### 🎯 Behavioral Flags
- First Time Device: ❌
- First Time Browser: ❌
- First Time App: ❌
- First Time Resource: ❌
- First Time Country: ❌
- First Time ISP: ❌
- Uncommonly Used Browser: ❌
- Investigation Priority: N/A

#### 🔍 Correlation Analysis

**Threat Indicators:**


**Behavioral Patterns:**


**Attack Vector:** None directly, but could be a precursor to user frustration leading to less secure practices

**Recommended Actions:**


**Related Events:** None identified

**Raw Event Summary:** ActivityType: "FailedLogOn" with a specific error message. Password was correct.

---


---

## 📝 Notes

This report was generated using AI-powered security correlation analysis. All events have been 
analyzed for behavioral anomalies, authentication patterns, and threat indicators. Please review 
high-priority events immediately and validate medium-priority events with the respective users.

**Report Generated By:** Advanced Security Correlation Engine v2.0 (Optimized)
