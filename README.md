# Conditional Access Analyzer

A comprehensive PowerShell module for analyzing and assessing Conditional Access policies in Microsoft Entra ID (formerly Azure AD).

## Overview

The Conditional Access Analyzer is designed to help security professionals and Identity administrators evaluate their Conditional Access configuration against security best practices. It performs automated checks across all key Zero Trust pillars including MFA enforcement, device compliance, risk-based access, and data protection.

![Conditional Access Report Example](https://raw.githubusercontent.com/DataGuys/ConditionalAccess/main/assets/report-example.png)

## Features

- **MFA Enforcement Analysis**
  - Verify MFA requirements for privileged administrative roles
  - Validate MFA policies for regular users across applications
  - Identify admin roles without proper MFA protection

- **Device Compliance Validation**
  - Check for device compliance requirements in access policies
  - Validate token-to-device binding settings
  - Analyze session control configurations

- **Risk-Based Policy Evaluation**
  - Assess sign-in risk policies
  - Evaluate user risk-based protections
  - Provide recommendations for risk-based controls

- **Mobile Application Management**
  - Verify MAM/APP policies for BYOD scenarios
  - Check for cut/copy/paste restrictions
  - Review data protection controls for mobile devices

- **Zero Trust Network Access**
  - Analyze Microsoft Defender for Cloud Apps integration
  - Check Global Secure Access configuration
  - Evaluate zero-trust network access policies

- **Comprehensive Reporting**
  - Generate detailed HTML reports with compliance scoring
  - Export results in CSV and JSON formats
  - Provide actionable recommendations

## Prerequisites

- PowerShell 5.1 or higher
- The following Microsoft Graph PowerShell modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.DeviceManagement
- Appropriate permissions in your Entra ID tenant:
  - Policy.Read.All
  - Directory.Read.All
  - DeviceManagementConfiguration.Read.All
  - DeviceManagementApps.Read.All
  - IdentityRiskyUser.Read.All
  - NetworkAccessPolicy.Read.All

## Installation

### Using Azure Cloud Shell (Recommended)

**Option 1: Direct Import (Fastest)**

Import the module directly from GitHub with a single line:

```powershell
# One-line direct import (no download needed)
Import-Module (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccess/refs/heads/main/ConditionalAccessAnalyzer.psm1" -UseBasicParsing).Content
```

**Option 2: Clone Repository**

1. Open [Azure Cloud Shell](https://shell.azure.com/) in PowerShell mode

2. Clone this repository directly in Cloud Shell:
```powershell
git clone https://github.com/DataGuys/ConditionalAccess.git
cd ConditionalAccess
```

3. Import the module:
```powershell
Import-Module ./ConditionalAccessAnalyzer.psm1
```

### Local Installation (Alternative)

If you prefer to run locally:

```powershell
# Option 1: Direct import (no download needed)
Import-Module (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccess/refs/heads/main/ConditionalAccessAnalyzer.psm1" -UseBasicParsing).Content

# Option 2: Clone repository
git clone https://github.com/DataGuys/ConditionalAccess.git
Import-Module .\ConditionalAccess\ConditionalAccessAnalyzer.psm1
```

## Usage

### Quick Start (One-liner to connect)

Copy and paste this one-liner into Azure Cloud Shell to ensure proper connectivity:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement -Force -AllowClobber; Connect-MgGraph -Scopes "Policy.Read.All","Directory.Rea
