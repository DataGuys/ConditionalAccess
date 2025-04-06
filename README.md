# Conditional Access Analyzer

A comprehensive PowerShell module for analyzing and assessing Conditional Access policies in Microsoft Entra ID (formerly Azure AD).

## Overview

The Conditional Access Analyzer is designed to help security professionals and Identity administrators evaluate their Conditional Access configuration against security best practices. It performs automated checks across all key Zero Trust pillars including MFA enforcement, device compliance, risk-based access, and data protection.

![Conditional Access Report Example](https://raw.githubusercontent.com/username/ConditionalAccess/main/assets/report-example.png)

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

1. Open [Azure Cloud Shell](https://shell.azure.com/) in PowerShell mode

2. Clone this repository directly in Cloud Shell:
```powershell
git clone https://github.com/username/ConditionalAccess.git
cd ConditionalAccess
```

3. Import the module:
```powershell
Import-Module ./ConditionalAccessAnalyzer.psm1
```

### Local Installation (Alternative)

If you prefer to run locally:

```powershell
git clone https://github.com/username/ConditionalAccess.git
Import-Module .\ConditionalAccess\ConditionalAccessAnalyzer.psm1
```

## Usage

### Quick Start (One-liner to connect)

Copy and paste this one-liner into Azure Cloud Shell to ensure proper connectivity:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement -Force -AllowClobber; Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","DeviceManagementConfiguration.Read.All","DeviceManagementApps.Read.All","IdentityRiskyUser.Read.All"
```

### Basic Usage in Cloud Shell

```powershell
# Import the module (if not already imported)
Import-Module ./ConditionalAccessAnalyzer.psm1

# Connect using the module's built-in function
Connect-CAAnalyzer

# Get a summary of all CA policies
Get-CAPoliciesSummary

# Run a comprehensive assessment
$results = Invoke-CAComplianceCheck

# Export results to HTML (saved in your Cloud Shell storage)
Export-CAComplianceReport -Results $results -Format HTML -Path "~/CAReport.html"

# Download the report from Cloud Shell
# Click on the "..." menu in Cloud Shell, select "Download" and navigate to ~/CAReport.html
```

### Running Specific Checks in Cloud Shell

You can run individual checks to focus on specific aspects:

```powershell
# Check MFA requirements for administrators
Test-AdminMFARequired

# Check device compliance requirements
Test-DeviceComplianceRequired

# Check risk-based policies
Test-RiskBasedPolicies

# Check MDCA and Zero Trust network configuration
Test-ZeroTrustNetwork

# Save individual check results
$adminMfaResults = Test-AdminMFARequired
$adminMfaResults | ConvertTo-Json | Out-File ~/adminMfaResults.json
```

### Creating New Policies

The module includes templates for creating best-practice policies:

```powershell
# Generate a template for a new MFA policy for administrators
New-CABestPracticePolicy -PolicyType AdminMFA

# Generate a template for risk-based policies
New-CABestPracticePolicy -PolicyType RiskBased
```

## Function Reference

| Function | Description |
|----------|-------------|
| `Connect-CAAnalyzer` | Connects to Microsoft Graph with required permissions |
| `Get-CAPoliciesSummary` | Gets a summary of all Conditional Access policies |
| `Test-AdminMFARequired` | Checks if MFA is required for administrators |
| `Test-UserMFARequired` | Checks if MFA is required for regular users |
| `Test-DeviceComplianceRequired` | Checks if device compliance is required |
| `Test-TokenSessionBinding` | Checks if token session binding is configured |
| `Test-RiskBasedPolicies` | Checks if risk-based CA policies are configured |
| `Test-MAMPolicies` | Checks if Mobile Application Management policies exist |
| `Test-ZeroTrustNetwork` | Checks MDCA and Global Secure Access configuration |
| `Invoke-CAComplianceCheck` | Runs a comprehensive assessment of all CA policies |
| `Export-CAComplianceReport` | Exports results to various formats |
| `New-CABestPracticePolicy` | Creates templates for best-practice policies |

## Sample Report

The module generates detailed HTML reports showing your compliance score and specific recommendations:

![Report Details](https://raw.githubusercontent.com/username/ConditionalAccess/main/assets/report-details.png)

### Viewing Reports in Cloud Shell

After generating a report in Cloud Shell:

1. In Cloud Shell, click on the "..." menu in the top-right corner
2. Select "Download"
3. Navigate to the report location (e.g., ~/CAReport.html)
4. Download and open the HTML file locally

You can also output a summary directly in the console:

```powershell
$results = Invoke-CAComplianceCheck
$results.ComplianceScore
$results.Checks.AdminMFA.Recommendation
$results.Checks.UserMFA.Recommendation
```

## Azure Cloud Shell Quick Start

For the fastest experience, copy and paste this all-in-one script into Azure Cloud Shell to immediately analyze your environment:

```powershell
# Run this in Azure Cloud Shell
curl -s https://raw.githubusercontent.com/username/ConditionalAccess/main/QuickStart.ps1 | iex
```

This script will:
1. Install required Microsoft Graph modules
2. Clone the repository
3. Connect to your tenant
4. Run a comprehensive analysis
5. Generate and help you download the report

The full script is available in the repository as [QuickStart.ps1](QuickStart.ps1).

## Contributing

Contributions are welcome! Please check out our [contribution guidelines](CONTRIBUTING.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Special thanks to the Microsoft Identity security community
- Inspired by the Microsoft Zero Trust security model recommendations
