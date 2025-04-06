# Changelog

All notable changes to the Conditional Access Analyzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-06

### Added

- Initial release of the Conditional Access Analyzer module
- Core functionality for assessing Conditional Access policies:
  - `Connect-CAAnalyzer` - Connects to Microsoft Graph with required permissions
  - `Get-CAPoliciesSummary` - Provides a summary of all Conditional Access policies
  - `Test-AdminMFARequired` - Checks MFA requirements for administrators
  - `Test-UserMFARequired` - Checks MFA requirements for regular users
  - `Test-DeviceComplianceRequired` - Evaluates device compliance settings
  - `Test-TokenSessionBinding` - Verifies token session binding configurations
  - `Test-RiskBasedPolicies` - Analyzes sign-in and user risk-based policies
  - `Test-MAMPolicies` - Checks Mobile Application Management policy settings
  - `Test-ZeroTrustNetwork` - Evaluates Zero Trust Network Access components
  - `Invoke-CAComplianceCheck` - Performs a comprehensive assessment
  - `Export-CAComplianceReport` - Exports results to HTML, CSV, or JSON formats
  - `New-CABestPracticePolicy` - Generates templates for best-practice policies
- HTML report generation with compliance scoring
- Support for Azure Cloud Shell
- QuickStart script for rapid deployment and assessment
