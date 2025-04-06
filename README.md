# ConditionalAccessAnalyzer Quick Start for Azure Cloud Shell
# Copy and paste into Azure Cloud Shell to quickly analyze your tenant

# Install required Microsoft Graph modules
```
Write-Host "Installing required Microsoft Graph modules..." -ForegroundColor Cyan
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.DeviceManagement -Force -AllowClobber -ErrorAction SilentlyContinue
```
# Direct import of the module
```
Write-Host "Importing ConditionalAccessAnalyzer module directly from GitHub..." -ForegroundColor Cyan
Import-Module (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccess/refs/heads/main/ConditionalAccessAnalyzer.psm1" -UseBasicParsing).Content
```
# Connect to Microsoft Graph
```
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-CAAnalyzer
```
# Run the compliance check
```
Write-Host "Running comprehensive Conditional Access compliance check..." -ForegroundColor Cyan
$results = Invoke-CAComplianceCheck
```
# Generate HTML report
```
Write-Host "Generating HTML report..." -ForegroundColor Cyan
Export-CAComplianceReport -Results $results -Format HTML -Path "~/CAReport.html"
```
# Display summary of findings
```
Write-Host "`nSUMMARY OF FINDINGS:" -ForegroundColor Green
Write-Host "Compliance Score: $($results.ComplianceScore)%" -ForegroundColor $(if ($results.ComplianceScore -ge 80) { "Green" } elseif ($results.ComplianceScore -ge 60) { "Yellow" } else { "Red" })

Write-Host "`nKey Recommendations:" -ForegroundColor Cyan
if ($results.Checks.AdminMFA.AdminMFARequired -eq $false) {
    Write-Host "- Admin MFA: $($results.Checks.AdminMFA.Recommendation)" -ForegroundColor Red
}
if ($results.Checks.UserMFA.BroadUserMFARequired -eq $false) {
    Write-Host "- User MFA: $($results.Checks.UserMFA.Recommendation)" -ForegroundColor Red
}
if ($results.Checks.DeviceCompliance.BroadDeviceComplianceRequired -eq $false) {
    Write-Host "- Device Compliance: $($results.Checks.DeviceCompliance.Recommendation)" -ForegroundColor Red
}
if ($results.Checks.RiskPolicies.SignInRiskPoliciesConfigured -eq $false) {
    Write-Host "- Risk-Based Access: $($results.Checks.RiskPolicies.Recommendation)" -ForegroundColor Red
}

Write-Host "`nTo view the detailed HTML report:" -ForegroundColor Cyan
Write-Host "1. Click on the '...' menu in the top-right corner of Cloud Shell" -ForegroundColor White
Write-Host "2. Select 'Download'" -ForegroundColor White
Write-Host "3. Navigate to ~/CAReport.html" -ForegroundColor White
Write-Host "4. Download and open the file in your browser" -ForegroundColor White

Write-Host "`nTo get more details in the console:" -ForegroundColor Cyan
Write-Host "PS> `$results.Checks.AdminMFA" -ForegroundColor White
Write-Host "PS> `$results.Checks.UserMFA" -ForegroundColor White
Write-Host "PS> `$results.Checks.RiskPolicies.RiskBasedPolicies" -ForegroundColor White
```
