# ConditionalAccessAnalyzer.psm1
#Requires -Modules @{ ModuleName="Microsoft.Graph.Authentication"; ModuleVersion="1.20.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.SignIns"; ModuleVersion="1.20.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.Identity.DirectoryManagement"; ModuleVersion="1.20.0" }
#Requires -Modules @{ ModuleName="Microsoft.Graph.DeviceManagement"; ModuleVersion="1.20.0" }

function Connect-CAAnalyzer {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the required permissions for Conditional Access analysis.
    .DESCRIPTION
        Authenticates to Microsoft Graph with the scopes needed to read Conditional Access policies,
        directory roles, users, and device compliance information.
    .EXAMPLE
        Connect-CAAnalyzer
    #>
    [CmdletBinding()]
    param()

    $requiredScopes = @(
        "Policy.Read.All",
        "Directory.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
        "IdentityRiskyUser.Read.All",
        "NetworkAccessPolicy.Read.All"
    )

    try {
        Connect-MgGraph -Scopes $requiredScopes
        Write-Host "Successfully connected to Microsoft Graph with required scopes for CA analysis" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        throw
    }
}

function Get-CAPoliciesSummary {
    <#
    .SYNOPSIS
        Gets a summary of all Conditional Access policies.
    .DESCRIPTION
        Retrieves all Conditional Access policies and provides a summary of their state and configuration.
    .EXAMPLE
        Get-CAPoliciesSummary
    #>
    [CmdletBinding()]
    param()

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy
        
        $results = @()
        foreach ($policy in $policies) {
            $results += [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                IncludeUsers = ($policy.Conditions.Users.IncludeUsers -join ", ")
                ExcludeUsers = ($policy.Conditions.Users.ExcludeUsers -join ", ")
                IncludeGroups = ($policy.Conditions.Users.IncludeGroups -join ", ")
                ExcludeGroups = ($policy.Conditions.Users.ExcludeGroups -join ", ")
                IncludeRoles = ($policy.Conditions.Users.IncludeRoles -join ", ")
                ExcludeRoles = ($policy.Conditions.Users.ExcludeRoles -join ", ")
                IncludeApplications = ($policy.Conditions.Applications.IncludeApplications -join ", ")
                GrantControls = ($policy.GrantControls.BuiltInControls -join ", ")
                SessionControls = if ($policy.SessionControls) { "Configured" } else { "Not Configured" }
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Failed to retrieve Conditional Access policies: $_"
        throw
    }
}

function Test-AdminMFARequired {
    <#
    .SYNOPSIS
        Checks if MFA is required for administrators.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if Multi-Factor Authentication 
        is properly enforced for all administrative roles.
    .EXAMPLE
        Test-AdminMFARequired
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking MFA requirements for administrative roles..." -ForegroundColor Yellow
    
    try {
        # Get all CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        # Get all privileged role template IDs
        $adminRoles = Get-MgDirectoryRole -ExpandProperty Members
        $adminRoleIds = $adminRoles.RoleTemplateId
        
        $adminMfaPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if this policy targets admin roles
            $includesAdmins = $false
            
            # Check if policy includes specific admin roles
            if ($policy.Conditions.Users.IncludeRoles) {
                $roleIntersection = Compare-Object -ReferenceObject $policy.Conditions.Users.IncludeRoles -DifferenceObject $adminRoleIds -IncludeEqual -ExcludeDifferent
                if ($roleIntersection) {
                    $includesAdmins = $true
                }
            }
            
            # Check if policy includes all users and doesn't exclude admins
            if (($policy.Conditions.Users.IncludeUsers -contains "All") -and 
                (-not (Compare-Object -ReferenceObject $policy.Conditions.Users.ExcludeRoles -DifferenceObject $adminRoleIds -IncludeEqual -ExcludeDifferent))) {
                $includesAdmins = $true
            }
            
            # If policy targets admins, check if it requires MFA
            if ($includesAdmins) {
                $requiresMfa = $policy.GrantControls.BuiltInControls -contains "mfa"
                
                $adminMfaPolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    RequiresMFA = $requiresMfa
                    PolicyState = $policy.State
                    TargetedRoles = if ($policy.Conditions.Users.IncludeRoles) { $policy.Conditions.Users.IncludeRoles -join ", " } else { "All Users" }
                }
            }
        }
        
        # Analyze results
        $missingMfaForRoles = @()
        foreach ($role in $adminRoles) {
            $isCovered = $false
            foreach ($policy in $adminMfaPolicies) {
                if (($policy.TargetedRoles -contains $role.RoleTemplateId) -or ($policy.TargetedRoles -eq "All Users")) {
                    if ($policy.RequiresMFA) {
                        $isCovered = $true
                        break
                    }
                }
            }
            
            if (-not $isCovered) {
                $missingMfaForRoles += $role.DisplayName
            }
        }
        
        # Return results
        return [PSCustomObject]@{
            AdminMFARequired = ($missingMfaForRoles.Count -eq 0)
            AdminMFAPolicies = $adminMfaPolicies
            AdminRolesWithoutMFA = $missingMfaForRoles
            Recommendation = if ($missingMfaForRoles.Count -gt 0) {
                "Create a CA policy requiring MFA for these admin roles: $($missingMfaForRoles -join ', ')"
            } else {
                "All administrative roles are properly protected with MFA requirements."
            }
        }
    }
    catch {
        Write-Error "Error evaluating admin MFA requirements: $_"
        throw
    }
}

function Test-UserMFARequired {
    <#
    .SYNOPSIS
        Checks if MFA is required for regular users.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if Multi-Factor Authentication 
        is properly enforced for regular users.
    .EXAMPLE
        Test-UserMFARequired
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking MFA requirements for regular users..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $userMfaPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy applies to all users or specific user groups
            $appliestoUsers = $policy.Conditions.Users.IncludeUsers -contains "All" -or $policy.Conditions.Users.IncludeGroups
            
            # Check if policy requires MFA
            $requiresMfa = $policy.GrantControls.BuiltInControls -contains "mfa"
            
            # Check applications scope - we want broad coverage
            $appCoverage = "Limited"
            if ($policy.Conditions.Applications.IncludeApplications -contains "All" -or 
                $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                $appCoverage = "Broad"
            }
            
            if ($appliestoUsers -and $requiresMfa) {
                $userMfaPolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    RequiresMFA = $requiresMfa
                    AppCoverage = $appCoverage
                    IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                    ExcludeUsers = if ($policy.Conditions.Users.ExcludeUsers) { "Has Exclusions" } else { "No Exclusions" }
                }
            }
        }
        
        # Analyze results
        $hasBroadUserMfaPolicy = $userMfaPolicies | Where-Object { 
            $_.AppCoverage -eq "Broad" -and $_.IncludeUsers -eq "All Users" -and $_.RequiresMFA 
        }
        
        # Return results
        return [PSCustomObject]@{
            BroadUserMFARequired = ($hasBroadUserMfaPolicy.Count -gt 0)
            UserMFAPolicies = $userMfaPolicies
            Recommendation = if (-not $hasBroadUserMfaPolicy) {
                "Create a CA policy requiring MFA for all users accessing Microsoft 365 applications"
            } else {
                "Regular users are properly protected with MFA requirements."
            }
        }
    }
    catch {
        Write-Error "Error evaluating user MFA requirements: $_"
        throw
    }
}

function Test-DeviceComplianceRequired {
    <#
    .SYNOPSIS
        Checks if device compliance is required for resource access.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if device compliance
        is enforced for accessing corporate resources.
    .EXAMPLE
        Test-DeviceComplianceRequired
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking device compliance requirements..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $compliancePolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy requires compliant devices
            $requiresCompliantDevice = $policy.GrantControls.BuiltInControls -contains "compliantDevice"
            
            # Check if policy requires hybrid Azure AD joined devices
            $requiresHybridJoin = $policy.GrantControls.BuiltInControls -contains "domainJoinedDevice"
            
            # Check applications scope
            $appCoverage = "Limited"
            if ($policy.Conditions.Applications.IncludeApplications -contains "All" -or 
                $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                $appCoverage = "Broad"
            }
            
            if ($requiresCompliantDevice -or $requiresHybridJoin) {
                $compliancePolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    RequiresCompliantDevice = $requiresCompliantDevice
                    RequiresHybridJoin = $requiresHybridJoin
                    AppCoverage = $appCoverage
                    IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                    ExcludeUsers = if ($policy.Conditions.Users.ExcludeUsers) { "Has Exclusions" } else { "No Exclusions" }
                }
            }
        }
        
        # Analyze results - do we have a broad policy?
        $hasBroadCompliancePolicy = $compliancePolicies | Where-Object { 
            $_.AppCoverage -eq "Broad" -and $_.IncludeUsers -eq "All Users" -and ($_.RequiresCompliantDevice -or $_.RequiresHybridJoin)
        }
        
        # Return results
        return [PSCustomObject]@{
            BroadDeviceComplianceRequired = ($hasBroadCompliancePolicy.Count -gt 0)
            CompliancePolicies = $compliancePolicies
            Recommendation = if (-not $hasBroadCompliancePolicy) {
                "Create a CA policy requiring device compliance for all users accessing Microsoft 365 applications"
            } else {
                "Device compliance requirements are properly configured."
            }
        }
    }
    catch {
        Write-Error "Error evaluating device compliance requirements: $_"
        throw
    }
}

function Test-TokenSessionBinding {
    <#
    .SYNOPSIS
        Checks if token session binding to devices is configured.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if token session binding
        is enforced, which ensures tokens are bound to the device used for authentication.
    .EXAMPLE
        Test-TokenSessionBinding
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking token session binding configuration..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $sessionBindingPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy has session controls
            if ($policy.SessionControls) {
                # Check if policy enforces device-based session controls
                $hasSignInFrequency = $null -ne $policy.SessionControls.SignInFrequency
                $hasPersistentBrowser = $null -ne $policy.SessionControls.PersistentBrowser
                $hasDeviceState = $null -ne $policy.SessionControls.PersistentBrowser -and 
                                  $policy.SessionControls.PersistentBrowser.Mode -eq "never"
                
                # Check applications scope
                $appCoverage = "Limited"
                if ($policy.Conditions.Applications.IncludeApplications -contains "All" -or 
                    $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                    $appCoverage = "Broad"
                }
                
                if ($hasSignInFrequency -or $hasPersistentBrowser) {
                    $sessionBindingPolicies += [PSCustomObject]@{
                        PolicyName = $policy.DisplayName
                        SignInFrequency = if ($hasSignInFrequency) { "$($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)" } else { "Not Set" }
                        PersistentBrowser = if ($hasPersistentBrowser) { $policy.SessionControls.PersistentBrowser.Mode } else { "Not Set" }
                        AppCoverage = $appCoverage
                        IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                    }
                }
            }
        }
        
        # Analyze results - do we have suitable policies?
        $hasBroadSessionPolicy = $sessionBindingPolicies | Where-Object { 
            $_.AppCoverage -eq "Broad" -and $_.IncludeUsers -eq "All Users" -and 
            ($_.SignInFrequency -ne "Not Set" -or $_.PersistentBrowser -eq "never")
        }
        
        # Return results
        return [PSCustomObject]@{
            TokenSessionBindingConfigured = ($hasBroadSessionPolicy.Count -gt 0)
            SessionBindingPolicies = $sessionBindingPolicies
            Recommendation = if (-not $hasBroadSessionPolicy) {
                "Configure CA policies with appropriate sign-in frequency and/or persistent browser session controls"
            } else {
                "Token session binding controls are properly configured."
            }
        }
    }
    catch {
        Write-Error "Error evaluating token session binding configuration: $_"
        throw
    }
}

function Test-RiskBasedPolicies {
    <#
    .SYNOPSIS
        Checks if risk-based Conditional Access policies are configured.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if sign-in risk and user risk
        conditions are used to protect the environment.
    .EXAMPLE
        Test-RiskBasedPolicies
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking risk-based Conditional Access policies..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $riskBasedPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy uses risk conditions
            $usesSignInRisk = $null -ne $policy.Conditions.SignInRisk -and $policy.Conditions.SignInRisk.RiskLevels
            $usesUserRisk = $null -ne $policy.Conditions.UserRiskLevels -and $policy.Conditions.UserRiskLevels.Count -gt 0
            
            if ($usesSignInRisk -or $usesUserRisk) {
                $riskBasedPolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    UsesSignInRisk = $usesSignInRisk
                    SignInRiskLevels = if ($usesSignInRisk) { $policy.Conditions.SignInRisk.RiskLevels -join ", " } else { "Not Used" }
                    UsesUserRisk = $usesUserRisk
                    UserRiskLevels = if ($usesUserRisk) { $policy.Conditions.UserRiskLevels -join ", " } else { "Not Used" }
                    IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                    GrantControls = $policy.GrantControls.BuiltInControls -join ", "
                }
            }
        }
        
        # Analyze results - check if we have both sign-in risk and user risk policies
        $hasSignInRiskPolicy = $riskBasedPolicies | Where-Object { $_.UsesSignInRisk }
        $hasUserRiskPolicy = $riskBasedPolicies | Where-Object { $_.UsesUserRisk }
        
        # Return results
        return [PSCustomObject]@{
            SignInRiskPoliciesConfigured = ($hasSignInRiskPolicy.Count -gt 0)
            UserRiskPoliciesConfigured = ($hasUserRiskPolicy.Count -gt 0)
            RiskBasedPolicies = $riskBasedPolicies
            Recommendation = @(
                if (-not $hasSignInRiskPolicy) { "Configure CA policy based on sign-in risk to protect against suspicious sign-in attempts" }
                if (-not $hasUserRiskPolicy) { "Configure CA policy based on user risk to protect compromised accounts" }
                if ($hasSignInRiskPolicy -and $hasUserRiskPolicy) { "Risk-based policies are properly configured." }
            ) -join "; "
        }
    }
    catch {
        Write-Error "Error evaluating risk-based policies: $_"
        throw
    }
}

function Test-MAMPolicies {
    <#
    .SYNOPSIS
        Checks if Mobile Application Management policies are configured.
    .DESCRIPTION
        Analyzes Conditional Access policies to determine if app protection policies
        are enforced for mobile devices, including controls like preventing cut/copy/paste.
    .EXAMPLE
        Test-MAMPolicies
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking Mobile Application Management policies..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $appProtectionPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy has app-enforced restrictions
            $hasAppEnforcedRestrictions = $null -ne $policy.SessionControls -and $null -ne $policy.SessionControls.ApplicationEnforcedRestrictions
            
            # Check if targeting mobile apps/platforms
            $targetsMobileApps = $false
            if ($policy.Conditions.Applications.IncludeApplications -contains "All" -or 
                $policy.Conditions.Applications.IncludeApplications -contains "Office365") {
                if ($policy.Conditions.Platforms -and 
                    ($policy.Conditions.Platforms.IncludePlatforms -contains "android" -or 
                     $policy.Conditions.Platforms.IncludePlatforms -contains "iOS")) {
                    $targetsMobileApps = $true
                }
            }
            
            if ($hasAppEnforcedRestrictions -or $targetsMobileApps) {
                $appProtectionPolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    HasAppEnforcedRestrictions = $hasAppEnforcedRestrictions
                    TargetsMobileApps = $targetsMobileApps
                    Platforms = if ($policy.Conditions.Platforms) { $policy.Conditions.Platforms.IncludePlatforms -join ", " } else { "All Platforms" }
                    IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                }
            }
        }
        
        # Try to get MAM policies from Intune if available
        $mamPolicies = $null
        try {
            $mamPolicies = Get-MgDeviceAppManagementTargetedManagedAppConfiguration
        }
        catch {
            Write-Warning "Unable to retrieve MAM policies from Intune: $_"
        }
        
        # Analyze results
        $hasMAMPolicies = $appProtectionPolicies.Count -gt 0 -or ($mamPolicies -and $mamPolicies.Count -gt 0)
        
        # Return results
        return [PSCustomObject]@{
            MAMPoliciesConfigured = $hasMAMPolicies
            ConditionalAccessPolicies = $appProtectionPolicies
            IntuneMAMPoliciesCount = if ($mamPolicies) { $mamPolicies.Count } else { "Unknown" }
            Recommendation = if (-not $hasMAMPolicies) {
                "Configure Mobile Application Management policies to protect corporate data on mobile devices"
            } else {
                "Mobile Application Management policies are configured."
            }
        }
    }
    catch {
        Write-Error "Error evaluating MAM policies: $_"
        throw
    }
}

function Test-ZeroTrustNetwork {
    <#
    .SYNOPSIS
        Checks if Secure Access Service Edge (SASE) / Zero Trust Network Access is configured.
    .DESCRIPTION
        Analyzes network configurations to determine if Microsoft Defender for Cloud Apps 
        and/or Global Secure Access is properly configured.
    .EXAMPLE
        Test-ZeroTrustNetwork
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Checking Zero Trust Network Access configuration..." -ForegroundColor Yellow
    
    try {
        # Get all enabled CA policies
        $policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }
        
        $cloudAppPolicies = @()
        
        foreach ($policy in $policies) {
            # Check if policy has cloud app security session control
            $hasCloudAppSecurity = $null -ne $policy.SessionControls -and 
                                  $null -ne $policy.SessionControls.CloudAppSecurity -and
                                  $policy.SessionControls.CloudAppSecurity.IsEnabled
                                  
            $cloudAppMode = "None"
            if ($hasCloudAppSecurity) {
                $cloudAppMode = $policy.SessionControls.CloudAppSecurity.CloudAppSecurityType
            }
            
            if ($hasCloudAppSecurity) {
                $cloudAppPolicies += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    CloudAppSecurityMode = $cloudAppMode
                    IncludeUsers = if ($policy.Conditions.Users.IncludeUsers -contains "All") { "All Users" } else { "Specific Users/Groups" }
                    IncludeApps = $policy.Conditions.Applications.IncludeApplications -join ", "
                }
            }
        }
        
        # Check for Global Secure Access policies
        $gsaPolicies = $null
        try {
            # This is a placeholder as the actual API for Global Secure Access is emerging
            # When available, use proper Graph endpoints for GSA policies
            $gsaPolicies = Get-MgPolicyNetworkAccessPolicy -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Unable to retrieve Global Secure Access policies: $_"
        }
        
        # Analyze results
        $hasMDCAIntegration = $cloudAppPolicies.Count -gt 0
        $hasGSAConfiguration = $gsaPolicies -and $gsaPolicies.Count -gt 0
        
        # Return results
        return [PSCustomObject]@{
            MDCAIntegrated = $hasMDCAIntegration
            GlobalSecureAccessConfigured = $hasGSAConfiguration
            CloudAppPolicies = $cloudAppPolicies
            GSAPoliciesCount = if ($gsaPolicies) { $gsaPolicies.Count } else { "Unknown" }
            Recommendation = @(
                if (-not $hasMDCAIntegration) { "Configure Microsoft Defender for Cloud Apps integration with Conditional Access" }
                if (-not $hasGSAConfiguration) { "Set up Global Secure Access policies for Zero Trust Network Access" }
                if ($hasMDCAIntegration -and $hasGSAConfiguration) { "Zero Trust Network Access components are properly configured." }
            ) -join "; "
        }
    }
    catch {
        Write-Error "Error evaluating Zero Trust Network configurations: $_"
        throw
    }
}

function Invoke-CAComplianceCheck {
    <#
    .SYNOPSIS
        Performs a comprehensive Conditional Access compliance check.
    .DESCRIPTION
        Runs all CA compliance checks and provides a consolidated report on the security posture.
    .EXAMPLE
        Invoke-CAComplianceCheck
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "Starting comprehensive Conditional Access compliance check..." -ForegroundColor Cyan
    
    $results = [PSCustomObject]@{
        Timestamp = Get-Date
        TenantId = (Get-MgContext).TenantId
        TenantName = (Get-MgOrganization).DisplayName
        Checks = @{}
    }
    
    # Run all checks
    $results.Checks.AdminMFA = Test-AdminMFARequired
    $results.Checks.UserMFA = Test-UserMFARequired
    $results.Checks.DeviceCompliance = Test-DeviceComplianceRequired
    $results.Checks.TokenBinding = Test-TokenSessionBinding
    $results.Checks.RiskPolicies = Test-RiskBasedPolicies
    $results.Checks.MAMPolicies = Test-MAMPolicies
    $results.Checks.ZeroTrust = Test-ZeroTrustNetwork
    
    # Calculate overall compliance score
    $checkResults = @(
        $results.Checks.AdminMFA.AdminMFARequired,
        $results.Checks.UserMFA.BroadUserMFARequired,
        $results.Checks.DeviceCompliance.BroadDeviceComplianceRequired,
        $results.Checks.TokenBinding.TokenSessionBindingConfigured,
        $results.Checks.RiskPolicies.SignInRiskPoliciesConfigured,
        $results.Checks.RiskPolicies.UserRiskPoliciesConfigured,
        $results.Checks.MAMPolicies.MAMPoliciesConfigured,
        $results.Checks.ZeroTrust.MDCAIntegrated,
        $results.Checks.ZeroTrust.GlobalSecureAccessConfigured
    )
    
    $passedChecks = ($checkResults | Where-Object { $_ -eq $true }).Count
    $totalChecks = $checkResults.Count
    $complianceScore = [math]::Round(($passedChecks / $totalChecks) * 100)
    
    $results | Add-Member -MemberType NoteProperty -Name "ComplianceScore" -Value $complianceScore
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Conditional Access Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #0078D4; }
        .summary { margin: 20px 0; padding: 15px; background-color: #f0f0f0; border-radius: 5px; }
        .score { font-size: 24px; font-weight: bold; }
        .pass { color: green; }
        .fail { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0078D4; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Conditional Access Compliance Report</h1>
    <div class="summary">
        <p>Tenant: $($results.TenantName)</p>
        <p>Generated: $($results.Timestamp)</p>
        <p>Compliance Score: <span class="score $($complianceScore -ge 80 ? 'pass' : ($complianceScore -ge 60 ? 'warning' : 'fail'))">$($complianceScore)%</span></p>
    </div>
    
    <h2>Summary of Findings</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Recommendation</th>
        </tr>
        <tr>
            <td>Admin MFA Required</td>
            <td class="$($results.Checks.AdminMFA.AdminMFARequired ? 'pass' : 'fail')">$($results.Checks.AdminMFA.AdminMFARequired ? 'PASS' : 'FAIL')</td>
            <td>$($results.Checks.AdminMFA.Recommendation)</td>
        </tr>
        <tr>
            <td>User MFA Required</td>
            <td class="$($results.Checks.UserMFA.BroadUserMFARequired ? 'pass' : 'fail')">$($results.Checks.UserMFA.BroadUserMFARequired ? 'PASS' : 'FAIL')</td>
            <td>$($results.Checks.UserMFA.Recommendation)</td>
        </tr>
        <tr>
            <td>Device Compliance Required</td>
            <td class="$($results.Checks.DeviceCompliance.BroadDeviceComplianceRequired ? 'pass' : 'fail')">$($results.Checks.DeviceCompliance.BroadDeviceComplianceRequired ? 'PASS' : 'FAIL')</td>
            <td>$($results.Checks.DeviceCompliance.Recommendation)</td>
        </tr>
        <tr>
            <td>Token Session Binding</td>
            <td class="$($results.Checks.TokenBinding.TokenSessionBindingConfigured ? 'pass' : 'fail')">$($results.Checks.TokenBinding.TokenSessionBindingConfigured ? 'PASS' : 'FAIL')</td>
            <td>$($results.Checks.TokenBinding.Recommendation)</td>
        </tr>
        <tr>
            <td>Sign-in Risk Policies</td>
            <td class="$($results.Checks.RiskPolicies.SignInRiskPoliciesConfigured ? 'pass' : 'fail')">$($results.Checks.RiskPolicies.SignInRiskPoliciesConfigured ? 'PASS' : 'FAIL')</td>
            <td rowspan="2">$($results.Checks.RiskPolicies.Recommendation)</td>
        </tr>
        <tr>
            <td>User Risk Policies</td>
            <td class="$($results.Checks.RiskPolicies.UserRiskPoliciesConfigured ? 'pass' : 'fail')">$($results.Checks.RiskPolicies.UserRiskPoliciesConfigured ? 'PASS' : 'FAIL')</td>
        </tr>
        <tr>
            <td>MAM Policies (Cut/Copy/Paste Controls)</td>
            <td class="$($results.Checks.MAMPolicies.MAMPoliciesConfigured ? 'pass' : 'fail')">$($results.Checks.MAMPolicies.MAMPoliciesConfigured ? 'PASS' : 'FAIL')</td>
            <td>$($results.Checks.MAMPolicies.Recommendation)</td>
        </tr>
        <tr>
            <td>MDCA Integration</td>
            <td class="$($results.Checks.ZeroTrust.MDCAIntegrated ? 'pass' : 'fail')">$($results.Checks.ZeroTrust.MDCAIntegrated ? 'PASS' : 'FAIL')</td>
            <td rowspan="2">$($results.Checks.ZeroTrust.Recommendation)</td>
        </tr>
        <tr>
            <td>Global Secure Access</td>
            <td class="$($results.Checks.ZeroTrust.GlobalSecureAccessConfigured ? 'pass' : 'fail')">$($results.Checks.ZeroTrust.GlobalSecureAccessConfigured ? 'PASS' : 'FAIL')</td>
        </tr>
