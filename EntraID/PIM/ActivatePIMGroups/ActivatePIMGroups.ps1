<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	17-12-2025 19:37
	 Created by:   	Michael Morten Sonne
	 Organization: 	Sonne´s Cloud
	 Blog:          https://blog.sonnes.cloud
	 Filename:     	ActivatePIMGroups.ps1
	===========================================================================

    .SYNOPSIS
    Improved PIM Group Activation Script with error handling and modularity

	.DESCRIPTION
		PowerShell script to connect to Microsoft Graph and activates PIM group membership
        with proper error handling, logging, and configuration management.

    .REQUREMENT
        - Microsoft.Graph.Authentication PowerShell module
        - Appropriate API permissions and Entra ID roles for PIM activation   

    .PARAMETER GroupDisplayName
        Display name of the RBAC group to activate membership for (default: 'RBAC_Global_Reader_No_approval') or similar.
        
        Help:
        - Ensure the group is PIM-enabled in Entra ID Privileged Identity Management (PIM for Groups)

    .PARAMETER Duration
        Duration for the activation (default: PT1H for 1 hour)

        Help:
        - ISO 8601 duration format (e.g., PT1H for 1 hour, PT30M for 30 minutes)

    .PARAMETER Justification
        Justification for the activation request - etc. 'Activate PIM group membership via PowerShell' or similar.
        
	.EXAMPLE
        .\ActivatePIMGroups.ps1 -GroupDisplayName 'RBAC_Global_Reader_No_approval' -Duration 'PT1H' -Justification 'Activate PIM group membership via PowerShell'

    .CHANGELOG
        17-12-2025 - Michael Morten Sonne - Initial release
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$GroupDisplayName = 'RBAC_Global_Reader_No_approval',
    
    [Parameter(Mandatory = $false)]
    [string]$Duration = 'PT1H',
    
    [Parameter(Mandatory = $false)]
    [string]$Justification = 'Activate PIM group membership via PowerShell'
)

# Required modules (minimal set for authentication)
$RequiredModules = @(
    'Microsoft.Graph.Authentication'
)

# Graph API Configuration
$GraphBaseUrl = 'https://graph.microsoft.com'
$GraphBetaUrl = 'https://graph.microsoft.com/beta'

# Configuration
$RequiredScopes = @(
    'Application.Read.All',
    'Group.Read.All',
    'User.Read.All',
    'Directory.AccessAsUser.All',
    'TeamSettings.Read.All',
    'RoleEligibilitySchedule.Read.Directory',
    'RoleAssignmentSchedule.ReadWrite.Directory',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup'
)

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
    }
}

function Install-RequiredModules {
    param([array]$ModuleNames)
    
    Write-LogMessage "Checking required PowerShell modules..." -Level Info
    
    foreach ($moduleName in $ModuleNames) {
        try {
            $module = Get-Module -Name $moduleName -ListAvailable
            if ($null -eq $module) {
                Write-LogMessage "Installing module: $moduleName" -Level Warning
                Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
                Write-LogMessage "Successfully installed module: $moduleName" -Level Info
            } else {
                Write-LogMessage "Module already available: $moduleName" -Level Info
            }
            
            # Import the module
            Import-Module $moduleName -Force
        }
        catch {
            Write-LogMessage "Error with module $moduleName : $($_.Exception.Message)" -Level Error
            throw "Failed to install or import module: $moduleName"
        }
    }
}

function Invoke-GraphApi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        [string]$Method = 'GET',
        [Parameter(Mandatory = $false)]
        [object]$Body = $null,
        [Parameter(Mandatory = $false)]
        [switch]$UseBeta
    )
    
    try {
        # Remove the base URL if present and construct the relative URI
        $relativeUri = $Uri
        if ($Uri.StartsWith('http')) {
            $baseUrl = if ($UseBeta) { $GraphBetaUrl } else { $GraphBaseUrl }
            $relativeUri = $Uri.Replace($baseUrl, "").TrimStart('/')
        } else {
            $relativeUri = $Uri.TrimStart('/')
        }
        
        # Add version prefix if not present
        if (-not $relativeUri.StartsWith('v1.0/') -and -not $relativeUri.StartsWith('beta/')) {
            $version = if ($UseBeta) { 'beta' } else { 'v1.0' }
            $relativeUri = "$version/$relativeUri"
        }
        
        Write-LogMessage "Making Graph API call: $Method $relativeUri" -Level Info
        
        # Use Invoke-MgGraphRequest which handles authentication automatically
        $requestParams = @{
            Uri = $relativeUri
            Method = $Method
        }
        
        if ($Body -and ($Method -eq 'POST' -or $Method -eq 'PATCH' -or $Method -eq 'PUT')) {
            $requestParams.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-MgGraphRequest @requestParams
        return $response
    }
    catch {
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        $errorMessage = $_.Exception.Message
        
        # Try to extract more detailed error information
        if ($_.Exception.Response) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorDetails.error.message) {
                    $errorMessage = $errorDetails.error.message
                }
            }
            catch {
                # Ignore if we can't parse error details
            }
        }
        
        Write-LogMessage "Graph API error ($statusCode): $errorMessage" -Level Error
        throw "Graph API call failed: $errorMessage"
    }
}

function Connect-ToMicrosoftGraph {
    try {
        Write-LogMessage "Connecting to Microsoft Graph..." -Level Info
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
        
        $context = Get-MgContext
        if ($null -eq $context) {
            throw "Failed to establish Graph connection"
        }
        
        # Get access token for REST API calls
        Write-LogMessage "Setting up authentication for REST API calls..." -Level Info
        
        # Instead of extracting the token manually, we'll use Invoke-MgGraphRequest
        # which handles authentication automatically
        $script:UseGraphRequest = $true
        
        # Test the connection with a simple call
        try {
            $testResponse = Invoke-MgGraphRequest -Uri "v1.0/me" -Method GET
            Write-LogMessage "Successfully verified Graph API access" -Level Info
        }
        catch {
            throw "Failed to verify Graph API access: $($_.Exception.Message)"
        }
        
        Write-LogMessage "Successfully connected to Microsoft Graph with REST API access" -Level Info
        return $context
    }
    catch {
        Write-LogMessage "Error connecting to Microsoft Graph: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-CurrentUserInfo {
    param([object]$Context)
    
    try {
        Write-LogMessage "Getting current user information via REST API..." -Level Info
        
        # Use REST API to get current user
        $user = Invoke-GraphApi -Uri "/v1.0/me" -Method GET
        
        if ($null -eq $user -or [string]::IsNullOrEmpty($user.id)) {
            throw "Failed to retrieve current user information"
        }
        
        Write-LogMessage "Current user: $($user.displayName) ($($user.id))" -Level Info
        return $user
    }
    catch {
        Write-LogMessage "Error getting current user: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-RBACGroupInfo {
    param([string]$DisplayName)
    
    try {
        Write-LogMessage "Finding RBAC group: $DisplayName via REST API..." -Level Info
        
        # Use REST API to search for group
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode("displayName eq '$DisplayName'")
        $response = Invoke-GraphApi -Uri "/v1.0/groups?`$filter=$encodedFilter" -Method GET
        
        if ($null -eq $response.value -or $response.value.Count -eq 0) {
            throw "Group '$DisplayName' not found"
        }
        
        $group = $response.value[0]
        
        Write-LogMessage "Found group: $($group.displayName) ($($group.id))" -Level Info
        return $group
    }
    catch {
        Write-LogMessage "Error finding group: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-EligibleAssignment {
    param(
        [string]$UserId,
        [string]$GroupId
    )
    
    try {
        Write-LogMessage "Checking eligible assignments for user in group via REST API..." -Level Info
        
        # Try the main PIM endpoint first
        try {
            $encodedFilter = [System.Web.HttpUtility]::UrlEncode("principalId eq '$UserId' and groupId eq '$GroupId'")
            $response = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=$encodedFilter" -Method GET -UseBeta
            
            if ($null -ne $response.value -and $response.value.Count -gt 0) {
                $eligibleAssignments = $response.value
            } else {
                throw "No eligible assignments found using main endpoint"
            }
        }
        catch {
            Write-LogMessage "Main PIM endpoint failed (403/Forbidden usually means no eligible assignments): $($_.Exception.Message)" -Level Warning
            
            # Try alternative approach - get all eligibility schedules for the user
            Write-LogMessage "Trying alternative approach to get user's eligible assignments..." -Level Info
            try {
                $userFilter = [System.Web.HttpUtility]::UrlEncode("principalId eq '$UserId'")
                $allUserAssignments = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=$userFilter" -Method GET -UseBeta
                
                if ($null -eq $allUserAssignments.value -or $allUserAssignments.value.Count -eq 0) {
                    throw "No PIM eligible assignments found for user. User may not have any PIM-eligible group memberships."
                }
                
                # Filter for the specific group
                $eligibleAssignments = $allUserAssignments.value | Where-Object { $_.groupId -eq $GroupId }
                
                if ($null -eq $eligibleAssignments -or $eligibleAssignments.Count -eq 0) {
                    throw "User has PIM eligible assignments, but not for the group '$GroupId'. Available groups: $($allUserAssignments.value.groupId -join ', ')"
                }
            }
            catch {
                Write-LogMessage "Alternative approach also failed: $($_.Exception.Message)" -Level Error
                
                # Try to get available PIM groups to provide better guidance
                try {
                    Write-LogMessage "Attempting to list available PIM-enabled groups for troubleshooting..." -Level Info
                    $pimGroups = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$select=groupId&`$top=10" -Method GET -UseBeta
                    
                    if ($pimGroups.value -and $pimGroups.value.Count -gt 0) {
                        $uniqueGroupIds = $pimGroups.value.groupId | Sort-Object -Unique
                        Write-LogMessage "Found PIM-enabled groups: $($uniqueGroupIds -join ', ')" -Level Info
                        throw "User may not have eligible assignments for group '$GroupId'. Check if the group is PIM-enabled and user has eligible role."
                    } else {
                        throw "No PIM groups found. This may indicate insufficient permissions or no PIM configuration."
                    }
                }
                catch {
                    # Provide comprehensive error message
                    $errorMsg = @"
No eligible PIM assignments found. This could be due to:
1. User doesn't have eligible assignments for group '$GroupId'
2. Group is not PIM-enabled
3. Insufficient permissions (need PrivilegedAccess.Read.AzureADGroup scope)
4. User needs 'Privileged Role Administrator' or 'Global Administrator' role
5. PIM license not assigned

Please check:
- User has eligible assignments in Azure AD > Privileged Identity Management
- Group '$GroupId' is configured for PIM
- Required scopes and permissions are granted
"@
                    throw $errorMsg
                }
            }
        }
        
        # Look for owner assignment first, then member
        $ownerAssignment = $eligibleAssignments | Where-Object { $_.accessId -eq "owner" }
        $memberAssignment = $eligibleAssignments | Where-Object { $_.accessId -eq "member" }
        
        $assignment = if ($ownerAssignment) { $ownerAssignment } else { $memberAssignment }
        
        if ($null -eq $assignment) {
            throw "No valid eligible assignments found. Available access types: $($eligibleAssignments.accessId -join ', ')"
        }
        
        Write-LogMessage "Found eligible assignment: $($assignment.accessId) role" -Level Info
        return $assignment
    }
    catch {
        Write-LogMessage "Error checking eligible assignments: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Request-GroupActivation {
    param(
        [object]$EligibleAssignment,
        [string]$Duration,
        [string]$Justification
    )
    
    try {
        Write-LogMessage "Creating activation request via REST API..." -Level Info
        
        # Format the schedule info properly - ensure proper ISO 8601 format
        $startDateTime = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
        
        $scheduleInfo = @{
            startDateTime = $startDateTime
            expiration    = @{
                type     = "afterDuration"
                duration = $Duration
            }
        }
        
        $requestBody = @{
            accessId      = $EligibleAssignment.accessId
            principalId   = $EligibleAssignment.principalId
            groupId       = $EligibleAssignment.groupId
            action        = "selfActivate"
            scheduleInfo  = $scheduleInfo
            justification = $Justification
        }
        
        Write-LogMessage "Request body: $($requestBody | ConvertTo-Json -Depth 5)" -Level Info
        
        # Use REST API to create activation request
        try {
            $response = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" -Method POST -Body $requestBody -UseBeta
            
            Write-LogMessage "Activation request created successfully. Request ID: $($response.id)" -Level Info
            Write-LogMessage "Status: $($response.status)" -Level Info
            
            return $response
        }
        catch {
            $errorMessage = $_.Exception.Message
            
            # Check for specific 403 errors and provide guidance
            if ($errorMessage -like "*403*" -or $errorMessage -like "*Forbidden*") {
                $guidanceMsg = @"
403 Forbidden error when creating PIM activation request. This typically indicates:

1. **Missing API Permissions**: Ensure the application has these scopes:
   - PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
   - RoleAssignmentSchedule.ReadWrite.Directory

2. **Missing Azure AD Roles**: User needs one of these roles:
   - Privileged Role Administrator
   - Global Administrator
   - Or be assigned as eligible for the target group

3. **PIM Policy Restrictions**: Check if the group has:
   - Approval requirements enabled
   - MFA requirements
   - Specific activation time windows
   - Maximum activation duration limits

4. **Consent Required**: Administrator consent might be needed for the new scopes.

To troubleshoot:
- Check Azure AD > Privileged Identity Management > Groups > Settings for this group
- Verify user has self-activation permissions for this role
- Check if approval workflow is enabled (which would require different process)

Current request details:
- Group: $($EligibleAssignment.groupId)
- Access: $($EligibleAssignment.accessId)
- Principal: $($EligibleAssignment.principalId)
- Action: selfActivate
- Duration: $Duration
"@
                Write-LogMessage $guidanceMsg -Level Error
                throw $guidanceMsg
            } else {
                throw $errorMessage
            }
        }
    }
    catch {
        Write-LogMessage "Error creating activation request: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Wait-ForActivation {
    param(
        [object]$ActivationRequest,
        [int]$TimeoutMinutes = 10,
        [int]$PollIntervalSeconds = 10
    )
    
    try {
        Write-LogMessage "Monitoring activation status..." -Level Info
        Write-LogMessage "Request ID: $($ActivationRequest.id)" -Level Info
        Write-LogMessage "Initial Status: $($ActivationRequest.status)" -Level Info
        
        $timeout = [DateTime]::Now.AddMinutes($TimeoutMinutes)
        $currentStatus = $ActivationRequest.status
        
        while ([DateTime]::Now -lt $timeout) {
            if ($currentStatus -eq "Activated" -or $currentStatus -eq "Provisioned") {
                Write-LogMessage "✅ Activation completed successfully! Status: $currentStatus" -Level Info
                return $currentStatus
            }
            
            if ($currentStatus -eq "Failed" -or $currentStatus -eq "Denied" -or $currentStatus -eq "Canceled") {
                Write-LogMessage "❌ Activation failed with status: $currentStatus" -Level Error
                throw "Activation request failed with status: $currentStatus"
            }
            
            if ($currentStatus -eq "PendingProvisioning" -or $currentStatus -eq "PendingApproval") {
                Write-LogMessage "⏳ Status: $currentStatus - waiting..." -Level Info
                Start-Sleep -Seconds $PollIntervalSeconds
                
                # Check the current status
                try {
                    $statusResponse = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests/$($ActivationRequest.id)" -Method GET -UseBeta
                    $currentStatus = $statusResponse.status
                    
                    Write-LogMessage "Status check: $currentStatus" -Level Info
                }
                catch {
                    Write-LogMessage "Error checking activation status: $($_.Exception.Message)" -Level Warning
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            } else {
                # Unknown status, still wait and check
                Write-LogMessage "⚠️  Unknown status: $currentStatus - continuing to monitor..." -Level Warning
                Start-Sleep -Seconds $PollIntervalSeconds
            }
        }
        
        # Timeout reached
        Write-LogMessage "⏰ Timeout reached after $TimeoutMinutes minutes. Final status: $currentStatus" -Level Warning
        
        if ($currentStatus -eq "PendingApproval") {
            Write-LogMessage "💡 The request may require manual approval. Check Azure AD PIM portal for pending approvals." -Level Info
        }
        
        return $currentStatus
    }
    catch {
        Write-LogMessage "Error monitoring activation: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Main execution
try {
    Write-LogMessage "Starting PIM Group Activation Process" -Level Info
    Write-LogMessage "Target Group: $GroupDisplayName" -Level Info
    Write-LogMessage "Duration: $Duration" -Level Info
    Write-LogMessage "Justification: $Justification" -Level Info
    
    # Step 0: Install and import required modules
    Install-RequiredModules -ModuleNames $RequiredModules
    
    # Step 1: Connect to Microsoft Graph
    $context = Connect-ToMicrosoftGraph
    
    # Step 2: Get current user information
    $currentUser = Get-CurrentUserInfo -Context $context
    
    # Step 3: Find the RBAC group
    $rbacGroup = Get-RBACGroupInfo -DisplayName $GroupDisplayName
    
    # Step 4: Check for eligible assignments
    $eligibleAssignment = Get-EligibleAssignment -UserId $currentUser.id -GroupId $rbacGroup.id
    
    # Step 5: Request activation
    $activationRequest = Request-GroupActivation -EligibleAssignment $eligibleAssignment -Duration $Duration -Justification $Justification
    
    Write-LogMessage "PIM Group Activation request submitted successfully!" -Level Info
    
    # Step 6: Monitor activation status
    Write-LogMessage "Starting activation monitoring..." -Level Info
    $finalStatus = Wait-ForActivation -ActivationRequest $activationRequest -TimeoutMinutes 10 -PollIntervalSeconds 10
    
    # Output summary with enhanced formatting
    Write-Host ""
    
    # Calculate dynamic width based on content length
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $statusIcon = if ($finalStatus -eq 'Activated' -or $finalStatus -eq 'Provisioned') { '✅' } else { '⚠️' }
    
    $contentItems = @(
        "👤 User        : $($currentUser.displayName)",
        "🔐 Group       : $($rbacGroup.displayName)", 
        "🎭 Role        : $($eligibleAssignment.accessId)",
        "📋 Request ID  : $($activationRequest.id)",
        "$statusIcon Status      : $finalStatus",
        "⏱️ Duration    : $Duration",
        "🕒 Completed   : $timestamp"
    )
    
    # Find the longest content line and add padding
    $maxContentLength = ($contentItems | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $boxWidth = [Math]::Max(82, $maxContentLength + 6)  # Minimum 82 characters, or content + padding
    
    # Create dynamic borders
    $topBorder = "╔" + ("═" * ($boxWidth - 2)) + "╗"
    $middleBorder = "╠" + ("═" * ($boxWidth - 2)) + "╣" 
    $bottomBorder = "╚" + ("═" * ($boxWidth - 2)) + "╝"
    
    # Calculate padding for centered title
    $title = "🎯 PIM ACTIVATION SUMMARY"
    $titlePadding = [Math]::Max(0, ($boxWidth - 2 - $title.Length) / 2)
    $titleLine = "║" + (" " * [Math]::Floor($titlePadding)) + $title + (" " * [Math]::Ceiling($titlePadding)) + "║"
    
    # Display header
    Write-Host $topBorder -ForegroundColor Cyan
    Write-Host $titleLine -ForegroundColor Cyan  
    Write-Host $middleBorder -ForegroundColor Cyan
    
    # Status color for status line
    $statusColor = if ($finalStatus -eq 'Activated' -or $finalStatus -eq 'Provisioned') { 'Green' } else { 'Yellow' }
    
    # Display content lines with proper padding
    $userLine = "║ " + "👤 User        : ".PadRight(17) + "$($currentUser.displayName)"
    $userLinePadded = $userLine + (" " * ($boxWidth - $userLine.Length - 1)) + "║"
    Write-Host $userLinePadded -ForegroundColor Cyan
    
    $groupLine = "║ " + "🔐 Group       : ".PadRight(17) + "$($rbacGroup.displayName)"
    $groupLinePadded = $groupLine + (" " * ($boxWidth - $groupLine.Length - 1)) + "║"
    Write-Host $groupLinePadded -ForegroundColor Cyan
    
    $roleLine = "║ " + "🎭 Role        : ".PadRight(17) + "$($eligibleAssignment.accessId)"
    $roleLinePadded = $roleLine + (" " * ($boxWidth - $roleLine.Length - 1)) + "║"
    Write-Host $roleLinePadded -ForegroundColor Cyan
    
    $requestLine = "║ " + "📋 Request ID  : ".PadRight(17) + "$($activationRequest.id)"
    $requestLinePadded = $requestLine + (" " * ($boxWidth - $requestLine.Length - 1)) + "║"
    Write-Host $requestLinePadded -ForegroundColor Cyan
    
    # Status line with color
    $statusPrefix = "║ " + "$statusIcon Status      : ".PadRight(17)
    $statusLine = $statusPrefix + $finalStatus
    $paddingNeeded = $boxWidth - $statusLine.Length - 1
    Write-Host $statusPrefix -ForegroundColor Cyan -NoNewline
    Write-Host $finalStatus -ForegroundColor $statusColor -NoNewline
    Write-Host (" " * $paddingNeeded + "║") -ForegroundColor Cyan
    
    $durationLine = "║ " + "⏱️ Duration    : ".PadRight(17) + "$Duration"
    $durationLinePadded = $durationLine + (" " * ($boxWidth - $durationLine.Length - 1)) + "║"
    Write-Host $durationLinePadded -ForegroundColor Cyan
    
    $completedLine = "║ " + "🕒 Completed   : ".PadRight(17) + "$timestamp"
    $completedLinePadded = $completedLine + (" " * ($boxWidth - $completedLine.Length - 1)) + "║"
    Write-Host $completedLinePadded -ForegroundColor Cyan
    
    Write-Host $bottomBorder -ForegroundColor Cyan
    
    # Additional status message
    if ($finalStatus -eq 'Activated' -or $finalStatus -eq 'Provisioned') {
        Write-Host ""
        Write-Host "🎉 " -ForegroundColor Green -NoNewline
        Write-Host "Activation successful! You now have elevated permissions for the specified duration." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "⚠️ " -ForegroundColor Yellow -NoNewline  
        Write-Host "Activation may still be in progress. Please check the Azure portal for current status." -ForegroundColor Yellow
    }
    Write-Host ""
}
catch {
    Write-LogMessage "PIM Group Activation failed: $($_.Exception.Message)" -Level Error
    exit 1
}
finally {
    # Cleanup
    if (Get-MgContext) {
        Write-LogMessage "Disconnecting from Microsoft Graph..." -Level Info
        #Disconnect-MgGraph
        Write-LogMessage "Disconnected from Microsoft Graph." -Level Info
    }
}
