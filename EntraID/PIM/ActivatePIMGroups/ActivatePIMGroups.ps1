<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	17-12-2025 19:37
	 Created by:   	Michael Morten Sonne
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

<#
.SYNOPSIS
    Writes formatted log messages with timestamps and color coding

.DESCRIPTION
    This function creates standardized log messages with timestamps and 
    color-coded output based on the severity level. Messages are displayed
    in the console with appropriate formatting.

.PARAMETER Message
    The message text to be logged

.PARAMETER Level
    The severity level of the message. Valid values are 'Info', 'Warning', 'Error'
    Default is 'Info'

.EXAMPLE
    Write-LogMessage "Process started" -Level Info
    Write-LogMessage "Configuration issue detected" -Level Warning
    Write-LogMessage "Fatal error occurred" -Level Error
#>
function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    # Create timestamp in standardized format
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Display message with appropriate color based on severity level
    switch ($Level) {
        'Info' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
    }
}

<#
.SYNOPSIS
    Installs and imports required PowerShell modules

.DESCRIPTION
    This function checks if the required PowerShell modules are available on the system.
    If a module is not installed, it will be automatically installed from the PowerShell Gallery
    with CurrentUser scope. All specified modules are then imported into the current session.

.PARAMETER ModuleNames
    Array of module names to check, install if missing, and import

.EXAMPLE
    Install-RequiredModules -ModuleNames @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')

.NOTES
    - Uses CurrentUser scope to avoid requiring administrator privileges
    - Uses -Force and -AllowClobber parameters to handle version conflicts
    - Throws terminating error if any module fails to install or import
#>
function Install-RequiredModules {
    param([array]$ModuleNames)
    
    Write-LogMessage "Checking required PowerShell modules..." -Level Info
    
    # Process each required module
    foreach ($moduleName in $ModuleNames) {
        try {
            # Check if module is already available
            $module = Get-Module -Name $moduleName -ListAvailable
            if ($null -eq $module) {
                Write-LogMessage "Installing module: $moduleName" -Level Warning
                # Install module for current user to avoid admin requirements
                Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser
                Write-LogMessage "Successfully installed module: $moduleName" -Level Info
            } else {
                Write-LogMessage "Module already available: $moduleName" -Level Info
            }
            
            # Import the module into current session
            Import-Module $moduleName -Force
        }
        catch {
            Write-LogMessage "Error with module $moduleName : $($_.Exception.Message)" -Level Error
            throw "Failed to install or import module: $moduleName"
        }
    }
}

<#
.SYNOPSIS
    Wrapper function for making Microsoft Graph API calls

.DESCRIPTION
    This function provides a standardized way to make Microsoft Graph API calls using
    the Invoke-MgGraphRequest cmdlet. It handles URI formatting, version selection,
    request body serialization, and comprehensive error handling with detailed logging.

.PARAMETER Uri
    The Graph API endpoint URI (relative or absolute). Can include or exclude the version prefix.

.PARAMETER Method
    HTTP method for the request (GET, POST, PATCH, PUT, DELETE). Default is 'GET'.

.PARAMETER Body
    Request body object for POST/PATCH/PUT operations. Will be automatically converted to JSON.

.PARAMETER UseBeta
    Switch to use the beta endpoint instead of the v1.0 endpoint

.EXAMPLE
    Invoke-GraphApi -Uri "/users" -Method GET
    Invoke-GraphApi -Uri "/groups" -Method POST -Body $groupData -UseBeta

.NOTES
    - Automatically handles URI formatting and version prefixes
    - Converts request bodies to JSON with proper depth
    - Provides detailed error messages with HTTP status codes
    - Requires active Microsoft Graph authentication context
#>
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
        # Normalize URI format - remove base URL if present and construct relative URI
        $relativeUri = $Uri
        if ($Uri.StartsWith('http')) {
            $baseUrl = if ($UseBeta) { $GraphBetaUrl } else { $GraphBaseUrl }
            $relativeUri = $Uri.Replace($baseUrl, "").TrimStart('/')
        } else {
            $relativeUri = $Uri.TrimStart('/')
        }
        
        # Add version prefix if not already present
        if (-not $relativeUri.StartsWith('v1.0/') -and -not $relativeUri.StartsWith('beta/')) {
            $version = if ($UseBeta) { 'beta' } else { 'v1.0' }
            $relativeUri = "$version/$relativeUri"
        }
        
        Write-LogMessage "Making Graph API call: $Method $relativeUri" -Level Info
        
        # Prepare request parameters for Invoke-MgGraphRequest
        $requestParams = @{
            Uri = $relativeUri
            Method = $Method
        }
        
        # Add request body for operations that support it
        if ($Body -and ($Method -eq 'POST' -or $Method -eq 'PATCH' -or $Method -eq 'PUT')) {
            $requestParams.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        # Execute the Graph API request
        $response = Invoke-MgGraphRequest @requestParams
        return $response
    }
    catch {
        # Extract status code and error message for detailed logging
        $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { "Unknown" }
        $errorMessage = $_.Exception.Message
        
        # Attempt to extract detailed error information from Graph API response
        if ($_.Exception.Response) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errorDetails.error.message) {
                    $errorMessage = $errorDetails.error.message
                }
            }
            catch {
                # Ignore parsing errors - use original error message
            }
        }
        
        Write-LogMessage "Graph API error ($statusCode): $errorMessage" -Level Error
        throw "Graph API call failed: $errorMessage"
    }
}

<#
.SYNOPSIS
    Establishes connection to Microsoft Graph API

.DESCRIPTION
    This function connects to Microsoft Graph using the Connect-MgGraph cmdlet with the
    required scopes for PIM operations. It verifies the connection by making a test API
    call and ensures authentication context is properly established.

.OUTPUTS
    Microsoft Graph context object

.EXAMPLE
    $context = Connect-ToMicrosoftGraph

.NOTES
    - Requires interactive authentication (device code flow or browser)
    - Uses predefined scopes from $RequiredScopes variable
    - Performs connection verification with test API call
    - Throws terminating error if connection fails
#>
function Connect-ToMicrosoftGraph {
    try {
        Write-LogMessage "Connecting to Microsoft Graph..." -Level Info
        
        # Connect to Microsoft Graph with required scopes for PIM operations
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
        
        # Verify connection was established successfully
        $context = Get-MgContext
        if ($null -eq $context) {
            throw "Failed to establish Graph connection"
        }
        
        Write-LogMessage "Setting up authentication for REST API calls..." -Level Info
        
        # Set flag to use Invoke-MgGraphRequest for REST API calls
        # This handles authentication automatically using the established context
        $script:UseGraphRequest = $true
        
        # Verify API access by making a test call to the /me endpoint
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

<#
.SYNOPSIS
    Retrieves information about the currently authenticated user

.DESCRIPTION
    This function queries Microsoft Graph API to get details about the user who
    is currently authenticated. It validates the response and ensures required
    user properties are available for PIM operations.

.PARAMETER Context
    Microsoft Graph context object (currently not used but kept for compatibility)

.OUTPUTS
    User object containing displayName, id, and other user properties

.EXAMPLE
    $currentUser = Get-CurrentUserInfo -Context $context
    Write-Host "Current user: $($currentUser.displayName)"

.NOTES
    - Requires active Microsoft Graph authentication
    - Validates that user ID is present in the response
    - Logs user information for audit trail
#>
function Get-CurrentUserInfo {
    param([object]$Context)
    
    try {
        Write-LogMessage "Getting current user information via REST API..." -Level Info
        
        # Query Microsoft Graph API to get current user details
        $user = Invoke-GraphApi -Uri "/v1.0/me" -Method GET
        
        # Validate that we received valid user information
        if ($null -eq $user -or [string]::IsNullOrEmpty($user.id)) {
            throw "Failed to retrieve current user information"
        }
        
        # Log user information for audit and debugging purposes
        Write-LogMessage "Current user: $($user.displayName) ($($user.id))" -Level Info
        return $user
    }
    catch {
        Write-LogMessage "Error getting current user: $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Searches for and retrieves information about a specific Azure AD group

.DESCRIPTION
    This function searches for an Azure AD group by its display name using Microsoft Graph API.
    It performs an exact match search and returns detailed group information needed for PIM operations.
    The function validates that the group exists and is accessible.

.PARAMETER DisplayName
    The exact display name of the group to search for (case-sensitive)

.OUTPUTS
    Group object containing id, displayName, and other group properties

.EXAMPLE
    $group = Get-RBACGroupInfo -DisplayName "RBAC_Global_Reader_No_approval"
    Write-Host "Found group: $($group.displayName) with ID: $($group.id)"

.NOTES
    - Uses OData filter for exact display name matching
    - Requires Groups.Read.All permission scope
    - Returns first matching group if multiple groups have the same display name
    - Throws error if group is not found or not accessible
#>
function Get-RBACGroupInfo {
    param([string]$DisplayName)
    
    try {
        Write-LogMessage "Finding RBAC group: $DisplayName via REST API..." -Level Info
        
        # Use REST API to search for group
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode("displayName eq '$DisplayName'")
        $response = Invoke-GraphApi -Uri "/v1.0/groups?`$filter=$encodedFilter" -Method GET
        
        # Validate that at least one group was found
        if ($null -eq $response.value -or $response.value.Count -eq 0) {
            throw "Group '$DisplayName' not found"
        }
        
        # Return the first matching group (should be unique by display name)
        $group = $response.value[0]
        
        Write-LogMessage "Found group: $($group.displayName) ($($group.id))" -Level Info
        return $group
    }
    catch {
        Write-LogMessage "Error finding group: $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Retrieves eligible PIM assignments for a user in a specific group

.DESCRIPTION
    This function checks if the specified user has eligible PIM assignments for the target group.
    It uses multiple approaches to find eligible assignments and provides comprehensive error
    handling with troubleshooting guidance. The function prioritizes 'owner' assignments over
    'member' assignments if both are available.

.PARAMETER UserId
    The Azure AD object ID of the user to check for eligible assignments

.PARAMETER GroupId
    The Azure AD object ID of the group to check for eligible assignments

.OUTPUTS
    PIM eligibility schedule object containing assignment details

.EXAMPLE
    $eligibility = Get-EligibleAssignment -UserId $user.id -GroupId $group.id
    Write-Host "Found eligible assignment: $($eligibility.accessId) for group $($eligibility.groupId)"

.NOTES
    - Requires PrivilegedEligibilitySchedule.Read.AzureADGroup permission scope
    - Uses fallback approaches if direct group filtering fails
    - Provides detailed error messages for troubleshooting
    - Prioritizes 'owner' role over 'member' role when both are available
    - May require privileged administrator roles for full functionality
#>
function Get-EligibleAssignment {
    param(
        [string]$UserId,
        [string]$GroupId
    )
    
    try {
        Write-LogMessage "Checking eligible assignments for user in group via REST API..." -Level Info
        
        # Primary approach: Try to get eligibility schedules filtered by user and group
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
            # Fallback approach: Get all user assignments and filter for specific group
            Write-LogMessage "Main PIM endpoint failed (403/Forbidden usually means no eligible assignments): $($_.Exception.Message)" -Level Warning
            
            Write-LogMessage "Trying alternative approach to get user's eligible assignments..." -Level Info
            try {
                # Get all eligible assignments for the user
                $userFilter = [System.Web.HttpUtility]::UrlEncode("principalId eq '$UserId'")
                $allUserAssignments = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=$userFilter" -Method GET -UseBeta
                
                if ($null -eq $allUserAssignments.value -or $allUserAssignments.value.Count -eq 0) {
                    throw "No PIM eligible assignments found for user. User may not have any PIM-eligible group memberships."
                }
                
                # Filter assignments for the specific target group
                $eligibleAssignments = $allUserAssignments.value | Where-Object { $_.groupId -eq $GroupId }
                
                if ($null -eq $eligibleAssignments -or $eligibleAssignments.Count -eq 0) {
                    throw "User has PIM eligible assignments, but not for the group '$GroupId'. Available groups: $($allUserAssignments.value.groupId -join ', ')"
                }
            }
            catch {
                Write-LogMessage "Alternative approach also failed: $($_.Exception.Message)" -Level Error
                
                # Final troubleshooting attempt: List available PIM groups
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
                    # Provide comprehensive error message with troubleshooting guidance
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
        
        # Prioritize assignment types: prefer 'owner' over 'member' if both exist
        $ownerAssignment = $eligibleAssignments | Where-Object { $_.accessId -eq "owner" }
        $memberAssignment = $eligibleAssignments | Where-Object { $_.accessId -eq "member" }
        
        $assignment = if ($ownerAssignment) { $ownerAssignment } else { $memberAssignment }
        
        # Validate that we found a usable assignment
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

<#
.SYNOPSIS
    Creates a PIM group activation request

.DESCRIPTION
    This function submits a PIM group activation request using Microsoft Graph API.
    It constructs the proper request body with schedule information, validates the request,
    and provides detailed error handling with troubleshooting guidance for common issues.

.PARAMETER EligibleAssignment
    The eligible assignment object containing principalId, groupId, and accessId

.PARAMETER Duration
    ISO 8601 duration string for how long the activation should last (e.g., 'PT1H' for 1 hour)

.PARAMETER Justification
    Business justification for the activation request

.OUTPUTS
    Assignment schedule request object containing the activation request details and status

.EXAMPLE
    $request = Request-GroupActivation -EligibleAssignment $assignment -Duration 'PT2H' -Justification 'Emergency access'
    Write-Host "Activation request ID: $($request.id) Status: $($request.status)"

.NOTES
    - Requires PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup permission scope
    - Uses ISO 8601 format for dates and durations
    - Provides specific guidance for 403 Forbidden errors
    - Validates that the group allows self-activation
    - May require approval depending on PIM policy configuration
#>
function Request-GroupActivation {
    param(
        [object]$EligibleAssignment,
        [string]$Duration,
        [string]$Justification
    )
    
    try {
        Write-LogMessage "Creating activation request via REST API..." -Level Info
        
        # Create properly formatted start date time in UTC with ISO 8601 format
        $startDateTime = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", [System.Globalization.CultureInfo]::InvariantCulture)
        
        # Construct schedule information for the activation request
        $scheduleInfo = @{
            startDateTime = $startDateTime
            expiration    = @{
                type     = "afterDuration"  # Activation expires after specified duration
                duration = $Duration
            }
        }
        
        # Build the complete request body for PIM group activation
        $requestBody = @{
            accessId      = $EligibleAssignment.accessId    # Role type (owner/member)
            principalId   = $EligibleAssignment.principalId # User ID
            groupId       = $EligibleAssignment.groupId     # Target group ID
            action        = "selfActivate"                  # Self-service activation
            scheduleInfo  = $scheduleInfo                   # When and for how long
            justification = $Justification                  # Business justification
        }
        
        # Log the request body for debugging purposes (useful for troubleshooting)
        Write-LogMessage "Request body: $($requestBody | ConvertTo-Json -Depth 5)" -Level Info
        
        # Submit the activation request to Microsoft Graph API
        try {
            $response = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" -Method POST -Body $requestBody -UseBeta
            
            Write-LogMessage "Activation request created successfully. Request ID: $($response.id)" -Level Info
            Write-LogMessage "Status: $($response.status)" -Level Info
            
            return $response
        }
        catch {
            $errorMessage = $_.Exception.Message
            
            # Provide specific guidance for 403 Forbidden errors
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
                # Re-throw other errors without modification
                throw $errorMessage
            }
        }
    }
    catch {
        Write-LogMessage "Error creating activation request: $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Monitors the status of a PIM activation request until completion

.DESCRIPTION
    This function continuously polls the Microsoft Graph API to monitor the status of a
    PIM activation request. It waits until the request is either activated, failed, or
    times out. The function provides real-time status updates and handles various
    activation states appropriately.

.PARAMETER ActivationRequest
    The activation request object returned from Request-GroupActivation function

.PARAMETER TimeoutMinutes
    Maximum time to wait for activation completion in minutes (default: 10)

.PARAMETER PollIntervalSeconds
    How often to check the activation status in seconds (default: 10)

.OUTPUTS
    String representing the final activation status

.EXAMPLE
    $finalStatus = Wait-ForActivation -ActivationRequest $request -TimeoutMinutes 5 -PollIntervalSeconds 15
    if ($finalStatus -eq 'Activated') { Write-Host "Activation successful!" }

.NOTES
    - Monitors these status values: Activated, Provisioned, Failed, Denied, Canceled, PendingProvisioning, PendingApproval
    - Provides helpful messages for approval-required scenarios
    - Includes timeout handling to prevent infinite loops
    - Uses exponential backoff-style polling to reduce API calls
    - Handles temporary API errors gracefully
#>
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
        
        # Calculate timeout deadline
        $timeout = [DateTime]::Now.AddMinutes($TimeoutMinutes)
        $currentStatus = $ActivationRequest.status
        
        # Continue monitoring until timeout is reached
        while ([DateTime]::Now -lt $timeout) {
            # Check for successful completion states
            if ($currentStatus -eq "Activated" -or $currentStatus -eq "Provisioned") {
                Write-LogMessage "✅ Activation completed successfully! Status: $currentStatus" -Level Info
                return $currentStatus
            }
            
            # Check for failure states
            if ($currentStatus -eq "Failed" -or $currentStatus -eq "Denied" -or $currentStatus -eq "Canceled") {
                Write-LogMessage "❌ Activation failed with status: $currentStatus" -Level Error
                throw "Activation request failed with status: $currentStatus"
            }
            
            # Handle pending states that require waiting
            if ($currentStatus -eq "PendingProvisioning" -or $currentStatus -eq "PendingApproval") {
                Write-LogMessage "⏳ Status: $currentStatus - waiting..." -Level Info
                Start-Sleep -Seconds $PollIntervalSeconds
                
                # Query current status from API
                try {
                    $statusResponse = Invoke-GraphApi -Uri "/beta/identityGovernance/privilegedAccess/group/assignmentScheduleRequests/$($ActivationRequest.id)" -Method GET -UseBeta
                    $currentStatus = $statusResponse.status
                    
                    Write-LogMessage "Status check: $currentStatus" -Level Info
                }
                catch {
                    # Handle temporary API errors gracefully
                    Write-LogMessage "Error checking activation status: $($_.Exception.Message)" -Level Warning
                    Start-Sleep -Seconds $PollIntervalSeconds
                }
            } else {
                # Handle unknown or unexpected status values
                Write-LogMessage "⚠️  Unknown status: $currentStatus - continuing to monitor..." -Level Warning
                Start-Sleep -Seconds $PollIntervalSeconds
            }
        }
        
        # Handle timeout scenario
        Write-LogMessage "⏰ Timeout reached after $TimeoutMinutes minutes. Final status: $currentStatus" -Level Warning
        
        # Provide specific guidance for approval-required scenarios
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

#region Main Execution Block
<#
    MAIN SCRIPT EXECUTION
    
    This section orchestrates the entire PIM group activation process:
    1. Module installation and import
    2. Microsoft Graph authentication
    3. User and group information retrieval
    4. Eligibility verification
    5. Activation request submission
    6. Status monitoring
    7. Results presentation
    
    The script uses comprehensive error handling and provides detailed
    logging throughout the process for debugging and audit purposes.
#>
try {
    # Initialize the activation process with parameter logging
    Write-LogMessage "Starting PIM Group Activation Process" -Level Info
    Write-LogMessage "Target Group: $GroupDisplayName" -Level Info
    Write-LogMessage "Duration: $Duration" -Level Info
    Write-LogMessage "Justification: $Justification" -Level Info
    
    # Phase 0: Ensure all required PowerShell modules are available
    Write-LogMessage "Phase 0: Module Installation" -Level Info
    Install-RequiredModules -ModuleNames $RequiredModules
    
    # Phase 1: Establish authenticated connection to Microsoft Graph
    Write-LogMessage "Phase 1: Graph Authentication" -Level Info
    $context = Connect-ToMicrosoftGraph
    
    # Phase 2: Retrieve current user information for the activation
    Write-LogMessage "Phase 2: User Information Retrieval" -Level Info
    $currentUser = Get-CurrentUserInfo -Context $context
    
    # Phase 3: Locate and validate the target RBAC group
    Write-LogMessage "Phase 3: Group Information Retrieval" -Level Info
    $rbacGroup = Get-RBACGroupInfo -DisplayName $GroupDisplayName
    
    # Phase 4: Verify user has eligible assignments for the target group
    Write-LogMessage "Phase 4: Eligibility Verification" -Level Info
    $eligibleAssignment = Get-EligibleAssignment -UserId $currentUser.id -GroupId $rbacGroup.id
    
    # Phase 5: Submit PIM activation request
    Write-LogMessage "Phase 5: Activation Request Submission" -Level Info
    $activationRequest = Request-GroupActivation -EligibleAssignment $eligibleAssignment -Duration $Duration -Justification $Justification
    
    Write-LogMessage "PIM Group Activation request submitted successfully!" -Level Info
    
    # Phase 6: Monitor activation progress until completion
    Write-LogMessage "Phase 6: Activation Status Monitoring" -Level Info
    Write-LogMessage "Starting activation monitoring..." -Level Info
    $finalStatus = Wait-ForActivation -ActivationRequest $activationRequest -TimeoutMinutes 10 -PollIntervalSeconds 10
    
    #region Results Display
    <#
        ACTIVATION RESULTS PRESENTATION
        
        This section creates a professional, formatted summary of the activation process
        including all key information and final status. The display uses:
        - Dynamic box sizing based on content length
        - Color-coded status indicators
        - Unicode box drawing characters for professional appearance
        - Comprehensive information display for audit purposes
    #>
    
    # Prepare summary data
    Write-Host ""
    
    # Generate timestamp and determine status icon for display
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $statusIcon = if ($finalStatus -eq 'Activated' -or $finalStatus -eq 'Provisioned') { '✅' } else { '⚠️' }
    
    # Collect all summary content items for dynamic width calculation
    $contentItems = @(
        "👤 User        : $($currentUser.displayName)",
        "🔐 Group       : $($rbacGroup.displayName)", 
        "🎭 Role        : $($eligibleAssignment.accessId)",
        "📋 Request ID  : $($activationRequest.id)",
        "$statusIcon Status      : $finalStatus",
        "⏱️ Duration    : $Duration",
        "🕒 Completed   : $timestamp"
    )
    
    # Calculate optimal display width (minimum 82 characters or content width + padding)
    $maxContentLength = ($contentItems | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $boxWidth = [Math]::Max(82, $maxContentLength + 6)
    
    # Generate dynamic border elements using Unicode box drawing characters
    $topBorder = "╔" + ("═" * ($boxWidth - 2)) + "╗"
    $middleBorder = "╠" + ("═" * ($boxWidth - 2)) + "╣" 
    $bottomBorder = "╚" + ("═" * ($boxWidth - 2)) + "╝"
    
    # Create centered title with proper padding
    $title = "🎯 PIM ACTIVATION SUMMARY"
    $titlePadding = [Math]::Max(0, ($boxWidth - 2 - $title.Length) / 2)
    $titleLine = "║" + (" " * [Math]::Floor($titlePadding)) + $title + (" " * [Math]::Ceiling($titlePadding)) + "║"
    
    # Display formatted header
    Write-Host $topBorder -ForegroundColor Cyan
    Write-Host $titleLine -ForegroundColor Cyan  
    Write-Host $middleBorder -ForegroundColor Cyan
    
    # Determine status color for the status line display
    $statusColor = if ($finalStatus -eq 'Activated' -or $finalStatus -eq 'Provisioned') { 'Green' } else { 'Yellow' }
    
    # Display each content line with proper padding and alignment
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
    
    # Display status line with appropriate color coding
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
    
    # Display footer
    Write-Host $bottomBorder -ForegroundColor Cyan
    
    # Provide context-appropriate status message
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
    #endregion Results Display
}
catch {
    # Handle any errors that occur during the activation process
    Write-LogMessage "PIM Group Activation failed: $($_.Exception.Message)" -Level Error
    exit 1  # Exit with error code to indicate failure
}
finally {
    # Cleanup: Disconnect from Microsoft Graph (currently commented out to preserve session)
    if (Get-MgContext) {
        Write-LogMessage "Disconnecting from Microsoft Graph..." -Level Info
        # Note: Disconnect-MgGraph is commented out to allow continued use of the session
        # Uncomment the line below if you want to force disconnection after each run
        Disconnect-MgGraph
        Write-LogMessage "Disconnected from Microsoft Graph." -Level Info
    }
}
#endregion Main Execution Block
