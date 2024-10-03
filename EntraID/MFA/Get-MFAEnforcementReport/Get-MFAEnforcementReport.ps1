#Requires -Version 5

<#
.SYNOPSIS
    This script generates a report on the status of MFA enforcement for Microsoft enforced portals for MFA and sends it via email to the specified
    recipient address using Microsoft Graph if specified.

.DESCRIPTION
    This script generates a report on the status of MFA enforcement for Microsoft enforced portals for MFA and sends it via email to the specified
    recipient address using Microsoft Graph if specified. The report includes the following information:
    - Impact: Accounts that will be affected when Microsoft enforces the MFA requirement (sign-ins have been detected).
    - Investigation Needed: Active accounts missing MFA registration with sign-ins in the last X days.
    - Investigation Needed: Active Accounts Missing MFA Registration with Sign-Ins in the Last X Days - Not MFA Capable.

    The script uses the Microsoft Graph PowerShell module to connect to Microsoft Graph and retrieve the required information. The script requires
    the following permissions to be granted to the application:
    - AuditLog.Read.All
    - Directory.Read.All
    - UserAuthenticationMethod.Read.All
    - Mail.Send

    The script also requires the following PowerShell modules to be installed:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Beta.Users
    - Microsoft.Graph.Beta.Reports
    - Microsoft.Graph.Reports

    The script can be run in the following modes:
    - Managed Identity: Use managed identity to connect to Microsoft Graph.
    - Normal Run: Connect to Microsoft Graph using the specified account and scopes.

    Read more here: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication

.PARAMETER UseManagedIdentity
    Use managed identity to connect to Microsoft Graph.

.PARAMETER AttatchExportedCSV
    If set to add attachment to the email, send it also.

.PARAMETER DebugOutput
    If set to true, the script will output additional debug information.

.PARAMETER daysToCheckLogs
    Number of days to check for sign-in logs (default is 90 days).

.PARAMETER EnforceYears
    Years when MFA enforcement is planned. The default values are "2024" and "2025".
    The "Admin Portals"/AppID c44b4083-3bb0-49c1-b47d-974e53cbdf3c covers multiple applications.
    See more here: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication#prepare-for-multifactor-authentication

.PARAMETER EmailTo
    Email address to send the report to.

.PARAMETER EmailFrom
    Email address to send the report from.

.PARAMETER EmailSubject
    Subject of the email.

.PARAMETER EmailBody
    Body of the email. The default value is "Please find the attached MFA Enforcement Report."

.EXAMPLE
    .\Get-MFAEnforcementReport.ps1 -UseManagedIdentity -AttatchExportedCSV -DebugOutput -daysToCheckLogs 90 -EmailTo "test@domain.com" -EmailFrom "no_reply@domain.com"

    This example generates a report on the status of MFA enforcement for Microsoft enforced portals for MFA and sends it via email to the specified recipient.

.OUTPUTS
    Output will be sent to the console too.

.NOTES
    Version:        0.1
    Author:         Michael Morten Sonne
    Creation Date:  

.WARRANTY
    Use at your own risk, no warranty provided.

#>

param (
    [switch]$useManagedIdentity, # Use managed identity to connect to Microsoft Graph
    [Parameter()][boolean]$attatchExportedCSV = $false, # If set to add attachment to the email, send it also
    [Parameter()][boolean]$debugOutput = $false, # If set to true, the script will output additional debug information
    [Parameter()][string]$daysToCheckLogs = 90, # Number of days to check for sign-in logs (default is 90 days)
    [ValidateSet("2024", "2025")][string[]]$EnforceYears = @("2024", "2025"), # Years when MFA enforcement is planned
    [Parameter()][string]$emailTo,
    [Parameter()][string]$emailFrom,
    [Parameter()][string]$emailSubjectText = "MFA Enforcement Report",
    [Parameter()][string]$emailBody = "Please find the attached MFA Enforcement Report."
)

# See full list here: https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in
# Azure Management API will cover the changes for "Early 2025"
$MFAAppsInScope = @(
    [PSCustomObject]@{
        AppName     = "Azure Portal"
        AppId       = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
        EnforceDate = "Oct 15, 2024"
    }
    [PSCustomObject]@{
        AppName     = "Azure Mobile App"
        AppId       = "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa"
        EnforceDate = "Early 2025"
    }
    [PSCustomObject]@{
        AppName     = "Microsoft Azure CLI"
        AppId       = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        EnforceDate = "Early 2025"
    }
    [PSCustomObject]@{
        AppName     = "Microsoft Azure PowerShell"
        AppId       = "1950a258-227b-4e31-a9cf-717495945fc2"
        EnforceDate = "Early 2025"
    }

    <# - As the "Admin Portals" covers multiple applications, we will not include them in the list - see more here:
    https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication#prepare-for-multifactor-authentication
    
    [PSCustomObject]@{
        AppName     = "Microsoft Entra admin center"
        AppId       = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
        EnforceDate = "Second half of 2024"
    }
    [PSCustomObject]@{
        AppName     = "Microsoft Intune admin center"
        AppId       = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
        EnforceDate = "Second half of 2024"
    }
    #>
)

#------------------------------------[Functions]------------------------------------

# Generate email body content for MFA Enforcement Report
function New-EmailBody {
    param (
        [array]$mfaEnforcementImpact,
        [array]$UsersMissingMFASetup,
        [array]$UsersMissingMFASetupNoSignIn,
        [array]$UsersMissingMFASetupMfaNotCapable
    )

    # Define CSS styles
    $EmailCSS = @"
<style>
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid black; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .issue { background-color: #f8d7da; }
</style>
"@

    # Construct the email body with headings and initial description
    $HtmlHead = @"
<h2>MFA Enforcement Report</h2>
<p>This report provides the current status of MFA enforcement for Microsoft enforced portals for MFA</p>
<p>$mfaEnforcementImpact</p>
"@

    # Convert users missing MFA setup to HTML table
    $HtmlUsersMissingMFASetup = @"
<h3>Users Missing MFA Setup</h3>
<table>
    <tr>
        <th>User Principal Name</th>
        <th>Display Name</th>
        <th>Last Sign-In Date</th>
        <th>Last Non-Interactive Sign-In Date</th>
    </tr>
"@

    foreach ($user in $UsersMissingMFASetup) {
        $HtmlUsersMissingMFASetup += "<tr><td>$($user.UserPrincipalName)</td><td>$($user.DisplayName)</td><td>$($user.EntraID_LastSignInDateTime)</td><td>$($user.EntraID_LastNonInteractiveSignInDateTime)</td></tr>"
    }

    $HtmlUsersMissingMFASetup += "</table>"

    # Convert users missing MFA setup and not capable to HTML table
    $HtmlUsersMissingMFASetupMfaNotCapable = @"
<h3>Users Missing MFA Setup (MFA Not Capable)</h3>
<table>
    <tr>
        <th>User Principal Name</th>
        <th>Display Name</th>
        <th>Last Sign-In Date</th>
        <th>Last Non-Interactive Sign-In Date</th>
    </tr>
"@

    foreach ($user in $UsersMissingMFASetupMfaNotCapable) {
        $HtmlUsersMissingMFASetupMfaNotCapable += "<tr><td>$($user.UserPrincipalName)</td><td>$($user.DisplayName)</td><td>$($user.EntraID_LastSignInDateTime)</td><td>$($user.EntraID_LastNonInteractiveSignInDateTime)</td></tr>"
    }

    $HtmlUsersMissingMFASetupMfaNotCapable += "</table>"

    # Construct the email footer with the closing tags for the tables
    $HtmlFooter = @"
<p>This report is sent from PowerShell!</p>
"@

    # Construct the final HTML message with the CSS, headings, and tables
    $HtmlMsg = "<html><head>$EmailCSS</head><body>$HtmlHead$HtmlUsersMissingMFASetup<br>$HtmlUsersMissingMFASetupMfaNotCapable<br>$HtmlFooter</body></html>"

    return $HtmlMsg
}

# Function to add attachments to the email
function Add-Attachments {
    param (
        [array]$CSVFiles
    )

    $mailAttachments = @()

    foreach ($CSVFile in $CSVFiles) {
        if (Test-Path $CSVFile) {
            Write-Output "Adding the CSV file as an attachment to the email: $CSVFile"
            # Read the content of the CSV file as a byte array
            $ContentBytes = [System.IO.File]::ReadAllBytes($CSVFile)

            # Encode the byte array to a base64 string
            $Base64Content = [System.Convert]::ToBase64String($ContentBytes)

            # Extract the filename from $CSVFile
            $FileName = Split-Path -Path $CSVFile -Leaf

            # Define the attachment
            $Attachment = @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                "name" = $FileName
                "contentType" = "text/csv"
                "contentBytes" = $Base64Content
            }

            # Add the attachment to the list
            $mailAttachments += $Attachment
        } else {
            Write-Output "File not found: $CSVFile"
        }
    }

    return $mailAttachments
}

# Function to send email report
function Send-EmailReport {
    param (
        [string]$Subject,
        [string]$Body,
        [array]$mailAttachments
    )

    $params = @{
        message = @{
            subject = $Subject
            body = @{
                contentType = "HTML"
                content = $Body
            }
            toRecipients = @(
                @{
                    emailAddress = @{
                        address = $emailTo
                    }
                }
            )
            Attachments = $mailAttachments
        }
        saveToSentItems = $True # Save the message in the Sent Items folder
        isDeliveryReceiptRequested = $True # Request a delivery receipt
    }

    try {
        # Send the email
        Send-MgUserMail -UserId $emailFrom -BodyParameter $params

        # Test response from email send if successful
        if ($?) {
            Write-Output "Message sent successfully! - Message containing information about MFA enforcements sent to $emailTo"
        } else {
            Write-Output "Message not sent - check the error message above"
        }
    } catch {
        Write-Output "Failed to send email report: $_"
    }
}
function Get-ModuleInstalledByName {
    param (
        [string]$moduleName
    )
    # Check if the module is installed
    $InstalledModules = Get-InstalledModule
    If ($moduleName -notin $InstalledModules.Name) {
        # Module is not installed - install it
        Write-Output "PowerShell Module '$moduleName' is not installed - installing it now"
        try {
            # Install the module
            Install-Module -Name $moduleName -Force -Scope CurrentUser
        }
        catch {
            # Output the error message
            Write-Output "Error installing PowerShell Module '$moduleName' with error: $_"
        }
    }
    else {
        # Module is already installed - skip installation
        Write-Output "PowerShell Module '$moduleName' is already installed - skipping installation"
    }
}

function Get-ModulesInstalled {
    param (
        [string[]]$moduleNames
    )
    foreach ($moduleName in $moduleNames) {
        # Check if the module is installed
        $InstalledModules = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
        if (-not $InstalledModules) {
            # Module is not installed - install it
            Write-Output "PowerShell Module '$moduleName' is not installed - installing it now"
            try {
                # Install the module
                Install-Module -Name $moduleName -Force -Scope CurrentUser
            }
            catch {
                # Output the error message
                Write-Output "Error installing PowerShell Module '$moduleName' with error: $_"
            }
        }
        else {
            # Module is already installed - skip installation
            Write-Output "PowerShell Module '$moduleName' is already installed - skipping installation"
        }
    }
}

function Connect-ToMicrosoftGraph {
    param (
        [switch]$useManagedIdentity
    )
    try {
        # Output the connection status
        Write-Output "Connecting to Microsoft Graph..."
        # Check if we should use managed identity
        if ($useManagedIdentity) {
            # Connect using managed identity
            Connect-MgGraph -Identity -NoWelcome
        } else {
            # Connect using normal run with specified scopes
            #Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome

            Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All", "Mail.Send" -NoWelcome
        }
        # Output the connected account vs managed identity
        if ($useManagedIdentity) {
            Write-Output "Connected to Microsoft Graph successfully using Managed Identity"
        } else {
            Write-Output "Connected to Microsoft Graph successfully as '$((Get-MgContext).Account)'"
        }
    }
    catch {
        # Output the error message
        Write-Output "Error connecting to Microsoft Graph with error: $_"
        throw
    }
}

# Function to display validation results
function Show-ValidationResults {
    param (
        [string]$taskDescription,
        [string]$noIssuesMessage,
        [array]$affectedUsers
    )

    Write-Host "`nValidation: $taskDescription" -ForegroundColor Cyan

    if ($affectedUsers.Count -eq 0) {
        Write-Host "$noIssuesMessage" -ForegroundColor Green
    } else {
        Write-Host "Users that MAY be impacted by MFA enforcement:" -ForegroundColor Yellow
        $affectedUsers | Format-Table -Property DisplayName, UserPrincipalName
    }
}

# Function to flatten complex properties
function Convert-SignInLogToFlatObject {
    param (
        $log
    )

    [PSCustomObject]@{
        AppDisplayName                    = $log.AppDisplayName
        AppId                             = $log.AppId
        AppliedConditionalAccessPolicies  = if ($log.AppliedConditionalAccessPolicies) { ($log.AppliedConditionalAccessPolicies | ForEach-Object { $_.DisplayName }) -join ", " } else { "" }
        ClientAppUsed                     = $log.ClientAppUsed
        ConditionalAccessStatus           = $log.ConditionalAccessStatus
        CorrelationId                     = $log.CorrelationId
        CreatedDateTime                   = $log.CreatedDateTime
        DeviceDetail                      = if ($log.DeviceDetail) { "$($log.DeviceDetail.DeviceId), $($log.DeviceDetail.DisplayName), $($log.DeviceDetail.OperatingSystem), $($log.DeviceDetail.Browser)" } else { "" }
        IPAddress                         = $log.IPAddress
        Id                                = $log.Id
        IsInteractive                     = $log.IsInteractive
        Location                          = if ($log.Location) { "$($log.Location.City), $($log.Location.State), $($log.Location.CountryOrRegion)" } else { "" }
        ResourceDisplayName               = $log.ResourceDisplayName
        ResourceId                        = $log.ResourceId
        RiskDetail                        = $log.RiskDetail
        RiskEventTypes                    = if ($log.RiskEventTypes) { ($log.RiskEventTypes) -join ", " } else { "" }
        RiskEventTypesV2                  = if ($log.RiskEventTypesV2) { ($log.RiskEventTypesV2) -join ", " } else { "" }
        RiskLevelAggregated               = $log.RiskLevelAggregated
        RiskLevelDuringSignIn             = $log.RiskLevelDuringSignIn
        RiskState                         = $log.RiskState
        Status                            = if ($log.Status) { "$($log.Status.ErrorCode), $($log.Status.FailureReason)" } else { "" }
        UserDisplayName                   = $log.UserDisplayName
        UserId                            = $log.UserId
        UserPrincipalName                 = $log.UserPrincipalName
        AdditionalProperties              = if ($log.AdditionalProperties) { ($log.AdditionalProperties.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", " } else { "" }
    }
}

# Function to check if a module is imported and import it if not
function Import-ModuleIfNotImported {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -Name $moduleName -ListAvailable)) {
        Write-Host "Importing module: $moduleName"
        Import-Module $moduleName
    } else {
        Write-Host "Module $moduleName is already imported."
    }
}

#------------------------------------[Main Script]------------------------------------
# Get the current directory path
$currentDir = (Get-Location).Path

Write-Host "Script is running from the directory: $currentDir"

#------------------------------------[Check for installed modules]------------------------------------

Write-Host "Checking Microsoft Powershell Modules"

# Call the function to ensure 'Microsoft.Graph.Beta' is installed
#Get-ModuleInstalledByName -ModuleName "Microsoft.Graph.Beta"

# Define the modules to check and install
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Beta.Users",
    "Microsoft.Graph.Beta.Reports",
    "Microsoft.Graph.Reports"
)

# Ensure the required modules are installed
Get-ModulesInstalled -ModuleNames $requiredModules

#------------------------------------[Import required modules]------------------------------------
# Import required modules if not already imported
Import-ModuleIfNotImported -ModuleName "Microsoft.Graph.Authentication"
Import-ModuleIfNotImported -ModuleName "Microsoft.Graph.Beta.Users"
Import-ModuleIfNotImported -ModuleName "Microsoft.Graph.Beta.Reports"
Import-ModuleIfNotImported -ModuleName "Microsoft.Graph.Reports"

#------------------------------------[Try to connect to Microsoft Graph]------------------------------------

# Connect to Microsoft Graph based on the specified mode
Connect-ToMicrosoftGraph -UseManagedIdentity:$useManagedIdentity

#------------------------------------[Get Sign-in logs]------------------------------------

Write-Host "Reviewing sign-in logs from the past $($daysToCheckLogs) day(s) to identify interactive sign-ins"

# Get the date from which to search for sign-in logs
$dateFromInSearch = (Get-Date).AddDays(-$daysToCheckLogs).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Get the sign-in logs for the specified applications
$signInLogsEvents = [System.Collections.ArrayList]@()
$totalCountLoginEvents = 0

# Filter apps based on the specified enforcement years
$FilteredApps = $MFAAppsInScope | Where-Object { $EnforceYears -contains $_.EnforceDate.Substring($_.EnforceDate.Length - 4) }

# Get the sign-in logs for each application in scope
ForEach ($AppToCheck in $FilteredApps) {
    $logInEvents = @()
    Write-host "Searching for login events for the application '$($AppToCheck.AppName)' in the last $($daysToCheckLogs) day(s)..."

    $AppId = [guid]$AppToCheck.AppId
    #$logInEvents = Get-MgAuditLogSignIn -Filter "(AppId eq '$($AppId)') and (createdDateTime ge $dateFromInSearch)" -All
    #$logInEvents = Get-MgAuditLogSignIn -Filter "AppId eq '$AppId'" -All | Where-Object { $_.CreatedDateTime -ge $dateFromInSearch }

    # Construct the URL
    #$url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=appId eq '$appId' and createdDateTime ge $dateFromInSearch"
    $url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=appId eq '$AppId' and createdDateTime ge $($dateFromInSearch -replace ':', '%3A')"

    # Make the GET request
    $response = Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers

    # Filter the results
    $logInEvents = $response.value | Where-Object { $_.createdDateTime -ge $dateFromInSearch }


    $totalCountLoginEvents = $totalCountLoginEvents + $logInEvents.Count

    Write-Host "> Found '$($logInEvents.Count)' login event(s) for the application '$($AppToCheck.AppName)' in the past $($daysToCheckLogs) day(s)"
    $logInEvents | ForEach-Object { $signInLogsEvents.Add($_) | Out-Null }
}

# Output the total number of login events found
If ($signInLogsEvents) {
    Write-Host "Found $($totalCountLoginEvents) total login event(s) in Entra ID over the past $($daysToCheckLogs) day(s)"

    $signInLogsEvents_Users_unique = $signInLogsEvents.UserPrincipalName | Sort-Object -Unique

    Write-Host "Found $($signInLogsEvents_Users_unique.count) unique user(s) with sign-ins over the past $($daysToCheckLogs) day(s)"
}

#------------------------------------[Get Authentication Methods]------------------------------------
 
Write-Host "Getting Authentication Methods for users..."
$allUsersAuthMethods = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All
If ($allUsersAuthMethods) {
    Write-Host "Found $($allUsersAuthMethods.count) authentication methods for user(s)"

    $allUsersAuthMethods_Hash = [ordered]@{}
    $allUsersAuthMethods | ForEach-Object { $allUsersAuthMethods_Hash.add($_.UserPrincipalName, $_) }
}

#------------------------------------[Get User Info]------------------------------------

Write-Host "Retrieving user information from Entra ID"

$users = Get-MgBetaUser -All -property AccountEnabled, id, givenname, surname, userprincipalname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesDistinguishedName, OnPremisesExtensionAttributes, OnPremisesSyncEnabled, displayname, signinactivity `
| select-object id, givenname, surname, userprincipalname, OnPremisesDistinguishedName, AccountEnabled, displayname, AssignedLicenses, AssignedPlans, Authentication, Devices, CreatedDateTime, Department, Identities, InvitedBy, IsResourceAccount, JoinedTeams, JoinedGroups, LastPasswordChangeDateTime, LicenseDetails, Mail, Manager, MobilePhone, OfficeLocation, PasswordPolicies, ProxyAddresses, UsageLocation, OnPremisesSyncEnabled, `
@{name = 'LastSignInDateTime'; expression = { $_.signinactivity.lastsignindatetime } }, `
@{name = 'LastNonInteractiveSignInDateTime'; expression = { $_.signinactivity.LastNonInteractiveSignInDateTime } }, `
@{name = 'AuthPhoneMethods'; expression = { $_.authentication.PhoneMethods } }, `
@{name = 'AuthMSAuthenticator'; expression = { $_.authentication.MicrosoftAuthenticatorMethods } }, `
@{name = 'AuthPassword'; expression = { $_.authentication.PasswordMethods } }

If ($users) {
    Write-Host "Found a total of $($users.count) user(s) in Entra ID"
    $users_Hash = [ordered]@{}
    $users | ForEach-Object { $users_Hash.add($_.UserPrincipalName, $_) }
}

#------------------------------------[Correlate data]------------------------------------

Write-Host "Correlating data sources into a user array for validation..."

# Get more about license details from Microsoft here: https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference
$licenseCSVData = Invoke-WebRequest -Method Get -UseBasicParsing -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv

# Initialize variables
$userInfoArray = [System.Collections.ArrayList]@()
$usersTotal = $users.count

# Process each user
Write-Host "Processing user information..."

# Process each user
$users | ForEach-Object -Begin {
    # Create the progress bar
    Write-Progress -Activity "Correlating User Information" -Status "In Progress:" -PercentComplete 0
    $taskProcessed = 0
} -Process {
    # Default values
    $user = $_
    $signInsDetected = $false

    # Get the user's sign-in events and authentication methods if show debug output
    if ($debugOutput) {
        Write-Host "Processing user '$($user.DisplayName)' for sign-in events and authentication methods..."
    }

    # Sign-in Events
    If ($user.UserPrincipalName -in $signInLogsEvents_Users_unique) {
        $signInsDetected = $true
    }

    # Authentication Methods               
    If ($allUsersAuthMethods) {
        $authMethods = $allUsersAuthMethods_Hash[$user.UserPrincipalName]
    }

    # Get user licenses
    $LicenseInfo = @()
    ForEach ($License in $user.AssignedLicenses) {
        $LicenseInfo += $licenseCSVData | Where-Object { $_.Guid -eq $License.SkuID }
    }
    If ($LicenseInfo) {
        $userLicenseInfo_List = (($LicenseInfo."???Product_Display_Name" | Sort-Object -Unique) -join ",")
    }

    # Get unique license IDs
    $LicenseInfo = $LicenseInfo.String_ID | Sort-Object -Unique
    $user.AssignedPlans | Out-Null

    # Building array
    $Object = [PSCustomObject]@{
        Id                                           = $user.Id
        GivenName                                    = $user.GivenName
        SurName                                      = $user.Surname
        UserPrincipalName                            = $user.UserPrincipalName
        DisplayName                                  = $user.DisplayName
        AccountEnabled                               = $user.AccountEnabled
        Mail                                         = $user.Mail
        EntraID_LastSignInDateTime                   = $user.LastSignInDateTime
        EntraID_LastNonInteractiveSignInDateTime     = $user.LastNonInteractiveSignInDateTime
        EntraID_PasswordPolicies                     = $user.PasswordPolicies
        ActiveDirectoryDistinguishedName             = $user.OnPremisesDistinguishedName
        SignInsDetectedMSAdminPortals                = $signInsDetected
        UserLicenseList                              = $userLicenseInfo_List
        IsAdmin                                      = $authMethods.IsAdmin
        DefaultMfaMethod                             = $authMethods.DefaultMfaMethod
        MethodsRegistered                            = $authMethods.MethodsRegistered -join ','
        IsMfaCapable                                 = $authMethods.IsMfaCapable
        IsMfaRegistered                              = $authMethods.IsMfaRegistered
        IsPasswordlessCapable                        = $authMethods.IsPasswordlessCapable
        IsSsprCapable                                = $authMethods.IsSsprCapable
        IsSsprEnabled                                = $authMethods.IsSsprEnabled
        IsSsprRegistered                             = $authMethods.IsSsprRegistered
        IsSystemPreferredAuthenticationMethodEnabled = $authMethods.IsSystemPreferredAuthenticationMethodEnabled
        AuthMethodsLastUpdatedDateTime               = $authMethods.LastUpdatedDateTime  
    }
    $userInfoArray.add($object) | Out-Null

    # Increment the $taskProcessed counter variable which is used to create the progress bar.
    $taskProcessed = $taskProcessed + 1

    # Determine the completion percentage
    $Completed = ($taskProcessed / $usersTotal) * 100
    Write-Progress -Activity "Correlating User Information" -Status "In Progress:" -PercentComplete $Completed
} -End {
    Write-Progress -Activity "Correlating User Information" -Status "Complete" -Completed
}

Write-Host "Processed a total of $($userInfoArray.count) user(s) for validation"

#------------------------------------[Build Conclusions]------------------------------------

$daysLastSignInCheck = (Get-Date) - (New-TimeSpan -Days $daysToCheckLogs)

Write-Host "Building conclusions and parseing users to..."

# Exclude the On-Premises Directory Synchronization Service Account from the report (if it exists)
$userInfoArray_Scoped = $userInfoArray | Where-Object { $_.DisplayName -notlike "On-Premises Directory Synchronization Service Account" }

# IMPACT: Accounts that will be affected when Microsoft enforces the MFA requirement (sign-ins have been detected).
$mfaEnforcementImpact = $userInfoArray_Scoped | Where-Object { ( (!($_.IsMfaRegistered)) -and ($_.SignInsDetectedMSAdminPortals) -and ($_.AccountEnabled) ) }
$task1Description = "Active accounts with missing MFA and cloud sign-ins in the past $($daysToCheckLogs) day(s), with sign-in events detected against Microsoft Admin portals in the last $($daysToCheckLogs) day(s)"
$task1NoIssuesMessage = "No issues were found - accounts are protected as needed!"
Show-ValidationResults -taskDescription $task1Description -noIssuesMessage $task1NoIssuesMessage -affectedUsers $mfaEnforcementImpact

# INVESTIGATION NEEDED: Active accounts missing MFA registration with sign-ins in the last X days.
$activeUsersWithoutMFA = $userInfoArray_Scoped | Where-Object { ( (!($_.IsMFARegistered) -and (!($_.SignInsDetectedMSAdminPortals)) -and ($_.EntraID_LastSignInDateTime -gt $daysLastSignInCheck)) ) }
$task2Description = "Active accounts with missing MFA and cloud sign-ins in the past $($daysToCheckLogs) day(s), with no sign-in events detected against Microsoft Admin portals"
$task2NoIssuesMessage = "No issues were found - accounts are protected as needed!"
Show-ValidationResults -taskDescription $task2Description -noIssuesMessage $task2NoIssuesMessage -affectedUsers $activeUsersWithoutMFA

# INVESTIGATION NEEDED: Active Accounts Missing MFA Registration with Sign-Ins in the Last xx Days - Not MFA Capable
# Not MFA Capable: Users who are registered and enabled for a strong authentication method in Microsoft Entra ID. Authentication methods can be registered by the user or an admin on their behalf if needed.
$activeUsersWithoutMFA_NotCapable = $userInfoArray_Scoped | Where-Object { ( (!($_.IsMfaRegistered) -and (!($_.SignInsDetectedMSAdminPortals)) -and (!($_.IsMfaCapable)) -and ($_.EntraID_LastSignInDateTime -gt $daysLastSignInCheck) ) ) }
$task3Description = "Active accounts with missing MFA, not MFA capable, and cloud sign-ins in the past $($daysToCheckLogs) day(s), with no sign-in events detected against Microsoft Admin portals"
$task3NoIssuesMessage = "No issues were found - accounts are protected as needed!"
Show-ValidationResults -taskDescription $task3Description -noIssuesMessage $task3NoIssuesMessage -affectedUsers $activeUsersWithoutMFA_NotCapable

Write-Host ""

# Export data to .csv files for further analysis
Write-Host "Exporting data to .csv files for further analysis..."

# Export user information to .csv file
if ($null -ne $userInfoArray_Scoped -and $userInfoArray_Scoped.Count -gt 0) {
    try {
        # Export the relevant properties to CSV
        $userInfoArray_Scoped | Export-Csv -Path ".\Identity_Overview.csv" -NoTypeInformation
    }
    catch {
        # Output the error message
        Write-Host "Error exporting data to Identity_Overview.csv with error: $_"
    }
} else {
    # Output message if no data to export
    Write-Host "No data to export for Identity_Overview.csv"
}

# Export sign-in logs to .csv file
If ($signInLogsEvents.Count -gt 0) {
    # Flatten the data if necessary
    $flattenedSignInLogsEvents = $signInLogsEvents | ForEach-Object { Convert-SignInLogToFlatObject $_ }

    # Export the relevant properties to CSV
    $flattenedSignInLogsEvents | Export-Csv -Path ".\Identity_Overview_LoginsLogs.csv" -NoTypeInformation

    Write-Output "Exported $($signInLogsEvents.Count) sign-in log(s) to Identity_Overview_LoginsLogs.csv"
} else {
    # Output message if no data to export
    Write-Host "No data to export for Identity_Overview_LoginsLogs.csv"
}

# Export data of users with impact on MFA enforcement to .csv file
if ($null -ne $mfaEnforcementImpact) {
    try {
        # Export the relevant properties to CSV
        $mfaEnforcementImpact | Export-Csv -Path ".\Identity_Overview_ImpactMFAEnforcement.csv" -NoTypeInformation

        Write-Output "Exported user(s) to Identity_Overview_ImpactMFAEnforcement.csv"
    }
    catch {
        # Output the error message
        Write-Host "Error exporting data to Identity_Overview_ImpactMFAEnforcement.csv with error: $_"
    }
} else {
    # Output message if no data to export
    Write-Host "No data to export for Identity_Overview_ImpactMFAEnforcement.csv"
}

# Export data of users with missing MFA registration and recent sign-ins to .csv file
if ($null -ne $activeUsersWithoutMFA) {
    try {
        # Export the relevant properties to CSV
        $activeUsersWithoutMFA | Export-Csv -Path ".\Identity_Overview_MissingMFA.csv" -NoTypeInformation

        Write-Output "Exported user(s) to Identity_Overview_MissingMFA.csv"
    }
    catch {
        # Output the error message
        Write-Host "Error exporting data to Identity_Overview_MissingMFA.csv with error: $_"
    }
} else {
    # Output message if no data to export
    Write-Host "No data to export for Identity_Overview_MissingMFA.csv"
}

# Export data of users with missing MFA registration, not MFA capable, and recent sign-ins to .csv file
if ($null -ne $activeUsersWithoutMFA_NotCapable) {
    try {
        # Export the relevant properties to CSV
        $activeUsersWithoutMFA_NotCapable | Export-Csv -Path ".\Identity_Overview_MissingMFA_NotCapable.csv" -NoTypeInformation

        Write-Output "Exported user(s) to Identity_Overview_MissingMFA_NotCapable.csv"
    }
    catch {
        # Output the error message
        Write-Host "Error exporting data to Identity_Overview_MissingMFA_NotCapable.csv with error: $_"
    }
} else {
    # Output message if no data to export
    Write-Host "No data to export for Identity_Overview_MissingMFA_NotCapable.csv"
}

# Check if there are any issues
if ($null -ne $activeUsersWithoutMFA -or $null -ne $activeUsersWithoutMFA_NotCapable -or $debugOutput) {
    # Generate the email body
    $emailBody = New-EmailBody -ImpactOnMFAEnforcement $mfaEnforcementImpact -UsersMissingMFASetup $activeUsersWithoutMFA -UsersMissingMFASetupNoSignIn $activeUsersWithoutMFANoSignIn -UsersMissingMFASetupMfaNotCapable $activeUsersWithoutMFA_NotCapable
    
    # Define the attachment paths dynamically
    $CSVFiles = @(
        "$currentDir\Identity_Overview.csv",
        "$currentDir\Identity_Overview_LoginsLogs.csv",
        "$currentDir\Identity_Overview_MissingMFA.csv",
        "$currentDir\Identity_Overview_MissingMFA_NotCapable.csv"
    )

    if ($attatchExportedCSV) {
        Write-Output "Adding the CSV file as an attachment to the email"
        # Add attachments to the email
        $mailAttachments = Add-Attachments -CSVFiles $CSVFiles
    }
    else {
        Write-Output "Set to not adding the CSV file as an attachment to the email"
        $mailAttachments = @()
    }  
    
    # Send the email report if email address is provided
    if ($emailTo -and $emailFrom) {
        Write-Output "Email address provided: $emailTo from $emailFrom"
        Send-EmailReport -Subject "MFA Enforcement Report" -Body $emailBody -Attachments $mailAttachments
    }
    else {
        Write-Output "No email address provided, no email will be sent."
    }
} else {
    Write-Output "No MFA enforcement issues found, no email will be sent."
}

# End of script
Write-Host "End of script"
