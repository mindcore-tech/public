<#
	==========================================================================
	 Created on:    12-11-2024 10:53
	 Created by:    Michael Morten Sonne
	===========================================================================

.SYNOPSIS
    Export specific Microsoft 365 mailbox messages by InternetMessageID using Microsoft Graph API.

.DESCRIPTION
    This script authenticates to Microsoft Graph with client credentials, searches for emails in a specific mailbox
    based on a list of InternetMessageIDs, and saves the message content as text files in a local folder.

.NOTES
    - Requires Entra ID App Registration with Mail.Read Graph API permissions.
    - Do not hardcode secrets: use environment variables for credentials or better (this is just an example).
    - Compatible with PowerShell 5.x, 7.x.

.PARAMETER Search_UPN
    The UPN of the mailbox to search.

.PARAMETER OutFolder
    The folder where messages are saved.

.PARAMETER MessageIDsFile
    Path to the file containing InternetMessageIDs (one per line).

.EXAMPLE
    $env:GRAPH_CLIENT_ID = "your-client-id"
    $env:GRAPH_CLIENT_SECRET = "your-client-secret"
    $env:GRAPH_TENANT_ID = "your-tenant-id"
    .\Export-M365-Messages.ps1 -Search_UPN "user@domain.com" -OutFolder "C:\temp\output" -MessageIDsFile "C:\temp\MessageIDs.txt"

Updates:
    16-07-2025: Rewritten
    
#>

param(
    [Parameter(Mandatory)]
    [string]$Search_UPN,

    [Parameter(Mandatory)]
    [string]$OutFolder,

    [Parameter(Mandatory)]
    [string]$MessageIDsFile
)

# Get credentials from environment variables
$clientID     = $env:GRAPH_CLIENT_ID
$ClientSecret = $env:GRAPH_CLIENT_SECRET
$tennant_ID   = $env:GRAPH_TENANT_ID

if (-not $clientID -or -not $ClientSecret -or -not $tennant_ID) {
    Write-Error "Missing environment variables: GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, GRAPH_TENANT_ID."
    exit 1
}

# Validate input file
if (-not (Test-Path $MessageIDsFile)) {
    Write-Error "Message ID file not found: $MessageIDsFile"
    exit 1
}

# Ensure output directory exists
if (-not (Test-Path $OutFolder)) {
    New-Item -Path $OutFolder -ItemType Directory -Force | Out-Null
}

# Acquire token
$AZ_Body = @{
    client_id     = $clientID
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}
try {
    $token = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tennant_ID/oauth2/v2.0/token" -Body $AZ_Body
} catch {
    Write-Error "Failed to acquire token: $_"
    exit 1
}
$Auth_headers = @{
    "Authorization" = "Bearer $($token.access_token)"
    "Content-type"  = "application/json"
}

# Read Message IDs
$list = Get-Content $MessageIDsFile | Where-Object { $_ -ne "" }

foreach ($INetMessageID in $list) {
    $fname = $INetMessageID.Replace("<", "").Replace(">", "").Replace("@", "_").Replace(".", "_").Replace(" ", "_")
    $Search_body = "https://graph.microsoft.com/v1.0/users/$Search_UPN/messages/?`$filter=internetMessageId eq '$INetMessageID'"

    Write-Host "Searching for message with InternetMessageID: '$INetMessageID'..." -ForegroundColor Cyan

    try {
        $result = Invoke-RestMethod -Uri $Search_body -Method Get -Headers $Auth_headers
        if ($null -eq $result.value -or $result.value.Count -eq 0) {
            Write-Warning "Message not found for: '$INetMessageID'"
            continue
        }
        $msg = $result.value[0]
        $messageID = $msg.id
        $messagesubject = $msg.subject

        Write-Host "Message found. ID: '$messageID'" -ForegroundColor Green
        Write-Host "Subject: $messagesubject" -ForegroundColor Yellow
    } catch {
        Write-Error "Error fetching message ID for '$INetMessageID': $_"
        continue
    }

    # Get message content
    $body_Content = "https://graph.microsoft.com/v1.0/users/$Search_UPN/messages/$messageID"
    try {
        Write-Host "Fetching message content for: '$messageID'..." -ForegroundColor Cyan
        $message_Content = Invoke-RestMethod -Uri $body_Content -Method Get -Headers $Auth_headers

        # Save as text, include subject and sender info for context
        $outputText = @"
InternetMessageID: $INetMessageID
Subject: $($message_Content.subject)
From: $($message_Content.from.emailAddress.address)
To: $($message_Content.toRecipients | ForEach-Object { $_.emailAddress.address } | Join-String ", ")
Received: $($message_Content.receivedDateTime)
Body Preview: $($message_Content.bodyPreview)

Full Body:
$($message_Content.body.content)
"@
        $filePath = Join-Path $OutFolder "$fname.txt"
        $outputText | Out-File -FilePath $filePath -Encoding UTF8

        Write-Host "Message saved to '$filePath'" -ForegroundColor Green
    } catch {
        Write-Error "Error fetching message content for '$messageID': $_"
    }

    Write-Host ""
}
