# Export-M365-Messages.ps1

This PowerShell script helps you export specific email messages from a Microsoft 365 mailbox using their InternetMessageID via the Microsoft Graph API.

## What does it do?

- Authenticates securely to Microsoft Graph with app credentials (environment variables).
- Searches a target mailbox for each InternetMessageID from a list.
- Saves every found message as a text file with useful details (subject, sender, recipients, body) to your chosen output folder.

## Prerequisites

- Azure AD App Registration with `Mail.Read` permission.
- Environment variables set for `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, and `GRAPH_TENANT_ID`.
- PowerShell 5.x or newer.
- A text file with InternetMessageIDs (one per line).

## Usage

```powershell
$env:GRAPH_CLIENT_ID     = "your-client-id"
$env:GRAPH_CLIENT_SECRET = "your-client-secret"
$env:GRAPH_TENANT_ID     = "your-tenant-id"

.\Export-M365-Messages.ps1 -Search_UPN "user@domain.com" -OutFolder "C:\temp\output" -MessageIDsFile "C:\temp\MessageIDs.txt"
```

Never share your client secrets. Always keep credentials secure and if possible, not use client secrets (sample code)

## Output

- Text files for each found message, saved in your output folder.

**Tip:**  
Use this script for investigations, compliance, or whenever you need to quickly extract selected emails from Microsoft 365.
