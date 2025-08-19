<#
	==========================================================================
	 Created on:    18-08-2025 19:53
	 Created by:    Michael Morten Sonne
	===========================================================================

.SYNOPSIS
    Ensures the Group.Unified directory setting has EnableMIPLabels=True, then (optionally) triggers a label sync using Microsoft Graph API.

.DESCRIPTION
    This script connects to Microsoft Graph, retrieves the Group.Unified directory setting, and ensures that the EnableMIPLabels property is set to True.
    If the setting does not exist, it creates it from the template. After updating the setting, it can optionally trigger a label sync in the Security & Compliance Center.

.NOTES
    - Requires at least Directory.ReadWrite.All Graph API permissions.
    - Requires the Microsoft Graph PowerShell SDK and Security & Compliance Center PowerShell module.
    - Compatible with PowerShell 5.x, 7.x.

.EXAMPLE
    
    .\Enable-MIPLabels.ps1
    This will connect to Microsoft Graph, ensure the Group.Unified setting has EnableMIPLabels=True, and trigger a label sync.

    .\Enable-MIPLabels.ps1 -SkipLabelSync
    This will perform the same operations but skip the label sync step.

Updates:
    18-08-2025: First version. 
    
#>

param(
    [switch]$SkipLabelSync
)

Write-Host "Connecting to Microsoft Graph..."
try {
    Connect-MgGraph -Scopes "Directory.ReadWrite.All" | Out-Null
    Write-Host "Connected to Microsoft Graph."
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

try {
    Write-Host "Retrieving Group.Unified directory setting..."
    $allSettings = Get-MgBetaDirectorySetting -All
    $grpUnifiedSetting = $allSettings | Where-Object { $_.DisplayName -eq "Group.Unified" }
    if (-not $grpUnifiedSetting) {
        throw "Group.Unified setting not found."
    }
    Write-Host "Group.Unified setting found. Updating EnableMIPLabels..."

    $params = @{
        Values = @(
            @{
                Name  = "EnableMIPLabels"
                Value = "True"
            }
        )
    }

    Update-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -BodyParameter $params -ErrorAction Stop
    Write-Host "EnableMIPLabels updated to 'True'."

    $Setting = Get-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -ErrorAction Stop
    Write-Host "Current setting values:"
    $Setting.Values | Format-Table -AutoSize
}
catch {
    Write-Warning "Could not update existing Group.Unified setting: $_"
    try {
        Write-Host "Attempting to create Group.Unified setting from template..."
        $Template = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }
        if (-not $Template) {
            throw "Group.Unified template not found."
        }

        $params = @{
            templateId = $Template.Id
            values     = @(
                @{
                    name  = "EnableMIPLabels"
                    value = "True"
                }
            )
        }

        New-MgBetaDirectorySetting -BodyParameter $params -ErrorAction Stop
        Write-Host "Group.Unified setting created."

        $allSettings = Get-MgBetaDirectorySetting -All
        $grpUnifiedSetting = $allSettings | Where-Object { $_.DisplayName -eq "Group.Unified" }
        $Setting = Get-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -ErrorAction Stop
        Write-Host "Current setting values:"
        $Setting.Values | Format-Table -AutoSize
    }
    catch {
        Write-Error "Failed to create Group.Unified setting: $_"
        exit 1
    }
}

if (-not $SkipLabelSync) {
    Write-Host "Connecting to Security & Compliance Center (IPPS)..."
    try {
        Connect-IPPSSession -ErrorAction Stop
        Write-Host "Connected to Security & Compliance Center (IPPS)."
        Execute-AzureAdLabelSync -ErrorAction Stop
        Write-Host "Label sync triggered successfully."
    } catch {
        Write-Error "Failed to trigger label sync: $_"
        exit 1
    }
} else {
    Write-Host "Skipping label sync as requested."
}

Write-Host "Script completed."
