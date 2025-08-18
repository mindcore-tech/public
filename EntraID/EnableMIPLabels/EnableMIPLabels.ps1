
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

    .\Enable-MIPLabels.ps1 -Loglevel Verbose
    This will run the script with verbose logging enabled.

Updates:
    18-08-2025: First version. 
    
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$GraphScopes = @(
        'Directory.ReadWrite.All'#,
        #'Policy.Read.All'
    ),
    [switch]$SkipLabelSync,
    [switch]$Quiet
)

# ---------- Logging ----------
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info','Warn','Error','Verbose')]
        [string]$Level = 'Info'
    )
    $ts = (Get-Date).ToString('u')
    switch ($Level) {
        'Info' {
            if (-not $Quiet) {
                Write-Information "[$ts] $Message" -InformationAction Continue
            }
        }
        'Warn'    { Write-Warning "[$ts] $Message" }
        'Error'   { Write-Error "[$ts] $Message" }
        'Verbose' { Write-Verbose "[$ts] $Message" }
    }
}

if (-not $Quiet) { $InformationPreference = 'Continue' }

# ---------- Utility ----------
function Test-Command {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' not found. Install/import the module that provides it."
    }
}

function Connect-GraphSafe {
    param([string[]]$Scopes)
    if (-not (Get-MgContext)) {
        Write-Log -Level Verbose -Message "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -ErrorAction Stop | Out-Null
    } else {
        Write-Log -Level Verbose -Message "Microsoft Graph already connected (Tenant: $((Get-MgContext).TenantId))."
    }
}

# ---------- Directory Setting Retrieval / Update ----------
function Get-GroupUnifiedSetting {
    try {
        $s = Get-MgBetaDirectorySetting -Search 'DisplayName:"Group.Unified"' -ErrorAction Stop
        if ($s) { return $s }
    } catch {
        Write-Log -Level Verbose -Message "Search retrieval failed, enumerating settings."
    }
    return Get-MgBetaDirectorySetting -All | Where-Object DisplayName -eq 'Group.Unified'
}

function Set-GroupUnifiedSetting {
    [CmdletBinding()]
    param()

    $setting = Get-GroupUnifiedSetting

    if (-not $setting) {
        Write-Log -Level Verbose -Message "Group.Unified setting not found. Creating from template."
        $template = Get-MgBetaDirectorySettingTemplate -All | Where-Object DisplayName -eq 'Group.Unified'
        if (-not $template) { throw "Group.Unified template not found." }

        $body = @{
            templateId = $template.Id
            values     = @(
                @{ name = 'EnableMIPLabels'; value = 'True' }
            )
        }

        if ($PSCmdlet.ShouldProcess("DirectorySetting(Group.Unified)", "Create with EnableMIPLabels=True")) {
            $setting = New-MgBetaDirectorySetting -BodyParameter $body -ErrorAction Stop
        }
    }
    return $setting
}

function Set-EnableMIPLabels {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Setting)

    $currentValue = ($Setting.Values | Where-Object Name -eq 'EnableMIPLabels').Value
    if ($currentValue -eq 'True') {
        Write-Log -Level Verbose -Message "EnableMIPLabels already True. No update needed."
        return $Setting
    }

    $updatedValues =
        $Setting.Values |
        ForEach-Object {
            if ($_.Name -eq 'EnableMIPLabels') {
                @{ Name = 'EnableMIPLabels'; Value = 'True' }
            } else {
                @{ Name = $_.Name; Value = $_.Value }
            }
        }

    if (-not ($updatedValues | Where-Object Name -eq 'EnableMIPLabels')) {
        $updatedValues += @{ Name = 'EnableMIPLabels'; Value = 'True' }
    }

    $body = @{ Values = $updatedValues }

    if ($PSCmdlet.ShouldProcess("DirectorySetting:$($Setting.Id)", "Set EnableMIPLabels=True")) {
        Update-MgBetaDirectorySetting -DirectorySettingId $Setting.Id -BodyParameter $body -ErrorAction Stop
        Write-Log -Level Verbose -Message "Updated EnableMIPLabels to True."
    }
    return Get-MgBetaDirectorySetting -DirectorySettingId $Setting.Id
}

# ---------- Label Sync ----------
function Invoke-LabelSync {
    [CmdletBinding()]
    param()

    Test-Command -Name Connect-IPPSSession
    Test-Command -Name Execute-AzureAdLabelSync

    if (-not (Get-PSSession | Where-Object { $_.ComputerName -like '*compliance*' })) {
        Write-Log -Level Verbose -Message "Connecting to IPPS (Security & Compliance Center)."
        # Banner from module will appear here (cannot suppress)
        Connect-IPPSSession -ErrorAction Stop | Out-Null
    } else {
        Write-Log -Level Verbose -Message "IPPS session already present."
    }

    Write-Log -Level Verbose -Message "Executing Azure AD label sync."
    Execute-AzureAdLabelSync
}

# ---------- Main ----------
try {
    Write-Log -Message "Starting operation."

    Test-Command -Name Connect-MgGraph
    Test-Command -Name Get-MgBetaDirectorySetting

    Connect-GraphSafe -Scopes $GraphScopes

    $setting = Set-GroupUnifiedSetting
    $final   = Set-EnableMIPLabels -Setting $setting

    $effective = ($final.Values | Where-Object Name -eq 'EnableMIPLabels').Value
    Write-Log -Message "EnableMIPLabels current value: $effective"

    if (-not $SkipLabelSync) {
        Invoke-LabelSync
        Write-Log -Message "Label sync triggered."
    } else {
        Write-Log -Level Verbose -Message "Label sync skipped."
    }

    Write-Log -Message "Completed successfully."
}
catch {
    Write-Log -Level Error -Message ("Failed: {0}" -f $_.Exception.Message)
    if ($PSBoundParameters['Verbose']) {
        $_ | Format-List * -Force | Out-String | ForEach-Object {
            Write-Log -Level Verbose -Message $_
        }
    }
    exit 1
}
finally {
    if (Get-MgContext) {
        Write-Log -Level Verbose -Message "Disconnecting from Microsoft Graph."
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
