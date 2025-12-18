# Entra ID PIM Groups Activation Script

🎯 **PowerShell script to automate Microsoft Entra ID Privileged Identity Management (PIM) group membership activation**

## Overview

This PowerShell script provides an automated way to activate PIM group memberships in Microsoft Entra ID using the Microsoft Graph API. It includes comprehensive error handling, logging, and status monitoring to ensure reliable activation of privileged roles.

## Features

- ✅ **Automated PIM Group Activation**: Seamlessly activate PIM-eligible group memberships
- 🔍 **Intelligent Group Discovery**: Find groups by display name with proper error handling
- 📊 **Real-time Status Monitoring**: Track activation progress with detailed status updates
- 🛡️ **Comprehensive Error Handling**: Detailed error messages and troubleshooting guidance
- 📝 **Enhanced Logging**: Color-coded log messages with timestamps
- 🎨 **Beautiful Output Formatting**: Professional summary display with status indicators
- 🔧 **Modular Design**: Well-structured functions for easy maintenance and extension

## Prerequisites

### PowerShell Modules
- `Microsoft.Graph.Authentication` (automatically installed if missing)

### Entra ID Permissions
The script requires the following Microsoft Graph API scopes:
- `Application.Read.All`
- `Group.Read.All`
- `User.Read.All`
- `Directory.AccessAsUser.All`
- `TeamSettings.Read.All`
- `RoleEligibilitySchedule.Read.Directory`
- `RoleAssignmentSchedule.ReadWrite.Directory`
- `PrivilegedEligibilitySchedule.Read.AzureADGroup`
- `PrivilegedAssignmentSchedule.Read.AzureADGroup`

### Entra ID Roles
The executing user needs one of the following roles:
- **Privileged Role Administrator** or **Global Administrator** if some permissions is missing for Graph
- And be eligible for the target PIM group

### PIM Configuration
- Target group must be **PIM-enabled** in Entra ID
- User must have **eligible assignment** for the target group
- PIM policies should allow **self-activation** (no approval required for this script)

## Usage

### Basic Usage
```powershell
.\ActivatePIMGroups.ps1
```

### Advanced Usage with Parameters
```powershell
.\ActivatePIMGroups.ps1 -GroupDisplayName "RBAC_Global_Reader_No_approval" -Duration "PT2H" -Justification "Emergency access required for incident response"
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GroupDisplayName` | String | `'RBAC_Global_Reader_No_approval'` | Display name of the PIM-enabled group |
| `Duration` | String | `'PT1H'` | Activation duration in ISO 8601 format |
| `Justification` | String | `'Activate PIM group membership via PowerShell'` | Business justification for the activation |

### Duration Format Examples
- `PT30M` - 30 minutes
- `PT1H` - 1 hour
- `PT2H` - 2 hours
- `PT4H` - 4 hours
- `PT8H` - 8 hours (maximum depends on PIM policy)

## Examples

### 1. Activate with Default Settings
```powershell
.\ActivatePIMGroups.ps1
```

### 2. Activate Specific Group for 4 Hours
```powershell
.\ActivatePIMGroups.ps1 -GroupDisplayName "RBAC_Exchange_Admin" -Duration "PT4H"
```

### 3. Complete Custom Activation
```powershell
.\ActivatePIMGroups.ps1 `
    -GroupDisplayName "RBAC_SharePoint_Admin" `
    -Duration "PT2H" `
    -Justification "Monthly maintenance and configuration updates"
```

## Script Workflow

1. **Module Installation**: Automatically installs required PowerShell modules
2. **Graph Authentication**: Connects to Microsoft Graph with required scopes
3. **User Verification**: Retrieves current user information
4. **Group Discovery**: Finds the specified PIM-enabled group
5. **Eligibility Check**: Verifies user has eligible assignments
6. **Activation Request**: Submits PIM activation request
7. **Status Monitoring**: Monitors activation progress until completion
8. **Summary Display**: Shows beautiful formatted results summary

## Output Example

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🎯 PIM ACTIVATION SUMMARY                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 👤 User        : John Doe                                                    ║
║ 🔐 Group       : RBAC_Global_Reader_No_approval                              ║
║ 🎭 Role        : member                                                      ║
║ 📋 Request ID  : 12345678-1234-1234-1234-123456789012                        ║
║ ✅ Status      : Activated                                                   ║
║ ⏱️ Duration    : PT1H                                                        ║
║ 🕒 Completed   : 2025-12-18 14:30:15                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

🎉 Activation successful! You now have elevated permissions for the specified duration.
```

## Troubleshooting

### Common Issues

#### 1. **403 Forbidden Error**
**Symptoms**: Script fails with "403 Forbidden" during activation
**Solutions**:
- Ensure user has required permissions/roles/membership
- Verify all Graph API scopes are granted and consented
- Check if admin consent is required for the application
- The user is already member (on the to-do to encount for)

#### 2. **Group not found**
**Symptoms**: "Group not found" error message
**Solutions**:
- Verify the group display name is correct
- Ensure the group exists in Entra ID
- Check if the group is PIM-enabled

#### 3. **No Eligible Assignments**
**Symptoms**: "No eligible assignments found" error
**Solutions**:
- Verify user has eligible (not active) assignments for the group
- Check PIM configuration in Azure/Entra ID Portal
- Ensure user has appropriate licenses (Entra ID P2)

#### 4. **Pending Approval**
**Symptoms**: Status shows "PendingApproval"
**Solutions**:
- Check if group requires approval for activation
- Contact PIM approvers to approve the request
- Consider using groups with self-activation enabled

#### 5. **Module Installation Issues**
**Symptoms**: PowerShell module installation fails
**Solutions**:
```powershell
# Run PowerShell as Administrator
Install-Module Microsoft.Graph.Authentication -Force -AllowClobber
```

### Debug Mode

For additional troubleshooting, the script provides detailed logging. Monitor the console output for specific error messages and guidance.

## Security Considerations

- 🔐 **Principle of Least Privilege**: Only activate roles when necessary
- ⏰ **Time-bound Access**: Use shortest duration needed for the task
- 📋 **Justification**: Always provide meaningful business justification
- 🔍 **Audit Trail**: All activations are logged in Azure AD audit logs
- 🚫 **No Credential Storage**: Script uses interactive authentication only

## Configuration Management

### PIM Policy Settings
Ensure your PIM group policies allow:
- Self-activation (if no approval workflow desired)
- Appropriate maximum activation duration
- Required MFA (if applicable)
- Notification settings

### Graph App Registration
If using app-based authentication, ensure:
- Required Graph API permissions are granted
- Admin consent is provided
- Appropriate redirect URIs are configured

## Script Information

- **Author**: Michael Morten Sonne
- **Created**: 17-12-2025
- **Version**: 1.0
- **PowerShell Version**: 5.1+ (PowerShell 7+ recommended)

## Contributing

Feel free to contribute improvements, bug fixes, or additional features:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This script is provided as-is for educational and operational purposes. Please review and test thoroughly before using in production environments.

## Related Scripts

Check out other scripts in this repository for additional Entra ID and PIM management capabilities:
- Active Directory management scripts
- Azure administration tools
- Microsoft 365 automation scripts

---

**⚠️ Important**: Always test in a non-production environment first. PIM activations grant elevated privileges and should be used responsibly.
