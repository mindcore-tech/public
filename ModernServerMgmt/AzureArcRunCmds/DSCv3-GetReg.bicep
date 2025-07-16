// this template will take a pre-existing Azure Arc machine and run a PowerShell script to deploy DCSv3.
// Note that this won't install it permanently (only for the session) when deployed through a run command. It's also bad practice to install software directly from Github.
// This is just a proof of concept to show how to use the new runCommand feature in Azure Arc.
// In addition to installing DSCv3, it will also get the specified registry key and return it as output.

// Define parameters (inputs from outside the Bicep file)
param location string = 'northeurope'
param machineName string = 'DC02'

resource azureArcMachine 'Microsoft.HybridCompute/machines@2024-07-10' existing = {
  name: machineName
}

resource deploymentscript 'Microsoft.HybridCompute/machines/runCommands@2024-11-10-preview' = {
  parent: azureArcMachine
  name: 'DSCv3-GetSetDeleteReg'
  location: location
  properties: {
    source: {
      script: '''# Define the GitHub repository and the asset pattern to download
$repo = "PowerShell/DSC"
$assetPattern = "dsc-win-.*.zip"

# Get the latest release information from GitHub API
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"

$assetPattern = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64')
{
  'DSC-*-aarch64-pc-windows-msvc.zip'
}
else
{
  'DSC-*-x86_64-pc-windows-msvc.zip'
}

# Find the asset that matches the pattern
$asset = $release.assets | Where-Object { $_.name -like $assetPattern }

if ($asset)
{
  # Download the asset
  $assetUrl = $asset.browser_download_url
  $downloadPath = Join-Path -Path $env:TEMP -ChildPath $asset.name
  Invoke-RestMethod -Uri $assetUrl -OutFile $downloadPath

  # Define the extraction path
  $extractPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'dsc'

  # Create the extraction directory if it doesn't exist
  if (-not (Test-Path -Path $extractPath)) {
    New-Item -ItemType Directory -Path $extractPath
  }

  # Extract the downloaded zip file
  if (Get-Command -Name 'Expand-Archive')
  {
    Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
  }
  else 
  {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($downloadPath, $extractPath)
  }

  # Clean up the downloaded zip file
  Remove-Item -Path $downloadPath -ErrorAction SilentlyContinue

  # Unblock all files
  Get-ChildItem -Path $extractPath -Recurse | Unblock-File

  # Add to PATH
  $env:PATH += ";$extractPath"

  # Verify the installation
  dsc --version

  # Get specified registry key
  dsc resource set --resource Microsoft.Windows/registry --input 'keyPath: HKLM\Software\hsg'
  dsc resource get --resource Microsoft.Windows/registry --input 'keyPath: HKLM\Software\hsg'
  dsc resource delete --resource Microsoft.Windows/registry --input 'keyPath: HKLM\Software\hsg'
}
'''
    }
    TreatFailureAsDeploymentFailure: true
  }
}

// Output and error fields in instanceView is limited to last 4KB
// Output the result of the script
output scriptResult string = deploymentscript.properties.instanceView.output

// only display error if there is any
output scriptResulterror string = deploymentscript.properties.instanceView.error
