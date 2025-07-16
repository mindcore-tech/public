// this template will take a pre-existing Azure Arc machine and test the runCommand feature by running a PowerShell script that outputs the current user, working directory, and PowerShell version table.

// Define parameters (inputs from outside the Bicep file)
param location string = 'northeurope'
param machineName string = 'DC02'

resource azureArcMachine 'Microsoft.HybridCompute/machines@2024-07-10' existing = {
  name: machineName
}

resource deploymentscript 'Microsoft.HybridCompute/machines/runCommands@2024-11-10-preview' = {
  parent: azureArcMachine
  name: 'Test-RunCommand'
  location: location
  properties: {
    source: {
      script: '''whoami
pwd
$psversiontable
'''
    }
  }
}
