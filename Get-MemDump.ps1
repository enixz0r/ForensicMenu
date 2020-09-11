## https://github.com/Velocidex/c-aff4/releases ##
## Ensure you have a copy of Memory Dump (winpmem.exe) executable stored locally before running this script ##
 
#################################################################################
## Function will do the following steps:                                       ##
## 1. Copy the Memory Dump executable to the remote machine                     ##
## 2. Run the Memory Dump command, Full memory dump in RAW format              ##
## 3. Copy the Memory Dump file (.raw) back to the locate machine              ##
## 4. Delete the Memory Dump file and executable files from the remote machine ##
#################################################################################
 
Function Get-MemDump {
    Clear-Host
    Write-Host "    Ensure you have gone to the following WebSite and downloaded the Memory Dump executable:
 
                          https://github.com/Velocidex/c-aff4/releases
                          --------------------------------------------
 
    WARNING: There will be a number of popup windows that may be in the background to PS!"
    $DumpFile = Read-Host "Enter the file path of the Memory Dump program:`nEg: C:\Users\Bob\Desktop\winpmem.exe`n`n==>"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the REMOTE MACHINE Name or IP Address - Click OK to Continue')
    $RemoteComputer = Read-Host "Enter the remote machine name or IP address you wish to run DumpIt on:`nEg: WIN8-01   OR   192.168.1.10`n`n==>"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the LOCAL MACHINE Name or IP Address - Click OK to Continue')
    $LocalComputer = Read-Host "Enter the IP address of your local machine:`n`n==>"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the credentials for the REMOTE MACHINE - Click OK to Continue')
    $RemoteCreds = Get-Credential -Message "Enter the credentials for the REMOTE MACHINE!"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the credentials for the LOCAL MACHINE - Click OK to Continue')
    $LocalCreds = Get-Credential -Message "Enter the credentials for the LOCAL MACHINE"
    
    ## If the user enters an IP addresses, add it to the TrustedHosts value ##
    IF ($RemoteComputer -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
        $THip = [string]$RemoteComputer
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
    }
    ELSE {            
    }
 
    ############################
    ## Main Script Body below ##
    ############################
    
    ## 1. Copy Memory Dump executable to remote machine via PSDrive Dump ##
    New-PSDrive -Name Dump -PSProvider FileSystem -Root "\\$RemoteComputer\c$" -Credential $RemoteCreds
    Copy-Item -Path $DumpFile -Destination Dump:

    Invoke-Command -ComputerName $RemoteComputer -Credential $RemoteCreds -ScriptBlock {
        ## 2. Run the Memory Dump executable on the remote machine ##
        cmd.exe /c "c:\winpmem.exe -o c:\1.raw --format raw"
        ## 3. Copy the RAW file back to the local machine ##
        ## If the user enters an IP addresses, add it to the TrustedHosts value ##

        IF ($using:LocalComputer -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
            $THip = [string]$using:LocalComputer
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
        }
        ELSE {            
        }

        $HomePC = New-PSSession -ComputerName $using:LocalComputer -Credential $using:LocalCreds
        Copy-Item -Path 'C:\1.raw' -Destination 'c:\' -ToSession $HomePC

        ## Remove the PSSession and process (wsmprovhost) from the remote machine ##
        Clear-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Force
        Get-PSSession | Remove-PSSession
    }
 
    ## 4. Remove ALL files from the remote machine and Clean Up ##
    Remove-Item 'Dump:\1.raw' -Force
    Remove-Item 'Dump:\winpmem.exe' -Force
    Remove-PSDrive -Name Dump -Force
    ## Return the TrustedHosts to $null ##
    Clear-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Force
}
 
###############
## Main Body ##
###############
 
## Is PSRemoting enabled of the local machine? ##
## IF it is install, run Function Get-MemDump ##
$TestIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
IF (Test-WSMan -ComputerName $TestIP -ErrorAction SilentlyContinue) {
    Get-MemDump
}
## IF PSRemoting is NOT installed, ENABLE it and run Function Get-MemDump ##
## PSRemoting will also be removed if NOT originally installed ##
ELSE {
    Enable-PSRemoting -Force
    Get-MemDump
    ## Disable PSRemoting, and rollback ALL changes from Enable-PSRemoting ##
    Disable-PSRemoting -Force
    Remove-Item -Path 'WSMan:\Localhost\listener\listener*' -Recurse
    Get-Item -Path 'WSMan:\Localhost\listener\'
    Stop-Service -Name 'WinRM' -Force
    Get-Service -Name 'WinRM' | Select-Object Name,Status | Format-List
    Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -Enabled False
    Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' | 
        Select-Object -Property DisplayName,Profile,Enabled | Format-List
}