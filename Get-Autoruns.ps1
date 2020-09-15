## https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns ##
## Ensure you have a copy of Autorunsc  (CLI version) executable stored locally before running this script ##
 
#################################################################################
## The Function will do the following steps:                                   ##
## 1. Copy the Autorunsc executable to the remote machine                      ##
## 2. Run the Autorunsc command, output will include all NON Microsoft         ##
## 3. Copy the Autorunsc file (.csv) back to the locate machine                ##
## 4. Delete the Autorunsc .csv and executable files from the remote machine   ##
#################################################################################
 
Function Get-Autoruns {
    Clear-Host
    ## Questions, and input required from the user ##
    Write-Host "Ensure you have a copy of the Autorunsc64.exe on your Desktop
    
    Otherwise go to the following website and download a copy
    https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
    ----------------------------------------------------------------
    
    WARNING: There will be a number of popup windows that may be in the background to PS!"
    $AutorunFile = Read-Host "Enter the file path of the Autorunsc program:`nEg: C:\Users\Bob\Desktop\autorunsc64.exe`n`n==>"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the REMOTE MACHINE Name or IP Address - Click OK to Continue')
    $RemoteComputer = Read-Host "Enter the remote machine name or IP address you wish to run Autorunsc64 on:`nEg: WIN8-01   OR   192.168.1.10`n`n==>"
    Clear-Host
    [System.Windows.MessageBox]::Show('Enter the LOCAL MACHINE Name or IP Address - Click OK to Continue')
    $LocalComputer = Read-Host "Enter the IP address of your local machine:`n`n==>"
    Clear-Host
    $Input = [System.Windows.Forms.MessageBox]::Show('Does the local & remote machine have the same username/password?', 'Local / Remote Username & Password', 'YesNo')
    
    ## IF the users selects YES regarding the local and remote machines having the same credentials ##
    IF ($Input -eq 'Yes') {
        $Creds = Get-Credential
    }
    ## ELSE the users selects NO regarding the local and remote machines having the same credentials ##
    ELSE {
        Clear-Host
        [System.Windows.MessageBox]::Show('Enter the credentials for the REMOTE MACHINE - Click OK to Continue')
        $RemoteCreds = Get-Credential -Message "Enter the credentials for the REMOTE MACHINE!"
        Clear-Host
        [System.Windows.MessageBox]::Show('Enter the credentials for the LOCAL MACHINE - Click OK to Continue')
        $LocalCreds = Get-Credential -Message "Enter the credentials for the LOCAL MACHINE!"
    }

    ## If the user enters an IP addresses, add it to the TrustedHosts value ##
    IF ($RemoteComputer -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
        $THip = [string]$RemoteComputer
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
    }
    ELSE {            
    }
    ## TEST and confirm the remote machine has PowerShell v5+ ##
    IF ($Creds -ne $null) {
        $Test1 = Invoke-Command -ComputerName $RemoteComputer -Credential $Creds -ScriptBlock {($PSVersionTable).PSVersion.Major -ge 5}
    }
    ELSE {
        $Test2 = Invoke-Command -ComputerName $RemoteComputer -Credential $RemoteCreds -ScriptBlock {($PSVersionTable).PSVersion.Major -ge 5}
    }
    
    ## IF the remote machine has PowerShell v5+ ##
    IF (($Test1 -eq $true) -or ($Test2 -eq $true)) { 
        
        ############################
        ## Main Script Body below ##
        ############################
    
        ## 1. Copy Autorunsc64 executable to remote machine via PSDrive Dump ##
        New-PSDrive -Name Autorun -PSProvider FileSystem -Root "\\$RemoteComputer\c$" -Credential $RemoteCreds
        Copy-Item -Path $AutorunFile -Destination Autorun:
        
        ## IF Credentials are the SAME on the local and remote machines ##
        IF ($Input -eq 'Yes') {
            Invoke-Command -ComputerName $RemoteComputer -Credential $Creds -ScriptBlock {
                ## 2. Run the Autorunsc64 executable on the remote machine ##
                cmd.exe /c "c:\autorunsc64.exe -accepteula -a * -s -m -t -h -ct > C:\Autorunsc64-1.csv"
                ## 3. Copy the .csv file back to the local machine ##
                
                ## IF the user entered an IP addresses (Local machine), add it to the TrustedHosts value on the destination machine ##
                IF ($using:LocalComputer -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
                    $THip = [string]$using:LocalComputer
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
                }
                ## ELSE, do nothing ##
                ELSE {
                }
                
                $HomePC = New-PSSession -ComputerName $using:LocalComputer -Credential $using:Creds
                Copy-Item -Path 'C:\Autorunsc64-1.csv' -Destination 'c:\' -ToSession $HomePC
                                
                ## Remove the PSSession and process (wsmprovhost) from the remote machine ##
                Clear-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Force
                Get-PSSession | Remove-PSSession
            }
        }
        ## ELSE Credenteials are NOT the SAME on the local and remote machines ##
        ELSE {
            Invoke-Command -ComputerName $RemoteComputer -Credential $RemoteCreds -ScriptBlock {
                ## 2. Run the Autorunsc64 executable on the remote machine ##
                cmd.exe /c "c:\autorunsc64.exe -accepteula -a * -s -m -t -h -ct > C:\Autorunsc64-1.csv"
                ## 3. Copy the .csv file back to the local machine ##
                
                ## If the user entered an IP addresses (Local machine), add it to the TrustedHosts value on the destination machine ##
                IF ($using:LocalComputer -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
                    $THip = [string]$using:LocalComputer
                    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
                }
                ELSE {            
                }
                
                $HomePC = New-PSSession -ComputerName $using:LocalComputer -Credential $using:LocalCreds
                Copy-Item -Path 'C:\Autorunsc64-1.csv' -Destination 'c:\' -ToSession $HomePC
                
                ## Remove the PSSession and process (wsmprovhost) from the remote machine ##
                Clear-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Force
                Get-PSSession | Remove-PSSession
            }
        }
        ## 4. Remove ALL files from the remote machine and Clean Up ##
        Remove-Item 'Autorun:\Autorunsc64-1.csv' -Force
        Remove-Item 'Autorun:\autoruns*.exe' -Force
        Remove-PSDrive -Name Autorun -Force
        ## Return the TrustedHosts to $null ##
        Clear-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Force
    }
    ELSE {
        Clear-Host
        [System.Windows.MessageBox]::Show('The version of PowerShell remotely MUST be 5+')
    }
}

###############
## Main Body ##
###############
 
## Is PSRemoting enabled of the local machine? ##
## IF it is install, run Function Get-MemDump ##
Clear-Host
$TestIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
IF (Test-WSMan -ComputerName $TestIP -ErrorAction SilentlyContinue) {
    Get-Autoruns
}
## IF PSRemoting is NOT installed, ENABLE it and run Function Get-MemDump ##
## PSRemoting will also be removed if NOT originally installed ##
ELSE {
    Enable-PSRemoting -Force
    Get-Autoruns
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
