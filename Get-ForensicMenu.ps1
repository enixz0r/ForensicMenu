###############################################
## Main Menu Function, add options as needed.##
###############################################
 
## MENU options for the user to select. User MUST enter 'q' to exit from the Function ##
function Get-Menu {
    param ([string]$Title = 'Forensic Scripts')
    Clear-Host
    Write-host `n
    Write-Host -ForegroundColor  Green "================ $Title ================"
    Write-Host `n
    Write-Host -ForegroundColor DarkCyan "1: Ping Sweep Script."
    Write-Host -ForegroundColor DarkCyan "2: File Search and Hash."
    Write-Host -ForegroundColor DarkCyan "3: Enum Script."
    Write-Host -ForegroundColor DarkCyan "4: Remote Host Processes."
    Write-Host -ForegroundColor DarkCyan "5: Remote Host Connections."
    Write-Host -ForegroundColor DarkCyan "6: Remote Host Local Users/Groups (WILL ERROR ON DC)."
    Write-Host -ForegroundColor DarkCyan "7: Remote Host Services."
    Write-Host -ForegroundColor DarkCyan "8: Remote Host Scheduled Tasks."
    Write-Host -ForegroundColor DarkCyan "9: PSSession to remote host."
    Write-Host -ForegroundColor DarkCyan "10: Kill Process on remote host."
    Write-Host -ForegroundColor DarkCyan "11: Memory Dump on a remote host."
    Write-Host -ForegroundColor Red `n "Q: Press 'Q' to quit."
} 
 
##############################################################
## Functions that will be called upon below, within DO loop ##
##############################################################
 
## FUNCTION 1: Ping Sweep a Class C network range, with the option of outputting your results to File ##
Function Start-PingSweep {
    Clear-Host
    Write-Host `n
    $iprange=Read-Host "Please enter IP range to Scan (eg. 10.10.10 or 192.168.0)"
    $ping = new-object System.Net.NetworkInformation.Ping
 
    $pingselection = Read-Host "Would you like to save Ping Results to a file? (Y or N)"
    switch ($pingselection) {
        'Y' {
            'Your file will be saved to Your Desktop as PingResults.txt'
            'Scan Running, Please wait....'
            1..254 | % {
                $ping.send("$iprange.$_",1) |where status -eq Success| % {
                    "{0}" -f $_.Address
                }
            } | Out-File -Append -FilePath $Env:USERPROFILE\Desktop\PingResults.txt
        }
        ## Run ping sweep and output to screen ##
        'N' {
            'Your results will be displayed below'
            1..254 | % {
                $ping.send("$iprange.$_",1) |where status -eq Success | % {
                    "{0}" -f $_.Address
                }
            }
        }
    } 
} 
 
## FUNCTION 2: File Search and MD5 Hash of the file, including its Path ##
Function Get-FilePathandMD5Hash {
    Clear-Host
    Write-Host `n
    $filecheckselection = Read-Host "Is the file on a remote host? (Y or N)"
    switch ($filecheckselection) {
        ## Find file and hash, save to file ##
        'Y' {
            $remotehost = Read-Host "Please enter the remote host IP"
            $THip = [string]$remotehost
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $filename = Read-Host "Please enter the filename (eg. hack.exe)"
            $creds = Get-Credential -Message "Please enter valid username and password"
            'Scan Running, Please wait....'
            Invoke-Command -ComputerName $remotehost -Credential $creds -ScriptBlock {
                $f = (Get-ChildItem -Path "C:\" -Include "$using:filename" -Force -Recurse -ErrorAction SilentlyContinue).FullName
                Clear-Host
                Write-Host "FilePath and MD5 Results for [$using:filename]:"
                $f | % {
                    Get-FileHash -Algorithm MD5 -Path $_ | Format-List -Property Algorithm,Hash,Path
                }
            }
        } 
        ## Find file and hash, output to screen ##
        'N' {
            $filename = Read-Host "Please enter the filename (eg. hack.exe)"
            'Scan Running, Please wait....'
            $f = (Get-ChildItem -Path C:\ -Include $filename -Force -Recurse -ErrorAction SilentlyContinue).FullName
            Clear-Host
            Write-Host "FilePath and MD5 Results for [$filename]:"
            $f | % {
                Get-FileHash -Algorithm MD5 -Path $_ | Format-List -Property Algorithm,Hash,Path
            }
        } 
    }
}
 
## FUNCTION 3: Quick Enumeration script ##
Function Get-Enumeration {
 
    ## Questions for user - INPUT REQUIRED ##
    Clear-Host
    $basicenu = Read-Host 'Do you wish to identify IPCONFIG, NETSTAT, PROCESSES, SERVICES, LOCAL USERS / GROUPS & REGISTRY KEYS? (Y or N)'
    $basicenuAD = Read-Host 'Do you wish to identify ADUSERs & key DOMAIN ADMIN GROUPS? (Y or N)'
    $HostIPs = Read-Host 'List ALL remote IP addresses you wish to run this against? (Eg: 192.168.1.10,192.168.1.20)'
    $THip = [string]$HostIPs
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
    $HostIPs = $HostIPs -split '[,]'
    $creds = Get-Credential
    $date = Get-Date -Format "dd/MM/yyyy-HH:mm:ss"
    $newdate = $date.Replace('/','-').Replace(':','-')  
    
    ## Basic Enumeration Commands ##
    Switch ($basicenu) { 
        ## YES = run the following commands ##
        'Y' {
            $HostIPs | % {
                ## All ipconfig settings ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "-----IPCONFIG-----"
                    ipconfig /all
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate Ipconfig $_.txt"
                ## All TCP & UDP connections ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----NETSTAT-----"
                    netstat -ano
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate Netstat $_.txt"
                ## All local processes ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----PROCESSES-----"
                    Get-Process
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate Processes $_.txt"
                ## All local services and states ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----SERVICES-----"
                    Get-Service | Select-Object Status,Name
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate Services $_.txt"
                ## View PowerShell History ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----PS CMD HISTORY-----"
                    Get-History | Select-Object -Property *
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate History $_.txt"
                ## All local user accounts & whether or not they are enabled/disabled ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----LOCAL USERS-----"
                    $cmd = try {
                        Get-LocalUser;$true
                    }
                    catch {
                        $false
                    }
                    IF ($cmd) {
                        Get-LocalUser | Select-Object Name,Enabled
                    }
                    ELSE {
                        wmic useraccount list brief
                    }
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate LocalUsers $_.txt"
                ## Who is in the local Administrators Group ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock { 
                    Write-Output "`n`n-----LOCAL ADMIN GROUP-----"
                    $cmd = try {
                        Get-LocalGroupMember -Name administrators;$true
                    }
                    catch {
                        $false
                    }
                    IF ($cmd) {
                        $LocalGroup = (Get-LocalGroup).Name
                        $LocalGroup | % {
                            Get-LocalGroupMember -Group $_
                        }
                    }
                    ELSE {
                        wmic path win32_groupuser
                    } 
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate LocalGroup $_.txt"
                ## Common Run Key locations and there values ##
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "`n`n-----REGISTRY KEYS-----"
                    ## Creates an array containing all possible Run Key locations ##
                    $RunKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\",
                    "HKU:\.Default\Software\Microsoft\Windows\CurrentVersion\Run\",
                    "HKU:\.Default\Software\Microsoft\Windows\CurrentVersion\RunOnce\",
                    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    "HKLM:\System\CurrentControlSet\Services\",
                    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run\",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run\ "
                    ## Disable standard error output = can create problems within your Keys variable (will fill it up with RED SHIT) ##
                    $ErrorActionPreference = 'silentlycontinue'
                    $RunKeys | % {
                        echo "`n$_" ((Get-Item -Path $_) | Format-Table)
                    }
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate RegKeys $_.txt"
            } 
        }
        ## NO = do not run the basic enumeration commands ##
        'N' {
        }
    }
    Switch ($basicenuAD) {
        'Y' {
            $HostIPs | % {
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    ## Who are the Active Directory Users in the system ##
                    ## NOTE: This could be a very large output depending upon the size of the organisation ##
                    Write-Output "`n`n-----AD USERS-----"
                    Get-ADUser -Filter * | Select-Object Name,Enabled
                    ## Who are the Active Directory Administrators group ##
                    Write-Output "`n`n-----AD GRP MBR's ADMINS-----"
                    Get-ADGroupMember -Identity 'Administrators' | Select-Object name,objectClass
                    ## Who are the Active Directory Domain Administrators group ##
                    Write-Output "`n`n-----AD GRP MBR's DOMAIN ADMINS-----"
                    Get-ADGroupMember -Identity 'Domain Admins' | Select-Object name,objectClass
                    ## Who are the Active Directory Schema Administrators group ##
                    Write-Output "`n`n-----AD GRP MBR's SCHEMA ADMINS-----"
                    Get-ADGroupMember -Identity 'Schema Admins' | Select-Object name,objectClass
                    ## Who are the Active Directory Enterprise Administrators group ##
                    Write-Output "`n`n-----AD GRP MBR's ENTERPRISE ADMINS-----"
                    Get-ADGroupMember -Identity 'Enterprise Admins' | Select-Object name,objectClass
                } | Out-File -Append "$env:USERPROFILE\Desktop\$newdate AD $_.txt"
            }
        }
        ## NO, do not run the AD enumeration commands ##
        'N' {
        }
    }
}
 
## FUNCTION 4: Kill a remote process ##
Function Stop-RemoteProcess {
    Clear-Host
    Write-Host `n
    $processip=Read-Host "Please enter the host IP address"
    $THip = [string]$processip
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
    $processname = Read-Host "Please enter the name of the process to kill (wildcards accepted)"
    $creds = Get-Credential -Message "Please enter valid username and password"
    $processselection = Read-Host "Ending a critical process can cause the host to crash. Do you want to continue? (Y or N)"
    switch ($processselection) {
        'Y' {
            'Kill Process Running, See below for processes killed....'
            Invoke-Command -ComputerName $processip -Credential $creds -ScriptBlock {
                $p = Get-Process | where Name -Like "$using:processname"
                Stop-Process -InputObject $p
                Get-Process | Where-Object {
                    $_.HasExited
                }
            }
        }
        'N' {
        } 
    } 
}
 
## FUNCTION 5: Get a Memory Dump from a remote machine ##
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
 
 
 
#############################################################
## Main Menu Loop which will only quit when 'q' is entered ##
#############################################################
 
do {
    Get-Menu
    Write-Host `n
    $selection = Read-Host "Please make a selection"
    switch ($selection) {
        ## Function 1 (above) ##
        '1' {
            Clear-Host
            Start-PingSweep
        }
        ## Function 2 (above) ##
        '2' {
            Clear-Host
            Get-FilePathandMD5Hash
        }
        ## Function 3 (above) ##
        '3' {
            Clear-Host
            Get-Enumeration
        }
        ## Get all Process(es) on a remote machine ##
        '4' {
            Clear-Host
            Write-Host `n
            $hostip=Read-Host "Please enter IP of remote host"
            $THip = [string]$hostip
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $creds = Get-Credential -Message "Please enter valid Credentials"
            Invoke-Command -Credential $creds -ComputerName $hostip -ScriptBlock {
                Get-Process
            }
        }
        ## NETSTAT -ano of a remote machine ##
        '5' {
            Clear-Host
            Write-Host `n
            $hostip=Read-Host "Please enter IP of remote host"
            $THip = [string]$hostip
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $creds = Get-Credential -Message "Please enter valid Credentials"
            Invoke-Command -Credential $creds -ComputerName $hostip -ScriptBlock {
                netstat -ano
            }
        }
        ## Get Local User(s) and the MemberOf the Administrators Group (WILL NOT WORK ON DC's) ##
        '6' {
            Clear-Host
            Write-Host `n
            $hostip=Read-Host "Please enter IP of remote host"
            $THip = [string]$hostip
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $creds = Get-Credential -Message "Please enter valid Credentials"
            Invoke-Command -Credential $creds -ComputerName $hostip -ScriptBlock {
                Write-Host "------------------ Local User(s) ------------------"
                Get-LocalUser | Select-Object Name,Enabled
                Write-Host "------- Members of the Administrators Group -------"
                Get-LocalGroupMember -Group Administrators
            } 
        }
        ## Get all Service of a remote machine ##
        '7' {
            Clear-Host
            Write-Host `n
            $hostip=Read-Host "Please enter IP of remote host"
            $THip = [string]$hostip
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $creds = Get-Credential -Message "Please enter valid Credentials"
            Invoke-Command -Credential $creds -ComputerName $hostip -ScriptBlock {
                Get-Service | Select-Object Status,Name
            } 
        }
        ## Display all Scheduled Tasks, Name of Task, State of Task (READY / DISABLE), and what the Task will execute ##
        '8' {
            Clear-Host
            Write-Host `n
            $hostip=Read-Host "Please enter IP of remote host"
            $THip = [string]$hostip
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
            $creds = Get-Credential -Message "Please enter valid Credentials"
            Invoke-Command -Credential $creds -ComputerName $hostip -ScriptBlock {
                $SchTask = (Get-ScheduledTask).TaskName
                foreach($Sch in $SchTask){
                    Get-ScheduledTask -TaskName $Sch | Select-Object -Property State -ExpandProperty Actions | % {
                        $state=[string]$_.State 
                        $exec=[string]$_.Execute
                    }
                    Write-Host "----------$Sch---------- `n $state `n $exec `n"
                } 
                ## IF THE FOREACH LOOP ABOVE DOES NOT WORK, THIS IS A BACKUP COMMAND YOU CAN TRY ##
                 
                ## $SchTask | % {
                    ## Write-Host "------------- $_ -------------"
                    ## Get-ScheduledTask -TaskName $_ | Select-Object -Property State -ExpandProperty Actions | 
                    ## Select-Object -Property State,Execute | Format-Table -HideTableHeaders -AutoSize
                ## } 
            }
        }
        ## Enter a PSSession ##
        '9' {
            Clear-Host
            start powershell { -noexit
                Write-Host `n
                $hostip=Read-Host "Please enter IP of remote host"
                $THip = [string]$hostip
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
                $creds = Get-Credential -Message 'Credentials'
                Enter-PSSession -ComputerName $hostip -Credential $creds
            } 
        }
        ## Function 4 (above) ##
        '10' {
            Clear-Host
            Stop-RemoteProcess
        }
        ## Function 5 (above) ##
        '11' {
            Clear-Host
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
        }
    }
    pause
}
## Press 'q' to exit the Menu and return to the PS CLI ##
until ($selection -eq 'q') 
