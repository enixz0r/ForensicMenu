
 #########################################
## Main Menu Function, add options as needed.##
#########################################
 
## MENU options for the user to select. User MUST enter 'q' to exit from the Function ##
function Get-Menu {
    param ([string]$Title = 'Forensic Scripts')
    Clear-Host
    Write-host `n
    Write-Host -ForegroundColor  Green "================ $Title ================"
    Write-Host `n
    Write-Host -ForegroundColor DarkCyan "1: Ping Sweep Script."
    Write-Host -ForegroundColor  DarkCyan "2: File Search and Hash."
    Write-Host -ForegroundColor  DarkCyan "3: Enum Script."
    Write-Host -ForegroundColor  DarkCyan "4: Remote Host Processes."
    Write-Host -ForegroundColor  DarkCyan "5: Remote Host Connections."
    Write-Host -ForegroundColor  DarkCyan "6: Remote Host Local Users/Groups (WILL ERROR ON DC)."
    Write-Host -ForegroundColor  DarkCyan "7: Remote Host Services."
    Write-Host -ForegroundColor  DarkCyan "8: Remote Host Scheduled Tasks."
    Write-Host -ForegroundColor  DarkCyan "9: PSSession to remote host."
    Write-Host -ForegroundColor  DarkCyan "10: Kill Process on remote host."
    Write-Host -ForegroundColor  Red `n "Q: Press 'Q' to quit."
} 
 
###################################################
## Functions that will be called upon below, within DO loop ##
###################################################
 
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
        ## Run ping sweep and save to file ##
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
        ## Run ping sweep and output to screen ##
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
    $HostIPs = $HostIPs -replace '[,]',"`n"
    $creds = Get-Credential
    $date = Get-Date -Format "dd/MM/yyyy-HH:mm:ss"
    $newdate = $date.Replace('/','-').Replace(':','-')  
    
    ## Basic Enumeration Commands ##
    Switch ($basicenu) { 
        ## YES = run the following commands ##
        'Y' {
            $HostIPs | % {
                Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock {
                    Write-Output "-------------------------------------- $using:_ Machine --------------------------------------"
                    ## All ipconfig settings ##
                    Write-Output "-----IPCONFIG-----"
                    ipconfig /all
                    ## All TCP & UDP connections
                    Write-Output "`n`n-----NETSTAT-----"
                    netstat -ano
                    ## All local processes ##
                    Write-Output "`n`n-----PROCESSES-----"
                    Get-Process
                    ## All local services and states ##
                    Write-Output "`n`n-----SERVICES-----"
                    Get-Service | Select-Object Status,Name
                    ## All local user accounts & whether or not they are enabled/disabled ##
                    Write-Output "`n`n-----LOCAL USERS-----"
                    Set-Variable -Name PSversionU -Value $null
                    $PSversionU= ((Get-Host).Version).Major
                    IF ($PSversionU -gt 2) {
                        Get-LocalUser | Select-Object Name,Enabled
                    }
                    ELSE {
                        wmic useraccount list brief
                    }
                    ## Who is in the local Administrators Group ##
                    Write-Output "`n`n-----LOCAL ADMIN GROUP-----"
                    $PSversionG = ((Get-Host).Version).Major
                    IF ($PSversionG -gt 2) {
                        $LocalGroup = (Get-LocalGroup).Name
                        $LocalGroup | % {
                            Get-LocalGroupMember -Group $_
                        }
                    }
                    ELSE {
                        wmic path win32_groupuser
                    }
                    Write-Output "`n`n-----REGISTRY KEYS-----"
                    ## Creates an array containing all possible Run Key locations ##
                    Set-Variable -Name RunKeys -Value $null
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
                } | Out-File -FilePath "$env:USERPROFILE\Desktop\$newdate $_.txt"
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
                } | Out-File -Append "$env:USERPROFILE\Desktop\$newdate $_.txt"
            }
        }
        ## NO, do not run the AD enumeration commands ##
        'N' {
        }
    }
}
 
## FUNCTION 4: Kill a remote process 
Function Stop-RemoteProcess {
    Clear-Host
    Write-Host `n
    $processip=Read-Host "Please enter the host IP address"
    $THip = [string]$processip
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $THip -Force
    $processname = Read-Host "Please enter the name of the process to kill (wildcards accepted)"
    $creds = Get-Credential -Message "Please enter valid username and password"
    $processselection = Read-Host "Ending a critical process can cause the host to crash. Do you want to continue? (Y or N)"
    switch ($pingselection) {
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
 
###################################################
## Main Menu Loop which will only quit when 'q' is entered ##
###################################################
 
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
                ## IF THE FOREACH LOOP ABOVE DOES NOT WORK, THIS IS A BACKUP COMMAND YOU CAN TRY
                ## TO EXECUTE A FILE SEARCH AND A MD5 HASH OF IT
 
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
    }
    pause
}
## Press 'q' to exit the Menu and return to the PS CLI ##
until ($selection -eq 'q') 
