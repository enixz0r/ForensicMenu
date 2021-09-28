Function Get-Enumeration {
 
    <#
 
    .SYNOPSIS
    Get-Enumeration will enumerate a remote computer(s) and create a report
 
    .DESCRIPTION
    This function will query a remote computer(s) and collect information within the following areas:
    SYSTEMINFO, IPCONFIG, NETSTAT, PSTREE, SERVICES, LOCAL USERS, ADMIN GROUP, SCHEDULE TASKS, REGISTRY KEYS, and AD DS users and key admin groups.
    The results will be saved to a location of your choosing with the computers name or IP and current date as the filename:
    EG:<WIN19-01_Date_15-01-20_TIME_13-04-50.txt>
    It is recommended that this be run on a Golden image or post installation to help you identify anomalies within your environment
    down the track.
 
    KEY NOTE: If you use a computers Domain Name, YOU MUST BE LOGGED IN LOCALLY AS A USER THAT CAN PREFORM ADMINISTRATIVE ACTIONS ON THE REMOTE COMPUTER!!!
 
    .PARAMETER ComputerName
    This is the IP address or Domain name of the remote computer.
    NOTE: When using a Computer domain name, ensure you have a connection to a DNS server that can resolve its name.
    NOTE2: When using an IP address, the TrustedHosts value will be modified and returned to its previous configuration once scan(s) are completed.
 
    .PARAMETER ResultDIR
    This is the Directory path you wish to save your output to (Eg: C:\Temp)
    NOTE: DO NOT end with a back slash '\'
    A file will created with the ComputerName or IP address, as well as the current Date and Time of your host computer
 
    .PARAMETER SearchItem
    This is will ascertain what type of scan you wish to run. The options available to you are the following:
    ALL, IPconfig, LocalAdminGroup, LocalUsers, Netstat, PSTree, RegistryKeys, ScheduleTask, Services, SystemInfo
    NOTE: If the parameter is left blank, ALL search items will be set by default
 
    .PARAMETER DomainGroupInfo
    This will identify all domain users, and the group members of the 'Domain Admins', 'Scheme Admins' and 'Enterprise Admins' groups.
 
    .PARAMETER IndividualFile
    This will save all the command results into individual files.
    NOTE: Only to be used with the '-SearchItem ALL'
    NOTE2: This option will give more flexible when running 'Compare-Object' to baseline results.
 
    .EXAMPLE
    Get-Enumeration -ComputerName '10.0.0.10,10.0.0.20' -ResultDIR 'C:\'
    This example will run the Basic Enumeration on multiple remote machines (10.0.0.10 & 10.0.0.20), with the results stored in the directory C:\,
    and each commands results will be saved to one single file.
    NOTE: IP addresses will be automatically ADD and REMOVE from the TrustedHosts file when executed.
 
    .EXAMPLE
    Get-Enumeration -ComputerName 'WIN19-01' -ResultDIR 'C:\Temp' -SearchItem ALL -IndividualFile
    This example will run all the Basic Enumeration scans on a single remote machine named WIN19-01, with the results stored in the directory C:\Temp,
    and each commands results will be saved to individually named files.
 
    .EXAMPLE
    Get-Enumeration -ComputerName 'WIN16-01,10.0.0.10' -ResultsDIR 'C:\Temp' -DomainGroupInfo
    This example will only run a scan of the 'Domain Users' and the three key Domain Admin groups, with the results stored in the directory C:\Temp
 
    #>
    
    ## CmdletBinding will add all the standard PowerShell search parameters to your custom Function (Eg: Verbose, etc...). SupportsShouldProcess 
    ## will give you the switch parameters options of -WHATIF and -CONFIRM ##
    [CmdletBinding(SupportsShouldProcess)]
 
    param(
        [Parameter(Position = 0,
        Mandatory = $true,
        ValueFromPipeline = $false,
        HelpMessage = "Enter the destination computer address, seperate multiple computer names with a comma ,")]
        [ValidateNotNullorEmpty()]
        $ComputerName = '',
                
        [Parameter(Position = 1,
        Mandatory = $true,
        ValueFromPipeline = $false,
        HelpMessage = "Enter a Directory path, DO NOT end with a back slash \")]
        [ValidateNotNullorEmpty()]
        [string]$ResultDIR = '',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('ALL','IPconfig','LocalAdminGroup','LocalUsers','Netstat','PSTree','RegistryKeys','RegistryKeys','ScheduleTasks','Services','SystemInfo')]
        [string]$SearchItem = 'ALL',
 
        [Parameter(Mandatory = $false)]
        [switch]$DomainGroupInfo,
 
        [Parameter(Mandatory = $false)]
        [switch]$IndividualFile
    )
 
    ## If the user enters IP addresses, they will added to the TrustedHosts value, and asked for Credentials ##
    $OriginalTrustHost = (Get-Item WSMan:\localhost\Client\TrustedHosts).value
    IF ($ComputerName -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
        $NewTrustHost = [string]$ComputerName
        Set-Item WSMan:\localhost\Client\TrustedHosts -Concatenate -Value $NewTrustHost -Force
        $creds = Get-Credential
    }
 
 
    #########################################
    ##             Main Code               ##
    #########################################
    
    ## Split multiple computer names/IP addresses into a list format ##
    $ComputerName1 = $ComputerName -split '[,]'
 
    ## Format the date time output, Windows files will NOT accept a colon ':' within the filename ##
    $date = Get-Date -Format "dd/MM/yyyy-HH:mm:ss"
    $newdate = $date.Replace('-',' _Time_').Replace('/','-').Replace(':','-')  
   
    ## Enumeration commands run against the remote computer(s), with the results saved into individual variables named ##
    ## after the command being run ##
    $ComputerName1 | % { 
        
        ## A Warning Window will pop up if Computer Names have been used over IP addresses, as you will NOT be asked for ##
        ## credentials before executing ##
        IF ($ComputerName -match "[a-zA-Z]") {
            [System.Windows.MessageBox]::Show('
            By using Computer Names your logged in
            user account MUST have remote credential!!
            
            Click OK to Continue','WARNING','OK','Error')
        }
 
        
        ##################################################################################################################
        ## There is a basic Function called and run depending on the results of an IF (IP address) ELSE (Computer Name) ##
        ##################################################################################################################
 
 
        #############################
        ## Function for SYSTEMINFO ##
        #############################
 
        ## Retrieve the SYSTEMINFO from the remote computer(s), and place the result into $SystemInfo ##
        Function TempSystemInfo {
            ## System Information ##
            Write-Output "-----SYSTEMINFO-----"
            systeminfo
        }
 
        IF (($SearchItem -eq 'SystemInfo') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $SystemInfo = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempSystemInfo}
        }
        ELSE {
            $SystemInfo = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempSystemInfo}                
        }
        
        ###########################
        ## Function for IPCONFIG ##
        ###########################
 
        ## Retrieve the IPCONFIG from the remote computer(s), and place the result into $ipconfig ##
        Function TempIPconfig {
            ## All ipconfig settings ##
            Write-Output "-----IPCONFIG-----"
            ipconfig /all
        }
        IF (($SearchItem -eq 'IPconfig') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $IPconfig = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempIPconfig}
        }
        ELSE {
            $IPconfig = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempIPconfig}
        }
        
        ##########################
        ## Function for NETSTAT ##
        ##########################
 
        ## Retrieve the NETSTAT from the remote computer(s), and place the result into $netstat ##
        Function TempNetstat {
            ## All TCP & UDP connections
            Write-Output "`n`n-----NETSTAT-----"
            netstat -ano
        }
        IF (($SearchItem -eq 'Netstat') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $Netstat = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempNetStat}
        }
        ELSE {
            $Netstat = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempNetStat}
        }
 
        #########################
        ## Function for PSTREE ##
        #########################
 
        ## Retrieve the PSTREE from the remote computer(s), and place the result into $PSTree ##
        Function TempPSTree {
            ## All Processes in tree formatting ##
            Write-Output "`n`n-----PROCESS TREE-----"
            function Get-ProcessTree {
                [CmdletBinding()]
                param([string]$ComputerName, [int]$IndentSize = 2)
    
                $indentSize   = [Math]::Max(1, [Math]::Min(12, $indentSize))
                $computerName = ($computerName, ".")[[String]::IsNullOrEmpty($computerName)]
                $processes    = Get-WmiObject Win32_Process -ComputerName $computerName
                $pids         = $processes | select -ExpandProperty ProcessId
                $parents      = $processes | select -ExpandProperty ParentProcessId -Unique
                $liveParents  = $parents | ? { $pids -contains $_ }
                $deadParents  = Compare-Object -ReferenceObject $parents -DifferenceObject $liveParents | Select-Object -ExpandProperty InputObject
                $processByParent = $processes | Group-Object -AsHashTable ParentProcessId
    
                function Write-ProcessTree($process, [int]$level = 0) {
                    $id = $process.ProcessId
                    $parentProcessId = $process.ParentProcessId
                    $process = Get-Process -Id $id -ComputerName $computerName
                    $indent = New-Object String(' ', ($level * $indentSize))
                    $process | Add-Member NoteProperty ParentId $parentProcessId -PassThru `
                        | Add-Member NoteProperty Level $level -PassThru | Add-Member NoteProperty IndentedName "$indent$($process.Name)" -PassThru 
                    $processByParent.Item($id) | Where-Object { $_ } | % {Write-ProcessTree $_ ($level + 1)}
                }
 
                $processes | Where-Object { $_.ProcessId -ne 0 -and ($_.ProcessId -eq $_.ParentProcessId -or $deadParents -contains $_.ParentProcessId) } `
                    | % { Write-ProcessTree $_ }
            }
            Get-ProcessTree -Verbose | Select-Object -Property Id, Level, IndentedName, ParentId | Format-Table -AutoSize    
        }
        IF (($SearchItem -eq 'PSTree') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $PSTree = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempPSTree}
        }
        ELSE {
            $PSTree = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempPSTree}    
        }
 
        ###########################
        ## Function for SERVICES ##
        ###########################
 
        ## Retrieve the SERVICES from the remote computer(s), and place the result into $Services ##
        Function TempServices {
            ## All local services and states ##
            Write-Output "`n`n-----SERVICES-----"
            Get-Service | Select-Object -Property Status,Name | Format-Table -AutoSize
        }
        IF (($SearchItem -eq 'Services') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $Services = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempServices}
        }
        ELSE {
            $Services = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempServices}    
        }
        
        ##############################
        ## Function for LOCAL USERS ##
        ##############################
 
        ## Retrieve the LOCAL USERS from the remote computer(s), and place the result into $LocalUsers ##
        Function TempLocalUsers {
            ## All local user accounts & whether or not they are enabled/disabled ##
            Write-Output "`n`n-----LOCAL USERS-----"
            Get-LocalUser | Select-Object -Property Name,Enabled | Format-Table -AutoSize
        }
        IF (($SearchItem -eq 'LocalUsers') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $LocalUsers = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempLocalUsers}
        }
        ELSE {
            $LocalUsers = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempLocalUsers}    
        }
        
        #############################################
        ## Function for LOCAL ADMINISTRATORS GROUP ##
        #############################################
 
        ## Retrieve the LOCAL ADMIN GROUP from the remote computer(s), and place the result into $LocalAdminGroup ##
        Function TempLocalAdminGroup {
            ## Will prevent Red errors, if the Local Admin Group does not exist (Domain Controllers) ##
            $ErrorActionPreference = 'silentlycontinue'
 
            ## Who is in the local Administrators Group ##
            Write-Output "`n`n-----LOCAL ADMIN GROUP-----"
            Get-LocalGroupMember -Group Administrators | Select-Object -Property Name,ObjectClass | Format-Table -AutoSize
        }
        IF (($SearchItem -eq 'LocalAdminGroup') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $LocalAdminGroup = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempLocalAdminGroup}
        }
        ELSE {    
            $LocalAdminGroup = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempLocalAdminGroup}    
        }
        
        ##################################
        ## Function for SCHEDULED TAKES ##
        ##################################
 
        ## Retrieve the SCHEDULE TASKS from the remote computer(s), and place the result into $ScheduleTasks ##
        Function TempScheduleTasks {
            ## Get ALL Scheduled Tasks, and some basic information about them ##
            Write-Output "`n`n-----LOCAL SCHEDULE TASKS-----"
                Get-ScheduledTask | Select-Object -Property TaskName,TaskPath,Date,Author,Actions,Triggers,Description,State | 
                    Where-Object {$_.Author -notlike 'Microsoft*'} | Format-List
        }
        IF (($SearchItem -eq 'ScheduleTasks') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $ScheduleTasks = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempScheduleTasks}
        }
        ELSE {
            $ScheduleTasks = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempScheduleTasks}    
        }
        
        ####################################
        ## Function for REGISTRY RUN KEYS ##
        ####################################
 
        ## Retrieve the REGISTRY KEYS from the remote computer(s), and place the result into $ScheduleTasks ##
        Function TempRegistryKeys {
            ## Will prevent Red errors, if the keys below do not exist ##
            $ErrorActionPreference = 'silentlycontinue'
            
            ## Creates an array containing all possible Run Key locations ##
            Write-Output "`n`n-----REGISTRY KEYS-----"
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
            $RunKeys | ForEach {echo "`n$_" ((Get-Item -Path $_) | Format-Table)}
        }
        IF (($SearchItem -eq 'RegistryKeys') -or ($SearchItem -eq 'ALL') -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $RegistryKeys = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempRegistryKeys}
        }
        ELSE {    
            $RegistryKeys = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempRegistryKeys}    
        }
        
        ########################################################
        ## Function for AD DS USERS and ADMINISTRATIVE GROUPS ##
        ########################################################
 
        ## Retrieve the AD DS Users and Group information, and place the result into $ADDS ##
        Function TempADDS {
            
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
        }
        IF (($DomainGroupInfo -eq $true) -and ($_ -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))) {
            $ADDS = Invoke-Command -Credential $creds -ComputerName $_ -ScriptBlock ${Function:TempADDS}
        }
        ELSE {
            $ADDS = Invoke-Command -ComputerName $_ -ScriptBlock ${Function:TempADDS}    
        }
        
        ## IF the parameter option ALL is used, gather all scanned results into the variable ALL ##
        IF ($SearchItem -eq 'ALL') {
                        
            ## Create a variable (ALL) that will contain all the scan results ##
            $ALL = New-Object System.Collections.Generic.List[System.Object]
            $ALL.Add($SystemInfo)
            $ALL.Add($Ipconfig)
            $ALL.Add($Netstat)
            $ALL.Add($PSTree)
            $ALL.Add($Services)
            $ALL.Add($LocalUsers)
            $ALL.Add($LocalAdminGroup)
            $ALL.Add($ScheduleTasks)
            $ALL.Add($RegistryKeys)
            $ALL.Add($ADDS)
        }
        
 
        ###############################################
        ##     Results - Output to File Options      ##  
        ###############################################
        
        ## Individual files are NOT required, and will return results for ALL scans in the one file ##
        IF (($IndividualFile -eq $false) -and ($SearchItem -eq 'ALL')) {
            $ALL | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate ALL.txt"
        }
 
        ## Individual files required, and results will be outputted into for ALL scans ##
        IF (($IndividualFile -eq $true) -and ($SearchItem -eq 'ALL')) {
            $SystemInfo | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate SYSTEMINFO.txt"
            $Ipconfig | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate IPCONFIG.txt"
            $Netstat | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate NETSTAT.txt"
            $PSTree | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate PSTree.txt"
            $Services | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate Services.txt"
            $LocalUsers | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate LocalUsers.txt"
            $LocalAdminGroup | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate LocalAdminGroup.txt"
            $ScheduleTasks | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate ScheduleTasks.txt"
            $RegistryKeys | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate RegistryKeys.txt"
        }
 
        ## Individual file, return results for SystemInfo only ##
        IF ($SearchItem -eq 'SystemInfo') {
            $SystemInfo | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate SYSTEMINFO.txt"
        }
 
        ## Individual file, return results for IPconfig only ##
        IF ($SearchItem -eq 'IPconfig') {
            $IPconfig | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate IPCONFIG.txt"
        }
 
        ## Individual file, return results for Netstat only ##
        IF ($SearchItem -eq 'Netstat') {
            $Netstat | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate NETSTAT.txt"
        }
 
        ## Individual file, return results for PSTree only ##
        IF ($SearchItem -eq 'PSTree') {
            $PSTree | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate PSTree.txt"
        }
 
        ## Individual file, return results for Services only ##
        IF (($IndividualFile -eq ($false -or $true)) -and ($SearchItem -eq 'Services')) {
            $Services | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate Services.txt"
        }
 
        ## Individual file, return results for LocalUsers only ##
        IF ($SearchItem -eq 'LocalUsers') {
            $LocalUsers | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate LocalUsers.txt"
        }
 
        ## Individual file, return results for LocalAdminGroup only ##
        IF ($SearchItem -eq 'LocalAdminGroup') {
            $LocalAdminGroup | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate LocalAdminGroup.txt"
        }
 
        ## Individual file, return results for ScheduleTasks only ##
        IF ($SearchItem -eq 'ScheduleTasks') {
            $ScheduleTasks | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate ScheduleTasks.txt"
        }
 
        ## Individual file, return results for RegistryKeys only ##
        IF ($SearchItem -eq 'RegistryKeys') {
            $RegistryKeys | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate RegistryKeys.txt"
        }
 
        ## Individual file, return results for ADDS only ##
        IF ($DomainGroupInfo -eq $true) {
            $ADDS | Out-File -FilePath "$ResultDIR\$_ _Date_$newdate ADDS.txt"
        }
    }
        
    ## If the COMPUTERNAME variable contained IP address(es), return the TrustedHosts file to its original value ##
    IF ($ComputerName -match ("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")) {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $OriginalTrustHost -Force
    }
}
