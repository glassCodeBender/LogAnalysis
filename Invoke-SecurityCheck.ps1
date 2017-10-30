<#
.SYNOPSIS

.DESCRIPTION

Program grabs some useful security info from Windows and writes to /Documents directory

NOTE: There are some serious bugs with this program. A lot of the things it claims to query do not work!!!
The list of security event logs was put together EXTREMELY quickly so I missed some stuff.
I've barely tested the program so I would definitely not use this in a corporate environment without testing it. 

Eventually I'll revise the program so it runs the commands on remote systems also. 
#>

# To sign script use: (520-523)
# See Get-Help Set-AuthicodeSignature
# #cert = @(Get-ChildItem cert:\currentuser\My -CodeSigning)[0]

# Stores current date
$currentDate = Get-Date 

# Example:
# Get-EventLog System -Newest 10 | Format-Table Index, Time, Source, Message -Auto

# This is the main method
function Main{
# Get powershell log
Get-EventLog "Windows Powershell" | Export-Csv -Path "C:\Users\wobblywudude\Documents\pslog.csv" -Delimiter '|'
# looks for all powershell scripts on system if run out of root dir.
FindPowershellScripts
# Get files written to in last 30 days.
GetRecentlyWrittenFiles
# Check registry Run key
CheckRunKey 
# Check security events for events with specific IDs.
# NOTE: I made this list very quickly. 
CheckSecurityEvts
# returns array with critical and error events from last 24 hours System, Security and Applcation event logs
Last24HoursCritical
# Get all critical and error events in System, Security and Application event logs
Get-WinEvent -FilterHashtable @{LogName = "System"; Level = 1,2} | Export-Csv -Path "C:\Users\wobblywudude\Documents\criticalsyslog.csv" -Delimiter '|'
Get-WinEvent -FilterHashtable @{LogName = "Security"; Level = 1,2} | Export-Csv -Path "C:\Users\wobblywudude\Documents\criticalseclog.csv" -Delimiter '|'
Get-WinEvent -FilterHashtable @{LogName = "Application"; Level = 1,2} | Export-Csv -Path "C:\Users\wobblywudude\Documents\criticalapplog.csv" -Delimiter '|'

# Grab Scheduled Tasks
# schtasks | Out-File -FilePath "C:\Users\wobblywudude\Documents\schtasks.txt"
GetScheduledTasks
LogManipulations 
CountLoginsByUser
SysMonCreatedProc
FindUnusualNetUsage
UnusualServices 
RegCheck 
AutostartPrograms 
CheckProcesses 

# Check system uptime 
# $performanceCounter = CheckUptime 
CheckUpTime 

} # END Main()

function PsExecEvents{
Get-EventLog System -InstanceID 7035 | Export-CSV -Path "C:\Users\wobblywudude\Documents\psexecEvts.csv" -Delimiter '|'
Get-EventLog System -InstanceID 7036 | Export-CSV -Append "C:\Users\wobblywudude\Documents\psexecEvts.csv" -Delimiter '|'

}

function SchtaskEvents{
Get-EventLog Security -InstanceID 106 | Export-CSV -Path "C:\Users\wobblywudude\Documents\schtasksEvts.csv" -Delimiter '|'

}

function GetUsers {

# List of users 
$netUsers = net user
$admins = net localgroup administrators
$concatUsers = "List of users:`r`n`r`n" + $netUsers + "`r`n`r`nList of administrators:`r`n`r`n" + $admins 

$concatUsers | Out-File -FilePath "C:\Users\wobblywudude\Documents\userlist.txt"

}

function CheckProcesses {
$procDetails = wmic process list full| Out-File -FilePath "C:\Users\wobblywudude\Documents\processdetails.txt"
$taskWithUsers = tasklist \v | Out-File -Append "C:\Users\wobblywudude\Documents\processdetails.txt"
}# END CheckProcesses

function AutostartPrograms{
wmic startup list full | Out-File -FilePath "C:\Users\wobblywudude\Documents\autostartprograms.txt"

} # END AutostartPrograms

# Check Run Keys
function RegCheck{

$run = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
$runOnce = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
$runOnceEx = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
# Check prefetch registry values to make sure prefetch wasn't disabled. 
$prefReg = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$reg = $run + "`r`n" + $runOnce + "`r`n" + $runOnceEx + "`r`n`r`n" + $prefReg

$reg | Out-File -FilePath "C:\Users\wobblywudude\Documents\regCheck.txt"
} # END RegCheck

function UnusualServices{

# Mapping of which services run out of which process 
$runningServices = tasklist /svc | Out-File -FilePath "C:\Users\wobblywudude\Documents\services.txt"
# List of services
$netStart = net start  | Out-File -Append "C:\Users\wobblywudude\Documents\services.txt"
# $concatSvcs = "`r`nList of available services`r`n`r`n" + $netStart + "`r`n`r`nMapping of running services to processes`r`n`r`n" + $runningServices 

#$concatSvcs | Out-File -FilePath "C:\Users\wobblywudude\Documents\services.txt"
} # END UnusualServices 

function FindUnusualNetUsage{

# Look at file shares so you can check purpose
net view \\127.0.0.1 | Out-File -FilePath "C:\Users\wobblywudude\Documents\netusage.txt"
# Look at who has an open session with the machine
net session | Out-File -Append "C:\Users\wobblywudude\Documents\netusage.txt"
# Look at which sessions this machine opened with other systems.
net use | Out-File -Append "C:\Users\wobblywudude\Documents\netusage.txt"
# Find NetBIOS over TCP/IP activity
nbtstat -S | Out-File -Append "C:\Users\wobblywudude\Documents\netusage.txt"
# Find Unusual TCP and UDP Ports
netstat -naob | Out-File -Append "C:\Users\wobblywudude\Documents\netusage.txt"
netsh advfirewall show currentprofile | Out-File -Append "C:\Users\wobblywudude\Documents\netusage.txt"

# $concatNet = "File Share:`r`n`r`n" + $netView + "`r`n`r`nMembers with Open Sessions:`r`n`r`n" + $netSession + "`r`n`r`nSessions client has open with other systems:`r`n`r`n" + $netUse + "`r`n`r`nNetBIOS over TCP/IP activity`r`n`r`n" + $nbtstat + "`r`n`r`nListening TCP/UDP Ports`r`n`r`n" + $netstat + "`r`n`r`nFirewall Config:`r`n`r`n" + $firewallConfig

#$concatNet | Out-File -FilePath "C:\Users\wobblywudude\Documents\netusage.txt"

} # END FindUnusualNetUsage

function CountLoginsByUser{
Get-WinEvent @{logname="security";id=4624}|%{$_.Properties[5].Value}|Group-Object -NoElement|sort count | Out-File -FilePath "C:\Users\wobblywudude\Documents\loginByUser.txt" 
Get-WinEvent @{logname="security";id=4625}|%{$_.Properties[5].Value}|Group-Object -NoElement|sort count | Out-File -FilePath "C:\Users\wobblywudude\Documents\failedLogins.txt" 

} # END CountLoginByUser 

function LogManipulations{
# Check for cleared logs 
Get-WinEvent @{logname="security";id=1102} | Out-File -FilePath "C:\Users\wobblywudude\Documents\clearedLogs.txt"

# Determine who and when security logs were deleted. 
Get-WinEvent -FilterHashtable @{logname="security";id=4776}|%{$_.Properties[1].Value}|sort -Unique| Out-File -FilePath "C:\Users\wobblywudude\Documents\delSecLogs.txt"

### Error Code and Description ###
#C0000064 user name does not exist
#C000006A user name is correct but the password is wrong
#C0000234 user is currently locked out
#C0000072 account is currently disabled
#C000006F user tried to logon outside his day of week or time of day restrictions
#C0000070 workstation restriction
#C0000193 account expiration
#C0000071 expired password
#C0000224 user is required to change password at next logon
#C0000225 evidently a bug in Windows and not a risk

# Identify names of users with logins 
Get-WinEvent @{logname="security";id=4624} | %{$_.Properties[5].Value} | sort -Unique| Out-File -FilePath "C:\Users\wobblywudude\Documents\users.txt"

} # END LogManipulations 

function SysMonCreatedProc{
 Get-WinEvent @{logname="Microsoft-Windows-Sysmon/Operational";id=1} | %{$_.Properties[3].Value} | sort -unique| Out-File -FilePath "C:\Users\wobblywudude\Documents\sysmon.txt"

} # END SysMonCreatedProc 

# Check system performance 
function CheckUptime{
$counter = Get-Counter "\System\System Up Time"
$uptime = $counter.CounterSample[0].CookedValue

# Possible: Get-Counter -Computer $computer "\System\System Up Time"

# Get processor uptime (488-489)
# $computer = $ENV.Computername
# Get-Counter -Computer $computer "process(_total)\% processor time" 
New-TimeSpan -Seconds $uptime | Out-File -FilePath "C:\Users\wobblywudude\Documents\uptime.txt"
}

function Last24HoursCritical{
$compareDate = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName = "Application"; Level = 1,2} | Where-Object {$_.Time -lt $compareDate} | Export-Csv -Path "C:\Users\wobblywudude\Documents\critical24hrlog.csv" -Delimiter '|'
Get-WinEvent -FilterHashtable @{LogName = "System"; Level = 1,2} | Where-Object {$_.Time -lt $compareDate} | Select-Object -ExpandProperty | Export-Csv -Append "C:\Users\wobblywudude\Documents\critical24hrlog.csv" -Delimiter '|'
Get-WinEvent -FilterHashtable @{LogName = "Security"; Level = 1,2,3,4} | Where-Object {$_.Time -lt $compareDate} | Select-Object -ExpandProperty | Export-Csv -Append "C:\Users\wobblywudude\Documents\critical24hrlog.csv" -Delimiter '|'

#$arr = New-Object System.Collections.ArrayList 
#[void] $arr.Add($app)
#[void] $arr.Add($sys)
#[void] $arr.Add($sec)

}

# Checks for certain security events by ID
function CheckSecurityEvts{
[regex] $securityIdArr = "1100|1102|1108|4616|4618|4625|4649|4650|4651|4652|4653|4654|4655|4656|4657|4659|4660|4663|4670|4671|4672|4688|4690|4691|4692|4693|4697|4698|4699|4701|4702|4703|4704|4705|4706|4709|4710|4712|4713|4714|4715|4717|4716|4718|4719|4720|4722|4725|4726|4727|4728|4732|4738|4740|4741|4742|4744|4745|4746|4756|4764|4767|4771|4772|4774|4775|4777|4780|4781|4782|4790|4794|4797|4798|4816|4819|4820|4821|4822|4823|4824|4825|4830|4864|4868|4869|4870|4871|4873|4882|4884|4885|4887|4888|4895|4896|4946|4947|4948|4949|4950|4951|4952|4953|4954|4957|4958|4960|4961|4962|4963|4964|4965|4976|4977|4978|4979|4980|4981|4982|4983|4984|5024|5025|5026|5027|5028|5029|5030|5031|5032|5033|5034|5035|5037|5038|5040|5041|5042|5043|5044|5045|5046|5047|5048|5049|5050|5057|5071|5120|5121|5122|5123|5124|5126|5143|5137|5145|5148|5151|5150|5152|5155|5156|5157|5158|5159|5168|5376|5377|5378|5451|5452|5453|5456|5457|5478|5479|5480|5483|5484|5485|6144|6145|6273|6276|6277|6279|6281|6406|6418|6423|6423" # END populate security ID array

Get-WinEvent @{logname="security";id=$id} | Where-Object {$_ -match $securityIdArr}  | Export-Csv -Path "C:\Users\wobblywudude\Documents\dangerSecLog.csv" -Delimiter '|'

# Grab all logins. We can use python program to check logon types later. 
# Look for login types 3,4,8,9,10,11. Remove Types 2 and 7 
Get-EventLog Security -InstanceID 4624 | Export-CSV -Path C:\Users\wobblywudude\Documents\All_logins.csv -Delimiter '|'

Get-EventLog Security -InstanceID 4624 | Export-CSV -Path C:\Users\wobblywudude\Documents\All_logins.csv -Delimiter '|'
} ## END CheckSecurityEvts

# Get scheduled tasks
function GetScheduledTasks{

schtasks | Out-File -FilePath "C:\Users\wobblywudude\Documents\schtasks.txt"
$schtasks = schtasks | Where-Object {$_ -NotMatch "N/A"} | Where-Object {$_ -NotMatch "======"} | Where-Object{$_ -NotMatch "TaskName"} | Where-Object {$_ -NotMatch "Folder"} | Where-Object {$_ -NotMatch "Info"}
$trimmed = $schtasks | Where-Object {$_} 
$trimmed |  Out-File -FilePath "C:\Users\wobblywudude\Documents\schtasks.txt"
} # END GetScheduledTasks

# Find all files written to in last 30 days.
function GetRecentlyWrittenFiles{
$compareDate = (Get-Date).AddDays(-30)
Get-ChildItem -Recurse | Where-Object {$_.LastWriteTime -lt $compareDate} | Out-File -FilePath "C:\Users\wobblywudude\Documents\recentlyWrittenFiles.txt"

} # END GetRecentlyWrittenFiles

# Checks what programs are set in Registry Run Key
# NOTE: Not sure if this works!!
# function CheckRunKey{
#Set-Location HKCU:
#Set-Location \Software\Microsoft\Windows\CurrentVersion\Run
#return Get-ItemProperty 
#}

# Script to find powershell scripts. I might add more extensions for other programming languages later.
function FindPowershellScripts{
Get-ChildItem -Include *.ps1 -Recurse | Out-File -FilePath "C:\Users\wobblywudude\Documents\psscripts.txt"

}

. Main 
Exit 
