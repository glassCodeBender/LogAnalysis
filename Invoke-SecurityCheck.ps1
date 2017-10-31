<#
.SYNOPSIS

.DESCRIPTION
Program grabs some useful security info from Windows and writes to /Documents directory

NOTE: The list of security event logs was put together EXTREMELY quickly so I missed some stuff.
I've barely tested the program so I would definitely not use this in a corporate environment without testing it. 

Eventually I'll revise the program so it runs the commands on remote systems also. 
#>

# To sign script use: (520-523)
# See Get-Help Set-AuthicodeSignature
# #cert = @(Get-ChildItem cert:\currentuser\My -CodeSigning)[0]

# Stores current date
$currentDate = Get-Date 

#### IMPORTANT FOR OTHER USERS ####
# Path to the directory the program will write to. 
$pathToDir = "C:\Users\wobblywudude\Documents\"

# This is the main method
function Main{
# Get powershell log
$psPath = $pathToDir + "pslog.csv"
Get-EventLog "Windows Powershell" | Export-Csv -Path $psPath -Delimiter '|'
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
Last24Hours
# Get all critical and error events in System, Security and Application event logs
$secPath = $pathToDir + "securitylog.csv"
$appPath = $pathToDir + "applog.csv"
$sysPath = $pathToDir + "systemlog.csv"
Get-EventLog Security | Export-Csv -Path $secPath -Delimiter '|'
Get-EventLog Application | Export-Csv -Path $appPath -Delimiter '|'
Get-EventLog System | Export-Csv -Path $sysPath -Delimiter '|'

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
$psEvents = $pathToDir + "psexecEvts.csv"
Get-EventLog System -InstanceID 7035 | Export-CSV -Path $psEvents -Delimiter '|'
Get-EventLog System -InstanceID 7036 | Export-CSV -Append $psEvents -Delimiter '|'
} # END PsExecEvents

function SchtaskEvents{
$schtasksEvts = $pathToDir + "schtasksEvts.csv"
Get-EventLog Security -InstanceID 106 | Export-CSV -Path $schtasksEvts -Delimiter '|'
} # END PsExecEvents

function GetUsers {

$userList = $pathToDir + "userlist.txt"
# List of users 
$netUsers = net user
$admins = net localgroup administrators
$concatUsers = "List of users:`r`n`r`n" + $netUsers + "`r`n`r`nList of administrators:`r`n`r`n" + $admins 

$concatUsers | Out-File -FilePath $userList

} # END GetUsers

function CheckProcesses {
$procPath = $pathToDir + "processdetails.txt"
$procDetails = wmic process list full | Out-File -FilePath $procPath
$taskWithUsers = tasklist \v | Out-File -Append $procPath
} # END CheckProcesses

function AutostartPrograms{
$autostartPath = $pathToDir + "autostartprograms.txt"
wmic startup list full | Out-File -FilePath $autostartPath
} # END AutostartPrograms

# Check Run Keys
function RegCheck{

$regPath = $pathToDir + "regcheck.txt"
$run = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
$runOnce = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
$runOnceEx = reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
# Check prefetch registry values to make sure prefetch wasn't disabled. 
$prefReg = reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$reg = $run + "`r`n" + $runOnce + "`r`n" + $runOnceEx + "`r`n`r`n" + $prefReg

$reg | Out-File -FilePath $regPath
} # END RegCheck

function UnusualServices{
$svcPath = $pathToDir + "services.txt"
# Mapping of which services run out of which process 
$runningServices = tasklist /svc | Out-File -FilePath $svcPath
# List of services
$netStart = net start  | Out-File -Append $svcPath
# $concatSvcs = "`r`nList of available services`r`n`r`n" + $netStart + "`r`n`r`nMapping of running services to processes`r`n`r`n" + $runningServices 

#$concatSvcs | Out-File -FilePath "C:\Users\wobblywudude\Documents\services.txt"
} # END UnusualServices 

function FindUnusualNetUsage{
$netUsagePath = $pathToDir + "netusage.txt"
# Look at file shares so you can check purpose
$netView = net view \\127.0.0.1 | Out-File -FilePath $netUsagePath
# Look at who has an open session with the machine
$netSession = net session | Out-File -Append $netUsagePath
# Look at which sessions this machine opened with other systems.
$netUse = net use | Out-File -Append $netUsagePath
# Find NetBIOS over TCP/IP activity
$nbtstat = nbtstat -S | Out-File -Append $netUsagePath
# Find Unusual TCP and UDP Ports
$netstat = netstat -naob | Out-File -Append $netUsagePath
$firewallConfig = netsh advfirewall show currentprofile | Out-File -Append $netUsagePath

} # END FindUnusualNetUsage

function CountLoginsByUser{
$loginByUserPath = $pathToDir + "loginbyuser.txt"
$failedloginsPath = $pathToDir + "failedlogins.txt"
Get-WinEvent @{logname="security";id=4624}|%{$_.Properties[5].Value}|Group-Object -NoElement|sort count | Out-File -FilePath $loginByUserPath
Get-WinEvent @{logname="security";id=4625}|%{$_.Properties[5].Value}|Group-Object -NoElement|sort count | Out-File -FilePath $failedLoginsPath

} # END CountLoginByUser 

function LogManipulations{
# Check for cleared logs 
$clearedLogs = $pathToDir + "clearedlogs.txt"
$delByUserPath = $pathToDir + "DeletedSecurityLogByUser.txt"
Get-EventLog system -InstanceId 104 | Out-File -FilePath $clearedLogs

# Determine who and when security logs were deleted. 
Get-WinEvent -FilterHashtable @{logname="system";id=104}|%{$_.Properties[1].Value}|sort -Unique| Out-File -FilePath $delByUserPath

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
# Get-WinEvent @{logname="security";id=4624} | %{$_.Properties[5].Value} | sort -Unique| Out-File -FilePath "C:\Users\wobblywudude\Documents\users.txt"

} # END LogManipulations 

function SysMonCreatedProc{
$sysmonPath = $pathToDir + "sysmon.txt"
 Get-WinEvent @{logname="Microsoft-Windows-Sysmon/Operational";id=1} | %{$_.Properties[3].Value} | sort -unique| Out-File -FilePath $sysmonPath

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
} ## END CheckUptime

function Last24Hours{
$appPath = $pathToDir + "application24hrlog.txt"
$secPath = $pathToDir + "security24hrlog.txt"
$sysPath = $pathToDir + "system24hrlog.txt"
$compareDate = (Get-Date).AddDays(-1)
Get-EventLog Application | Where-Object {$_.Time -lt $compareDate} | Export-Csv -Path $appPath -Delimiter '|'
Get-EventLog Security | Where-Object {$_.Time -lt $compareDate} | Select-Object -ExpandProperty | Export-Csv -Path $secPath -Delimiter '|'
Get-EventLog System | Where-Object {$_.Time -lt $compareDate} | Select-Object -ExpandProperty | Export-Csv -Path $sysPath -Delimiter '|'

} ## END Last24Hours

# Checks for certain security events by ID
function CheckSecurityEvts{
$secPath = $pathToDir + "dangerSecLog.csv"
$loginsPath = $pathToDir + "all_logins.csv"
[regex] $securityIdArr = "1100|1102|1108|4616|4618|4625|4649|4650|4651|4652|4653|4654|4655|4656|4657|4659|4660|4663|4670|4671|4672|4688|4690|4691|4692|4693|4697|4698|4699|4701|4702|4703|4704|4705|4706|4709|4710|4712|4713|4714|4715|4717|4716|4718|4719|4720|4722|4725|4726|4727|4728|4732|4738|4740|4741|4742|4744|4745|4746|4756|4764|4767|4771|4772|4774|4775|4777|4780|4781|4782|4790|4794|4797|4798|4816|4819|4820|4821|4822|4823|4824|4825|4830|4864|4868|4869|4870|4871|4873|4882|4884|4885|4887|4888|4895|4896|4946|4947|4948|4949|4950|4951|4952|4953|4954|4957|4958|4960|4961|4962|4963|4964|4965|4976|4977|4978|4979|4980|4981|4982|4983|4984|5024|5025|5026|5027|5028|5029|5030|5031|5032|5033|5034|5035|5037|5038|5040|5041|5042|5043|5044|5045|5046|5047|5048|5049|5050|5057|5071|5120|5121|5122|5123|5124|5126|5143|5137|5145|5148|5151|5150|5152|5155|5156|5157|5158|5159|5168|5376|5377|5378|5451|5452|5453|5456|5457|5478|5479|5480|5483|5484|5485|6144|6145|6273|6276|6277|6279|6281|6406|6418|6423|6423" # END populate security ID array

Get-WinEvent @{logname="security"}| Where-Object {$_ -match $securityIdArr}  | Export-Csv -Path $secPath -Delimiter '|'

# Grab all logins. We can use python program to check logon types later. 
# Look for login types 3,4,8,9,10,11. Remove Types 2 and 7 
Get-EventLog Security -InstanceID 4624 | Export-CSV -Path $loginsPath -Delimiter '|'

} ## END CheckSecurityEvts

# Get scheduled tasks
function GetScheduledTasks{
$schtasksPath = $pathToDir + "schtasks.txt"
# schtasks | Out-File -FilePath "C:\Users\wobblywudude\Documents\schtasks.txt"
$schtasks = schtasks | Where-Object {$_ -NotMatch "N/A"} | Where-Object {$_ -NotMatch "======"} | Where-Object{$_ -NotMatch "TaskName"} | Where-Object {$_ -NotMatch "Folder"} | Where-Object {$_ -NotMatch "Info"}
$trimmed = $schtasks | Where-Object {$_} 
$trimmed |  Out-File -FilePath $schtasksPath
} # END GetScheduledTasks

# Find all files written to in last 30 days.
function GetRecentlyWrittenFiles{
$recentPath = $pathToDir + "RecentlyWrittenFiles.txt"
$compareDate = (Get-Date).AddDays(-30)
Get-ChildItem -Recurse | Where-Object {$_.LastWriteTime -lt $compareDate} | Out-File -FilePath $recentPath

} # END GetRecentlyWrittenFiles

# Script to find powershell scripts. I might add more extensions for other programming languages later.
function FindPowershellScripts{
$psscriptPath = $pathToDir + "psscripts.txt"
Get-ChildItem -Include *.ps1 -Recurse | Out-File -FilePath $psscriptPath
Get-ChildItem -Include *.psm1 -Recurse | Out-File -Append $psscriptPath
Get-ChildItem -Include *.psd1 -Recurse | Out-File -Append $psscriptPath
Get-ChildItem -Include *.ps1xml -Recurse | Out-File -Append $psscriptPath
Get-ChildItem -Include *.pssc -Recurse | Out-File -Append $psscriptPath
Get-ChildItem -Include *.ps1xml -Recurse | Out-File -Append $psscriptPath
Get-ChildItem -Include *.cdxml -Recurse | Out-File -Append $psscriptPath
} # END FindPowershellScripts

. Main 
Exit 
