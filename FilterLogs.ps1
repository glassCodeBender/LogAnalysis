#
# Description: Program grabs some useful security info from Windows and writes to /Documents directory
#
# NOTE:
# This program is not done, it's untested, and I can't guarantee that it's actually useful. I wrote it in 2 hours.
# The list of security event logs was put together EXTREMELY quickly. I probably missed some stuff...
#
# Eventually I'll revise the program so it runs the commands on remote systems also. 
#

# Stores current date
$currentDate = Get-Date 

# Example:
# Get-EventLog System -Newest 10 | Format-Table Index, Time, Source, Message -Auto

# This is the main method
function Main{
# Get powershell log
$psLog = Get-EventLog "Windows Powershell" | ConvertTo-Csv
# looks for all powershell scripts on system if run out of root dir.
$psScripts = FindPowershellScripts
# Get files written to in last 30 days.
$recentlyWritten = GetRecentlyWrittenFiles
# Check registry Run key
$runKey = CheckRunKey 
# Check security events for events with specific IDs.
# NOTE: I made this list very quickly. 
$secEvts = CheckSecurityEvts
# returns array with critical and error events from last 24 hours System, Security and Applcation event logs
$last24Hours = Last24HoursCritical
# Get all critical and error events in System, Security and Application event logs
$criticalSystemEvt = Get-WinEvent -FilterHashtable @{LogName = "System"; Level = 1,2} | ConvertTo-Csv
$criticalSecurityEvt = Get-WinEvent -FilterHashtable @{LogName = "Security"; Level = 1,2} | ConvertTo-Csv
$criticalAppEvt = Get-WinEvent -FilterHashtable @{LogName = "Application"; Level = 1,2}| ConvertTo-Csv

# Write script results to various files. 
$criticalSystemEvt >> .\Documents\criticalsys$date.csv
$criticalSecurityEvt >> .\Documents\criticalsys$date.csv
$criticalAppEvt >> .\Documents\criticalsys$date.csv
$secEvts >> .\Documents\DANGERsecurityevents$date.csv
$last24Hours >> .\Documents\last24hourscritical$date.txt
$psLog >> .\Documents\pslog$date.txt
$runKey >> .\Documents\runkey$date.txt
$recentlyWritten >> .\Documents\recentlywritten$date.csv
$psScripts  >> .\Documents\psScripts$date.txt

} # END Main()

function Last24HoursCritical{
$compareDate = (Get-Date).AddDays(-1)
$app = Get-WinEvent -FilterHashtable @{LogName = "Application"; Level = 1,2} | Where-Object {$_.Time -lt $compareDate} | ConvertTo-Csv
$sys =  Get-WinEvent -FilterHashtable @{LogName = "System"; Level = 1,2} | Where-Object {$_.Time -lt $compareDate} | ConvertTo-Csv
$sec =  Get-WinEvent -FilterHashtable @{LogName = "Security"; Level = 1,2} | Where-Object {$_.Time -lt $compareDate} | ConvertTo-Csv
#$arr = New-Object System.Collections.ArrayList 
#[void] $arr.Add($app)
#[void] $arr.Add($sys)
#[void] $arr.Add($sec)

# concat all log files together. 
$last24 = $app + "`r`n" + $sys + "`r`n" + $sec 

return $last24
}

function CheckSecurityEvts{
$securityIdArr = @(1100,1102,11084616,4618,4625,4649,
4650,
4651,
4652,
4653,
4654,
4655,
4656,
4657,
4659,
4660,
4663,
4670,
4671,
4672,
4688,
4690,
4691,
4692,
4693,
4697,
4698,
4699,
4701,
4702,
4703,
4704,
4705,
4706,
4709,
4710,
4712,
4713,
4714,
4715,
4717,
4716,
4718,
4719,
4720,
4722,
4725,
4726,
4727,
4728,
4732,
4738,
4740,
4741,
4742,
4744,
4745,
4746,
4756,
4764,
4767,
4771,
4772,
4774,
4775,
4777,
4780,
4781,
4782,
4790,
4794,
4797,
4798,
4816,
4819,
4820,
4821,
4822,
4823,
4824,
4825,
4830,
4864,
4868,
4869,
4870,
4871,
4873,
4882,
4884,
4885,
4887,
4888,
4895,
4896,
4946,
4947,
4948,
4949,
4950,
4951,
4952,
4953,
4954,
4957,
4958,
4960,
4961,
4962,
4963,
4964,
4965,
4976,
4977,
4978,
4979,
4980,
4981,
4982,
4983,
4984,
5024,
5025,
5026,
5027,
5028,
5029,
5030,
5031,
5032,
5033,
5034,
5035,
5037,
5038,
5040,
5041,
5042,
5043,
5044,
5045,
5046,
5047,
5048,
5049,
5050,
5057,
5071,
5120,
5121,
5122,
5123,
5124,
5126,
5143,
5137,
5145,
5148,
5151,
5150,
5154,
5155,
5156,
5157,
5158,
5159,
5168,
5376,
5377,
5378,
5451,
5452,
5453,
5456,
5457,
5478,
5479,
5480,
5483,
5484,
5485,
6144,
6145,
6273,
6276,
6277,
6279,
6281,
6406,
6418,
6423,
6423
) # END populate security ID array

# Adds each item retrieved to array of strings
ForEach($id in $securityIdArr){
    $evts = @(Get-EventLog "Security" | Where-Object {_.Index -eq $id}) | ConvertTo-Csv
}
# convert Array to String object 
$holderStr = ""
$secEvents = $evts | ForEach-Object {$holderStr += "`r`n$_" }

return $secEvts
} ## END CheckSecurityEvts

# Find all files written to in last 30 days.
function GetRecentlyWrittenFiles{
$compareDate = (Get-Date).AddDays(-30)
$modBeforeDate = Get-ChildItem -Recurse | Where-Object {$_.LastWriteTime -lt $compareDate} | ConvertTo-Csv
return $modBeforeDate
}

# Checks what programs are set in Registry Run Key
# NOTE: Not sure if this works!!
function CheckRunKey{
Set-Location HKCU:
Set-Location \Software\Microsoft\Windows\CurrentVersion\Run
return Get-ItemProperty 
}

# Script to find powershell scripts. I might add more extensions for other programming languages later.
function FindPowershellScripts{
$psScripts = Get-ChildItem -Include *.ps1 -Recurse
return $psScripts
}

Main 
Exit 
