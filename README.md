# LogAnalysis

I believe in trust with limitations. In regard to my comment about being used, I think everyone feels that way sometimes. I've felt like I didn't have control over my life for a long time. I understand that it was important that I did not have control because I don't have a full view of what's going on. Nevertheless, I'm tired. That's why I'm reducing my social media footprint. 

WINDOWS LOG ANALYSIS 

Invoke-SecurityCheck is a script I wrote in powershell to analyze log files and grab useful security info. 

I got bored while working on the powershell program so I probably won't work on it again until I have 
a new windows computer to do forensics on.

The program does the following:

1. Grab Security, Application, and System logs for the last 30 days.
2. Looks for events involving psexec.
3. Extracts scheduled tasks and events related to scheduled tasks.
4. Looks for events correlating to deleted logs and determines which computer cleared the
logs.
5. Grabs user and administrators information.
6. Grabs processes and determines which process belongs to which user.
7. Grabs autostart programs.
8. Extracts the Run, RunOnce, RunOnceEx, and PrefetchParameters keys.
9. Prints out services running on the machine and prints a mapping of running services to
processes.
10. Prints out file shares, users with open sessions on the machine, looks at sessions the
machine opened, finds NetBIOS over TCP/IP activity, helps the user find unusual TCP and
UDP ports and prints the current Windows firewall profile.
11. Prints a count of logins by user.
12. Extracts critical and error events from the last 24 hours.
13. Grabs all files written to in the last 7 days.
14. Finds powershell scripts present on the computer.

MAC OS LOG ANALYSIS

I put together a bunch of commandline code to do Mac OS analysis. I was going to put the commands into 
a Scala program, but I don't have time to write the code at the moment. 

Powershell is super easy so, after doing a ton of research on Mac OS event log analysis, I ended up
writing a program in Powershell to supplement a class project instead.
