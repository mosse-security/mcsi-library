:orphan:
(windows-forensics)=

# Windows Forensics Tools

## Shortcut Files

- Tool name: *LECmd.exe*
- Tool type: CLI tool
- Tool requirements: Use *cmd.exe* without admin privileges to use *LECmd.exe*
- Example: `LECmd.exe -f file.lnk`

## Prefetch Files

- Tool name: *PECmd.exe*
- Tool type: CLI tool
- Tool requirements: Use *cmd.exe* without admin privileges to use *PECmd.exe*
- Example: `PECmd.exe -f CMD.EXE-0BD30981.pf`

## Event Logs

- Tool name: *Event Viewer*
- Tool type: GUI tool
- View the exported event log as a saved file in *Event Viewer*

## Shadow Copies

- Tool name: *ShadowCopyView.exe*
- Tool type: GUI tool
- Installation not required. Use the standalone utility without admin privileges to view the shadow copies.

## Background Activity Monitor Registry Keys

- Tool name: *Regedit*
- Tool type: GUI tool
- Registry path: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`. Here {SID} refers to the security identifier assigned to a user.

## Amcache Hive

- Tool name: *AmcacheParser.exe*
- Tool type: CLI tool
- Tool requirements: Use *cmd.exe* with admin privileges to use *AmcacheParser.exe*. Create a folder to store the results
- Example: `AmcacheParser.exe -f C:\Windows\appcompat\Programs\Amcache.hve --csv C:\Users\thirty\Documents\AmcacheResults` 

## ActivitiesCache Database

- Tool name: *WxTCmd.exe*
- Tool type: CLI tool
- Tool requirements: Use *cmd.exe* with admin privileges to use *WxTCmd.exe*. Create a folder to store the results
- Example: `WxTCmd.exe -f C:\Users\thirty\AppData\Local\ConnectedDevicesPlatform\L.thirty\ActivitiesCache.db --csv C:\Users\thirty\Documents\ActivitiesCache-Results`

## SRUM Dump

- Tool name: *srum_dump.exe*
- Tool type: GUI tool
- No installation required. Use the standalone utility with admin privileges to parse the SRUM Database located at *C:\Windows\System32\sru\SRUDB.dat*

## Windows Registry

- Tool name: *regshot.exe*
- Tool type: GUI tool
- No installation required. Use the standalone utility without admin privileges to process the registry contents.