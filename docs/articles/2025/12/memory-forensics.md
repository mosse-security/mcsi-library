:orphan:
(memory-forensics)=

# Memory Forensics Tools

This section lists the tools for memory acquisition and memory analysis.

## Memory Acquisition

- Tool name: *DumpIt.exe*
- Tool type: CLI tool
- Tool requirements: Execute the standalone utility from a USB or file share. Double click it to begin memory acquisition.

&nbsp;

- Tool name: *winpmem.exe*
- Tool type: CLI tool
- Tool requirements: Execute the standalone utility from a USB or file share. Use *cmd.exe* with admin privileges to use *winpmem.exe*, and provide a name for the acquired memory dump.

## Memory Analysis

- Tool name: *volatility 3*
- Tool type: CLI tool
- Tool requirements: Requires python 3, and the following python packages *yara-python*, *pycryptodome*, *pefile*, *capstone*.

### Process artefacts

To retrieve the list of active processes:

`python vol.py -f mem.dmp windows.pslist`

To retrieve the tree-list of the active processes:

`python vol.py -f mem.dmp windows.pstree`

To retrieve hidden and recently exited processes:

`python vol.py -f mem.dmp windows.psscan`

To dump a process executable with pid 1234 from the memory dump:

`python vol.py -f mem.dmp windows.pslist --pid 1234 --dump`

### DLLs loaded by a process

To retrieve the DLLs loaded by a process with pid 1304:

`python vol.py -f mem.dmp windows.dlllist --pid 1304`

### Handles used by a process

To retrieve the handles used by a process with pid 1604:

`python vol.py -f mem.dmp windows.handles --pid 1604`

### Networking Artefacts

To retrieve the list of active network connections:

`python vol.py -f mem.dmp windows.netstat`

To retrieve hidden and recently exited network connections:

`python vol.py -f mem.dmp windows.netscan`

### Command-line arguments

To retrieve the CLI arguments used to start a process with pid 2801:

`python vol.py -f mem.dmp windows.cmdline --pid 2801`

### Environment Variables

To retrieve the environment variables loaded by a process with pid 4152:

`python vol.py -f mem.dmp windows.envars --pid 4152`

### Dump files cached in memory by a process

To retrieve files caches in memory by a process with pid 6598 (create a directory to store the dumped files):

`python vol.py -f mem.dmp windows.dumpfiles --pid 6598`

### Registry Artefacts

To retrieve the list of registry hives in memory:

`python vol.py -f mem.dmp windows.registry.hivelist`

To retrieve all the keys in a registry hive at offset 0x8782eea9d000 (results can be piped to a text file):

`python vol.py -f mem.dmp windows.registry.printkey --offset 0x8782eea9d000 --recurse`

### Scheduled Tasks

To retrieve information about scheduled tasks from the memory dump:

`python vol.py -f mem.dmp windows.scheduled_tasks.ScheduledTasks`

### Master File Table (MFT)

To retrieve the MFT present in the memory dump:

`python vol.py -f mem.dmp windows.mftscan.MFTScan`

### Injected Code

To retrieve code injected by the process with pid 7601 into memory:

`python vol.py -f mem.dmp windows.malfind --pid 7601`
