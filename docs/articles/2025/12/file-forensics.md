:orphan:
(file-forensics)=

# File Forensics Tools

## To determine file type

- Tool name: *file.exe*
- Tool type: CLI tool
- Tool requirements: On Windows, use *cmd.exe* without admin privileges to use *file.exe*
- Example: `file.exe sample.jpeg`

## To retrieve strings

- Tool name: *strings.exe*
- Tool type: CLI tool
- Tool requirements: On Windows, use *cmd.exe* without admin privileges to use *strings.exe*
- Example: `strings.exe sample.jpeg`
- The command results can be exported to a text file.
- Example: `strings.exe sample.jpeg > sample_strings.txt`

## To decompose MSI files

- Tool name: Orca MSI Editor
- Tool type: GUI tool
- Tool requirements: Use the tool with admin privileges to view the tables in the MSI

## To decompile JAVA executables

- Tool name: JD-GUI
- Tool type: GUI tool
- Tool requirements: Requires JAVA Runtime Environment. Use the standalone utility to decompile a JAVA executable.

## To decompile Python executables

- Tool name: *pyinstxtractor*
- Tool type: CLI tool
- Tool requirements: Requires python executable to be created using pyinstaller. Usage depends on the selected platform.
- Example: On Linux, `./pyinstxtractor sample.exe` 
  
&nbsp;
- Tool name: Pylingual
- Tool type: CLI tool
- Tool requirements: Requires python
- Example: `pylingual main.pyc`

## To analyse PDF files

- Tool name: *pdfid.py*
- Tool type: CLI tool
- Tool requirements: Requires python. Use *cmd.exe* without admin privileges to use *pdfid.py*
- Example: `python pdfid.py sample.pdf`

&nbsp;
- Tool name: *pdf-parser.py*
- Tool type: CLI tool
- Tool requirements: Requires python. Use *cmd.exe* without admin privileges to use *pdf-parser.py*
- Example: `python pdf-parser.py sample.pdf`

## To analyse RTF files

- Tool name: *rtfobj*
- Tool type: CLI tool
- Tool requirements: Requires python and the python package *oletools*. Use *cmd.exe* without admin privileges to use *rtfobj*
- Example: `rtfobj sample.rtf`

&nbsp;
- Tool name: *rtfdump.py*
- Tool type: CLI tool
- Tool requirements: Requires python. Use *cmd.exe* without admin privileges to use *rtfdump.py*
- Example: `python rtfdump.py sample.rtf`