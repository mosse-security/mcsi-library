:orphan:
(powerup)=

# Using PowerUp to test for Windows Vulnerabilities

1. Download PowerUp.ps1 to a folder excluded from AV scanning.
<br>

2. You may need to bypass the PowerShell execution policy in order to use PowerUp.ps1. The following command can be used: `powershell -ep bypass`
<br>

3. To execute PowerUp.ps1 and retain the modules in scope, execute the script with a preceding period, like so: `. .\PowerUp.ps1`
<br>

4. Use the following cmdlet to test for Windows Vulnerabilities: `Invoke-AllChecks`