@echo off
:: JBASC Installer
:: Installs JBASC.java, JBASCFile.java, and jbasc.bat to C:\tools\jbasc
:: Sets JBASC_HOME and adds it to PATH

:: Target directory
set "TARGET_DIR=C:\tools\jbasc"

:: Create directory if it doesn't exist
if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%"
    echo Created directory: %TARGET_DIR%
) else (
    echo Directory already exists: %TARGET_DIR%
)

:: Copy files to target directory
echo Copying files...
copy "JBASC.java" "%TARGET_DIR%" /Y
copy "JBASCFile.java" "%TARGET_DIR%" /Y
copy "jbasc.bat" "%TARGET_DIR%" /Y

:: Set system environment variable JBASC_HOME
echo Setting JBASC_HOME...
setx JBASC_HOME "%TARGET_DIR%" /M

:: Add JBASC_HOME to system PATH if not already there
echo Updating system PATH...
:: Get current system PATH
for /f "tokens=2,*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul') do set "CurrentPath=%%B"
:: Check if JBASC_HOME is already in PATH
echo %CurrentPath% | find /I "%TARGET_DIR%" >nul
if errorlevel 1 (
    setx Path "%CurrentPath%;%TARGET_DIR%" /M
    echo Added %TARGET_DIR% to system PATH.
) else (
    echo %TARGET_DIR% already in PATH.
)

echo Installation complete.
pause