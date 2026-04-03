@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: spring-audit ^<folder^>
    exit /b 3
)

if not exist "%~1" (
    echo ERROR: Folder not found: %~1
    exit /b 3
)

set "ROOT=%~f1"
set "TOTAL=0"
set "CRITICAL=0"
set "HIGH=0"
set "MEDIUM=0"
set "LOW=0"
set "FILECOUNT=0"
set "TMPFILE=%TEMP%\spring-audit-%RANDOM%.tmp"

for /r "%ROOT%" %%f in (*.java *.xml *.properties *.yml *.yaml) do set /a FILECOUNT+=1

echo ======================================================================
echo   SPRING (JAVA) SECURITY AUDIT
echo ======================================================================
echo   Target: %ROOT%
echo   Scanning %FILECOUNT% files for vulnerabilities...
echo.

>"%TMPFILE%" echo.

call :SCAN "SQL Injection" "Critical" "SQLI-001" "MyBatis dollar-brace" "*.xml" "$\{"
call :SCAN "SQL Injection" "High" "SQLI-002" "JPA createQuery with plus" "*.java" "createQuery.*+"
call :SCAN "SQL Injection" "High" "SQLI-003" "JPA createNativeQuery with plus" "*.java" "createNativeQuery.*+"
call :SCAN "SQL Injection" "Critical" "SQLI-004" "JDBC Statement" "*.java" "createStatement"
call :SCAN "SQL Injection" "High" "SQLI-005" "JDBC execute with plus" "*.java" "execute.*+"
call :SCAN "SQL Injection" "High" "SQLI-006" "Spring @Query with plus" "*.java" "@Query.*+"
call :SCAN "SQL Injection" "High" "SQLI-007" "StringBuilder SQL" "*.java" "StringBuilder.*append.*SELECT"
call :SCAN "SQL Injection" "High" "SQLI-008" "String.format SQL" "*.java" "String.format.*SELECT"
call :SCAN "SQL Injection" "Critical" "SQLI-009" "SpEL Expression Parser" "*.java" "SpelExpressionParser"
call :SCAN "SQL Injection" "Medium" "SQLI-010" "Dynamic ORDER BY" "*.java" "ORDER BY.*+"

call :SCAN "RCE" "Critical" "RCE-001" "Runtime.exec" "*.java" "Runtime.getRuntime.exec"
call :SCAN "RCE" "Critical" "RCE-002" "ProcessBuilder" "*.java" "ProcessBuilder"
call :SCAN "RCE" "Critical" "RCE-003" "ScriptEngine" "*.java" "ScriptEngine"
call :SCAN "RCE" "Critical" "RCE-004" "GroovyShell" "*.java" "GroovyShell"
call :SCAN "RCE" "High" "RCE-005" "Method.invoke" "*.java" "Method.invoke"
call :SCAN "RCE" "High" "RCE-006" "Class.forName" "*.java" "Class.forName"
call :SCAN "RCE" "Critical" "RCE-007" "SnakeYAML default" "*.java" "new Yaml()"
call :SCAN "RCE" "Critical" "RCE-008" "H2 INIT=RUNSCRIPT" "*.java" "INIT=.*RUNSCRIPT"

call :SCAN "SSRF" "High" "SSRF-001" "new URL" "*.java" "new URL("
call :SCAN "SSRF" "High" "SSRF-002" "HttpURLConnection" "*.java" "HttpURLConnection"
call :SCAN "SSRF" "High" "SSRF-003" "RestTemplate HTTP" "*.java" "RestTemplate.*For"
call :SCAN "SSRF" "High" "SSRF-004" "WebClient HTTP" "*.java" "WebClient.*("
call :SCAN "SSRF" "High" "SSRF-005" "HttpClient" "*.java" "HttpClient"
call :SCAN "SSRF" "Critical" "SSRF-006" "ImageIO.read URL" "*.java" "ImageIO.read"
call :SCAN "SSRF" "Medium" "SSRF-007" "InetAddress.getByName" "*.java" "InetAddress.getByName"

call :SCAN "Insecure Deserialization" "Critical" "DESER-001" "ObjectInputStream" "*.java" "ObjectInputStream"
call :SCAN "Insecure Deserialization" "Critical" "DESER-002" "XMLDecoder" "*.java" "XMLDecoder"
call :SCAN "Insecure Deserialization" "High" "DESER-003" "Jackson enableDefaultTyping" "*.java" "enableDefaultTyping"
call :SCAN "Insecure Deserialization" "Critical" "DESER-004" "Fastjson parse" "*.java" "JSON.parse"
call :SCAN "Insecure Deserialization" "High" "DESER-005" "XStream" "*.java" "XStream"
call :SCAN "Insecure Deserialization" "High" "DESER-006" "Kryo" "*.java" "Kryo"
call :SCAN "Insecure Deserialization" "High" "DESER-007" "Hessian" "*.java" "HessianInput"

call :SCAN "Command Injection" "Critical" "CMDI-001" "exec with plus" "*.java" "exec.*+"
call :SCAN "Expression Injection" "Critical" "EXPI-001" "SpEL parser" "*.java" "ExpressionParser"
call :SCAN "XXE" "High" "XXE-001" "XML parser factory" "*.java" "DocumentBuilderFactory"
call :SCAN "JNDI Injection" "Critical" "JNDI-001" "JNDI lookup" "*.java" "InitialContext.lookup"

call :SCAN "Actuator Exposure" "Critical" "ACT-001" "Actuator wildcard include" "*.properties" "include.*\*"
call :SCAN "Actuator Exposure" "Critical" "ACT-002" "Actuator wildcard YAML" "*.yml" "include.*\*"
call :SCAN "Actuator Exposure" "High" "ACT-003" "Actuator sensitive endpoints" "*.properties" "include.*env"
call :SCAN "Actuator Exposure" "High" "ACT-004" "Actuator sensitive YAML" "*.yml" "include.*env"
call :SCAN "Actuator Exposure" "Critical" "ACT-005" "Actuator security disabled" "*.properties" "security.enabled.*false"
call :SCAN "Actuator Exposure" "Medium" "ACT-006" "Actuator separate port" "*.properties" "management.server.port"
call :SCAN "Actuator Exposure" "High" "ACT-007" "Actuator permitAll" "*.java" "permitAll.*actuator"
call :SCAN "Actuator Exposure" "High" "ACT-008" "ActuatorMatchers permit" "*.java" "Matchers.*actuator.*permitAll"
call :SCAN "Actuator Exposure" "Critical" "ACT-009" "All endpoints enabled" "*.properties" "endpoints.*all.*enabled"
call :SCAN "Actuator Exposure" "High" "ACT-010" "Endpoint enabled" "*.properties" "endpoint.*enabled.*true"

set /a TOTAL=CRITICAL+HIGH+MEDIUM+LOW

echo.
echo ======================================================================
echo   AUDIT REPORT
echo ======================================================================
echo   Files Scanned:  %FILECOUNT%
echo   Total Findings: %TOTAL%
echo   Critical: %CRITICAL%   High: %HIGH%   Medium: %MEDIUM%   Low: %LOW%
echo.

if %TOTAL% EQU 0 (
    echo   No vulnerabilities found.
    goto :DONE
)

type "%TMPFILE%"

echo ======================================================================
echo   RECOMMENDATIONS
echo ======================================================================
echo.

if %CRITICAL% GTR 0 (
    echo   [!] CRITICAL findings detected. Prioritize immediate remediation.
    echo.
)
if %HIGH% GTR 0 (
    echo   [!] HIGH findings detected. Plan remediation soon.
    echo.
)

findstr /c:"SQL Injection" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   SQL Injection:
    echo     - Use parameterized queries
    echo     - In MyBatis, replace ${} with #{}
    echo     - For ORDER BY, use whitelist
    echo.
)

findstr /c:"RCE" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   RCE:
    echo     - Avoid Runtime.exec with user input
    echo     - Use SafeConstructor for SnakeYAML
    echo.
)

findstr /c:"SSRF" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   SSRF:
    echo     - Implement URL allowlists
    echo     - Block internal IPs
    echo.
)

findstr /c:"Deserialization" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   Deserialization:
    echo     - Avoid ObjectInputStream with untrusted data
    echo     - For Jackson: disable enableDefaultTyping
    echo     - For Fastjson: upgrade and disable autoType
    echo.
)

findstr /c:"Actuator" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   Actuator:
    echo     - Never use include=*
    echo     - Expose only needed endpoints
    echo.
)

:DONE
echo ======================================================================
echo   END OF REPORT
echo ======================================================================

if exist "%TMPFILE%" del "%TMPFILE%"

if %CRITICAL% GTR 0 exit /b 2
if %HIGH% GTR 0 exit /b 1
exit /b 0

:SCAN
set "CAT=%~1"
set "SEV=%~2"
set "RID=%~3"
set "MSG=%~4"
set "EXT=%~5"
set "PAT=%~6"

set "COUNT=0"

for /r "%ROOT%" %%f in (%EXT%) do (
    findstr /i /r /n /c:"%PAT%" "%%f" >nul 2>&1
    if not errorlevel 1 (
        for /f "usebackq tokens=1,* delims=:" %%a in (`findstr /i /r /n /c:"%PAT%" "%%f"`) do (
            set "LINE=%%b"
            if defined LINE (
                set "RELFILE=%%f"
                set "RELFILE=!RELFILE:%ROOT%=.!"
                set /a COUNT+=1
                set "CODE=!LINE:~0,120!"
                echo   %SEV% %RID%  %MSG% >>"%TMPFILE%"
                echo            File: !RELFILE!:%%a >>"%TMPFILE%"
                echo            Code: !CODE! >>"%TMPFILE%"
                echo. >>"%TMPFILE%"
            )
        )
    )
)

if %SEV%==Critical set /a CRITICAL+=%COUNT%
if %SEV%==High set /a HIGH+=%COUNT%
if %SEV%==Medium set /a MEDIUM+=%COUNT%
if %SEV%==Low set /a LOW+=%COUNT%

goto :eof
