@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: spring-audit.bat ^<folder^>
    exit /b 3
)

if not exist "%~1" (
    echo ERROR: Folder not found: %~1
    exit /b 3
)

set "ROOT=%~f1"
set "ESC=�"
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

call :SCAN "SQL Injection" "Critical" "SQLI-001" "MyBatis ${} interpolation (use #{} instead)" "*.xml" "\$\{"
call :SCAN "SQL Injection" "High"     "SQLI-002" "JPA createQuery() with string concatenation" "*.java" "createQuery.*(\"\|').*+"
call :SCAN "SQL Injection" "High"     "SQLI-003" "JPA createNativeQuery() with string concatenation" "*.java" "createNativeQuery.*(\"\|').*+"
call :SCAN "SQL Injection" "Critical" "SQLI-004" "JDBC Statement used instead of PreparedStatement" "*.java" "createStatement"
call :SCAN "SQL Injection" "High"     "SQLI-005" "JDBC execute with string concatenation" "*.java" "\.execute.*(\"\|').*+\^|\.executeQuery.*(\"\|').*+\^|\.executeUpdate.*(\"\|').*+"
call :SCAN "SQL Injection" "High"     "SQLI-006" "Spring @Query with string concatenation" "*.java" "@Query.*(\"\|').*+"
call :SCAN "SQL Injection" "High"     "SQLI-007" "SQL built via StringBuilder.append()" "*.java" "StringBuilder.*append.*SELECT\^|StringBuilder.*append.*INSERT\^|StringBuilder.*append.*UPDATE\^|StringBuilder.*append.*DELETE\^|StringBuilder.*append.*WHERE"
call :SCAN "SQL Injection" "High"     "SQLI-008" "SQL built via String.format()" "*.java" "String\.format.*SELECT\^|String\.format.*INSERT\^|String\.format.*UPDATE\^|String\.format.*DELETE\^|String\.format.*WHERE"
call :SCAN "SQL Injection" "Critical" "SQLI-009" "SpEL Expression Parser" "*.java" "SpelExpressionParser\|\.parseExpression("
call :SCAN "SQL Injection" "Medium"   "SQLI-010" "Dynamic ORDER BY" "*.java" "ORDER.*BY.*+\^|ORDER.*BY.*\$"

call :SCAN "RCE" "Critical" "RCE-001" "Runtime.exec() - OS command execution" "*.java" "Runtime.*getRuntime.*exec("
call :SCAN "RCE" "Critical" "RCE-002" "ProcessBuilder - OS process creation" "*.java" "new.*ProcessBuilder("
call :SCAN "RCE" "Critical" "RCE-003" "Script engine - potential code injection" "*.java" "ScriptEngine\|ScriptEngineManager"
call :SCAN "RCE" "Critical" "RCE-004" "Groovy script execution" "*.java" "GroovyShell\|GroovyScriptEngine\|GroovyClassLoader"
call :SCAN "RCE" "High"     "RCE-005" "Reflection-based method invocation" "*.java" "Method\.invoke("
call :SCAN "RCE" "High"     "RCE-006" "Dynamic class loading via Class.forName()" "*.java" "Class\.forName("
call :SCAN "RCE" "Critical" "RCE-007" "SnakeYAML default constructor (CVE-2022-1471)" "*.java" "new.*Yaml()"
call :SCAN "RCE" "Critical" "RCE-008" "H2 INIT=RUNSCRIPT - RCE via JDBC" "*.java" "INIT.*=.*RUNSCRIPT"

call :SCAN "SSRF" "High"     "SSRF-001" "URL/URI creation - check if user-controlled" "*.java" "new.*URL(\|new.*URI("
call :SCAN "SSRF" "High"     "SSRF-002" "HTTP connection - verify URL" "*.java" "HttpURLConnection\|URLConnection\|openConnection()"
call :SCAN "SSRF" "High"     "SSRF-003" "RestTemplate HTTP call - verify URL" "*.java" "RestTemplate\.(get\^|post\^|exchange\^|execute\^|put\^|delete\^|head)For"
call :SCAN "SSRF" "High"     "SSRF-004" "WebClient HTTP call - verify URI" "*.java" "WebClient\.(get\^|post\^|put\^|delete\^|patch\^|head)(\^|\.uri("
call :SCAN "SSRF" "High"     "SSRF-005" "HTTP client - verify URL" "*.java" "HttpClient\^|OkHttpClient\^|newRequest\^|\.send("
call :SCAN "SSRF" "Critical" "SSRF-006" "ImageIO.read(URL) - SSRF via image processing" "*.java" "ImageIO\.read("
call :SCAN "SSRF" "Medium"   "SSRF-007" "DNS resolution - check hostname" "*.java" "InetAddress\.getByName("

call :SCAN "Insecure Deserialization" "Critical" "DESER-001" "Java native deserialization (ObjectInputStream)" "*.java" "ObjectInputStream\|readObject("
call :SCAN "Insecure Deserialization" "Critical" "DESER-002" "XMLDecoder - insecure XML deserialization" "*.java" "XMLDecoder"
call :SCAN "Insecure Deserialization" "High"     "DESER-003" "Jackson enableDefaultTyping()" "*.java" "enableDefaultTyping"
call :SCAN "Insecure Deserialization" "Critical" "DESER-004" "Fastjson parsing - check version" "*.java" "JSON\.parseObject(\^|JSON\.parse("
call :SCAN "Insecure Deserialization" "High"     "DESER-005" "XStream deserialization - verify allowlist" "*.java" "new.*XStream\|xstream\.fromXML"
call :SCAN "Insecure Deserialization" "High"     "DESER-006" "Kryo deserialization - verify registration" "*.java" "new.*Kryo()\|readClassAndObject"
call :SCAN "Insecure Deserialization" "High"     "DESER-007" "Hessian deserialization detected" "*.java" "HessianInput\|Hessian2Input"

call :SCAN "Command Injection" "Critical" "CMDI-001" "Command execution with concatenated input" "*.java" "exec(.*+\^|\.command(.*+"
call :SCAN "Expression Injection" "Critical" "EXPI-001" "SpEL parser with dynamic expression" "*.java" "ExpressionParser\|\.parseExpression("
call :SCAN "XXE" "High" "XXE-001" "XML parser factory - verify DTD disabled" "*.java" "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory"
call :SCAN "JNDI Injection" "Critical" "JNDI-001" "JNDI lookup - verify input" "*.java" "InitialContext\|\.lookup("

call :SCAN "Actuator Exposure" "Critical" "ACT-001" "Actuator exposes ALL endpoints via wildcard" "*.properties" "management.endpoints.web.exposure.include.*\*"
call :SCAN "Actuator Exposure" "Critical" "ACT-002" "Actuator exposes ALL endpoints via wildcard (YAML)" "*.yml" "include.*\*"
call :SCAN "Actuator Exposure" "High"     "ACT-003" "Actuator exposes sensitive endpoints" "*.properties" "management.endpoints.web.exposure.include.*env\^|management.endpoints.web.exposure.include.*heapdump\^|management.endpoints.web.exposure.include.*configprops\^|management.endpoints.web.exposure.include.*beans\^|management.endpoints.web.exposure.include.*mappings"
call :SCAN "Actuator Exposure" "High"     "ACT-004" "Actuator sensitive endpoints (YAML)" "*.yml" "include.*env\^|include.*heapdump\^|include.*configprops\^|include.*beans\^|include.*mappings"
call :SCAN "Actuator Exposure" "Critical" "ACT-005" "Actuator security explicitly disabled" "*.properties" "management.security.enabled.*false"
call :SCAN "Actuator Exposure" "Medium"   "ACT-006" "Actuator on separate port" "*.properties" "management.server.port"
call :SCAN "Actuator Exposure" "High"     "ACT-007" "Actuator endpoints without authentication" "*.java" "permitAll().*actuator\|actuator.*permitAll()"
call :SCAN "Actuator Exposure" "High"     "ACT-008" "Actuator path permitted without auth" "*.java" "requestMatchers.*actuator.*permitAll\|antMatchers.*actuator.*permitAll"
call :SCAN "Actuator Exposure" "Critical" "ACT-009" "All actuator endpoints enabled" "*.properties" "endpoints.*all.*enabled"
call :SCAN "Actuator Exposure" "High"     "ACT-010" "Individual actuator endpoint enabled" "*.properties" "management.endpoint.*enabled.*true"

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
    echo     - Use parameterized queries (PreparedStatement, JPA named params)
    echo     - In MyBatis, replace ${} with #{}
    echo     - For ORDER BY/LIMIT, use whitelist validation
    echo.
)

findstr /c:"RCE" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   RCE:
    echo     - Avoid Runtime.exec() / ProcessBuilder with user input
    echo     - Use SafeConstructor for SnakeYAML: new Yaml(new SafeConstructor^(^))
    echo     - Disable SpEL with untrusted input
    echo.
)

findstr /c:"SSRF" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   SSRF:
    echo     - Implement URL allowlists (whitelist permitted domains/IPs)
    echo     - Block internal IPs: 127.0.0.0/8, 10.0.0.0/8, 169.254.169.254
    echo     - Validate URLs before HTTP calls
    echo.
)

findstr /c:"Deserialization" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   Insecure Deserialization:
    echo     - Avoid ObjectInputStream with untrusted data
    echo     - For Jackson: disable enableDefaultTyping^(^)
    echo     - For Fastjson: upgrade to ^>= 1.2.83 and disable autoType
    echo     - For XStream: configure allowlist with XStream.allowTypes^(^)
    echo.
)

findstr /c:"Actuator Exposure" "%TMPFILE%" >nul 2>&1
if not errorlevel 1 (
    echo   Actuator Exposure:
    echo     - Never use management.endpoints.web.exposure.include=*
    echo     - Expose only needed endpoints (health, info) and require auth
    echo     - Secure actuator with Spring Security: require ROLE_ADMIN
    echo     - Use management.server.port to isolate actuator on internal port
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
