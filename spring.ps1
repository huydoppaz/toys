#Requires -Version 5.1
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Folder
)

$ErrorActionPreference = "Stop"
$script:Findings = [System.Collections.ArrayList]::new()
$script:Stats = @{ FilesScanned = 0; TotalFindings = 0; Critical = 0; High = 0; Medium = 0; Low = 0 }
$SeverityOrder = @{ "Critical" = 4; "High" = 3; "Medium" = 2; "Low" = 1 }

$Colors = @{
    Critical = "`e[91m"; High = "`e[93m"; Medium = "`e[96m"; Low = "`e[90m"
    Reset = "`e[0m"; Header = "`e[95m"; Info = "`e[92m"; Dim = "`e[2m"
}
if (-not $Host.UI.SupportsVirtualTerminal) {
    $Colors.Keys | ForEach-Object { $Colors[$_] = "" }
}

$Patterns = @(
    @{ Cat="SQL Injection"; Id="SQLI-001"; Sev="Critical"; Re='\$\{[^}]+\}';        Ext="*.xml";   Msg="MyBatis ${} interpolation (use #{} instead)" }
    @{ Cat="SQL Injection"; Id="SQLI-002"; Sev="High";     Re='createQuery\s*\(\s*["\x27].*\+';               Ext="*.java"; Msg="JPA createQuery() with string concatenation" }
    @{ Cat="SQL Injection"; Id="SQLI-003"; Sev="High";     Re='createNativeQuery\s*\(\s*["\x27].*\+';         Ext="*.java"; Msg="JPA createNativeQuery() with string concatenation" }
    @{ Cat="SQL Injection"; Id="SQLI-004"; Sev="Critical"; Re='Statement\s+\w+\s*=.*createStatement|\.createStatement\(\)'; Ext="*.java"; Msg="JDBC Statement used instead of PreparedStatement" }
    @{ Cat="SQL Injection"; Id="SQLI-005"; Sev="High";     Re='\.execute\(\s*["\x27].*\+|\.executeQuery\(\s*["\x27].*\+|\.executeUpdate\(\s*["\x27].*\+'; Ext="*.java"; Msg="JDBC execute with string concatenation" }
    @{ Cat="SQL Injection"; Id="SQLI-006"; Sev="High";     Re='@Query\s*\(\s*["\x27].*\+';                    Ext="*.java"; Msg="Spring @Query with string concatenation" }
    @{ Cat="SQL Injection"; Id="SQLI-007"; Sev="High";     Re='StringBuilder.*append.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)'; Ext="*.java"; Msg="SQL built via StringBuilder.append()" }
    @{ Cat="SQL Injection"; Id="SQLI-008"; Sev="High";     Re='String\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)';  Ext="*.java"; Msg="SQL built via String.format()" }
    @{ Cat="SQL Injection"; Id="SQLI-009"; Sev="Critical"; Re='SpelExpressionParser|\.parseExpression\(';      Ext="*.java"; Msg="SpEL Expression Parser - check if user input is used" }
    @{ Cat="SQL Injection"; Id="SQLI-010"; Sev="Medium";   Re='ORDER\s+BY\s.*\+|ORDER\s+BY\s.*\$';            Ext="*.java"; Msg="Dynamic ORDER BY - verify whitelist validation" }

    @{ Cat="RCE"; Id="RCE-001"; Sev="Critical"; Re='Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(';  Ext="*.java"; Msg="Runtime.exec() - OS command execution" }
    @{ Cat="RCE"; Id="RCE-002"; Sev="Critical"; Re='new\s+ProcessBuilder\s*\(';                                Ext="*.java"; Msg="ProcessBuilder - OS process creation" }
    @{ Cat="RCE"; Id="RCE-003"; Sev="Critical"; Re='ScriptEngine|ScriptEngineManager';                         Ext="*.java"; Msg="Script engine - potential code injection" }
    @{ Cat="RCE"; Id="RCE-004"; Sev="Critical"; Re='GroovyShell|GroovyScriptEngine|new\s+GroovyClassLoader';   Ext="*.java"; Msg="Groovy script execution" }
    @{ Cat="RCE"; Id="RCE-005"; Sev="High";     Re='Method\.invoke\s*\(|\.getMethod\s*\(|\.getDeclaredMethod\s*\('; Ext="*.java"; Msg="Reflection-based method invocation" }
    @{ Cat="RCE"; Id="RCE-006"; Sev="High";     Re='Class\.forName\s*\(';                                      Ext="*.java"; Msg="Dynamic class loading via Class.forName()" }
    @{ Cat="RCE"; Id="RCE-007"; Sev="Critical"; Re='new\s+Yaml\s*\(\s*\)';                                    Ext="*.java"; Msg="SnakeYAML default constructor (CVE-2022-1471)" }
    @{ Cat="RCE"; Id="RCE-008"; Sev="Critical"; Re='INIT\s*=\s*RUNSCRIPT';                                    Ext="*.java"; Msg="H2 INIT=RUNSCRIPT - RCE via JDBC" }

    @{ Cat="SSRF"; Id="SSRF-001"; Sev="High";     Re='new\s+URL\s*\(|new\s+URI\s*\(';                        Ext="*.java"; Msg="URL/URI creation - check if user-controlled" }
    @{ Cat="SSRF"; Id="SSRF-002"; Sev="High";     Re='HttpURLConnection|URLConnection|openConnection\(\)';    Ext="*.java"; Msg="HTTP connection - verify URL is not user-controlled" }
    @{ Cat="SSRF"; Id="SSRF-003"; Sev="High";     Re='RestTemplate\s*\.\s*(?:get|post|exchange|execute|put|delete|head|options|patch)For'; Ext="*.java"; Msg="RestTemplate HTTP call - verify URL" }
    @{ Cat="SSRF"; Id="SSRF-004"; Sev="High";     Re='WebClient\s*\.\s*(?:get|post|put|delete|patch|head)\s*\(|\.uri\s*\('; Ext="*.java"; Msg="WebClient HTTP call - verify URI" }
    @{ Cat="SSRF"; Id="SSRF-005"; Sev="High";     Re='HttpClient|OkHttpClient|newRequest|\.send\(';            Ext="*.java"; Msg="HTTP client - verify URL is not user-controlled" }
    @{ Cat="SSRF"; Id="SSRF-006"; Sev="Critical"; Re='ImageIO\.read\s*\(\s*(?:new\s+URL|url|uri)';            Ext="*.java"; Msg="ImageIO.read(URL) - SSRF via image processing" }
    @{ Cat="SSRF"; Id="SSRF-007"; Sev="Medium";   Re='InetAddress\.getByName\s*\(';                           Ext="*.java"; Msg="DNS resolution - check if hostname is user-controlled" }

    @{ Cat="Insecure Deserialization"; Id="DESER-001"; Sev="Critical"; Re='ObjectInputStream|readObject\s*\(';       Ext="*.java"; Msg="Java native deserialization (ObjectInputStream)" }
    @{ Cat="Insecure Deserialization"; Id="DESER-002"; Sev="Critical"; Re='XMLDecoder';                             Ext="*.java"; Msg="XMLDecoder - insecure XML deserialization" }
    @{ Cat="Insecure Deserialization"; Id="DESER-003"; Sev="High";     Re='enableDefaultTyping';                    Ext="*.java"; Msg="Jackson enableDefaultTyping() - polymorphic deserialization" }
    @{ Cat="Insecure Deserialization"; Id="DESER-004"; Sev="Critical"; Re='JSON\.parseObject\s*\(|JSON\.parse\s*\('; Ext="*.java"; Msg="Fastjson parsing - check version and autoType" }
    @{ Cat="Insecure Deserialization"; Id="DESER-005"; Sev="High";     Re='new\s+XStream|xstream\.fromXML';         Ext="*.java"; Msg="XStream deserialization - verify allowlist" }
    @{ Cat="Insecure Deserialization"; Id="DESER-006"; Sev="High";     Re='new\s+Kryo\(\)|\.readClassAndObject';    Ext="*.java"; Msg="Kryo deserialization - verify registration" }
    @{ Cat="Insecure Deserialization"; Id="DESER-007"; Sev="High";     Re='HessianInput|Hessian2Input';              Ext="*.java"; Msg="Hessian deserialization detected" }

    @{ Cat="Command Injection";   Id="CMDI-001"; Sev="Critical"; Re='exec\s*\(\s*\w+\s*\+|\.command\s*\(\s*\w+\s*\+'; Ext="*.java"; Msg="Command execution with concatenated input" }
    @{ Cat="Expression Injection";Id="EXPI-001"; Sev="Critical"; Re='ExpressionParser|\.parseExpression\s*\(\s*\w+';   Ext="*.java"; Msg="SpEL parser with dynamic expression" }
    @{ Cat="XXE";                 Id="XXE-001";  Sev="High";     Re='DocumentBuilderFactory|SAXParserFactory|XMLInputFactory'; Ext="*.java"; Msg="XML parser factory - verify DTD disabled" }
    @{ Cat="JNDI Injection";      Id="JNDI-001"; Sev="Critical"; Re='InitialContext|\.lookup\s*\(\s*\w+\s*\)';       Ext="*.java"; Msg="JNDI lookup - verify input is not user-controlled" }

    @{ Cat="Actuator Exposure"; Id="ACT-001"; Sev="Critical"; Re='management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*'; Ext="*.properties"; Msg="Actuator exposes ALL endpoints via wildcard" }
    @{ Cat="Actuator Exposure"; Id="ACT-002"; Sev="Critical"; Re='exposure:\s*\n\s+include:\s*["\x27]?\*';           Ext="*.yml"; Msg="Actuator exposes ALL endpoints via wildcard (YAML)" }
    @{ Cat="Actuator Exposure"; Id="ACT-003"; Sev="High";     Re='management\.endpoints\.web\.exposure\.include\s*[:=].*(?:env|heapdump|configprops|beans|mappings)'; Ext="*.properties"; Msg="Actuator exposes sensitive endpoints (env/heapdump/configprops/beans/mappings)" }
    @{ Cat="Actuator Exposure"; Id="ACT-004"; Sev="High";     Re='include:.*(?:env|heapdump|configprops|beans|mappings)'; Ext="*.yml"; Msg="Actuator exposes sensitive endpoints (YAML)" }
    @{ Cat="Actuator Exposure"; Id="ACT-005"; Sev="Critical"; Re='management\.security\.enabled\s*[:=]\s*false';     Ext="*.properties"; Msg="Actuator security explicitly disabled" }
    @{ Cat="Actuator Exposure"; Id="ACT-006"; Sev="Medium";   Re='management\.server\.port\s*[:=]';                 Ext="*.properties"; Msg="Actuator on separate port - verify access control" }
    @{ Cat="Actuator Exposure"; Id="ACT-007"; Sev="High";     Re='permitAll\(\).*actuator|actuator.*permitAll\(\)'; Ext="*.java"; Msg="Actuator endpoints permitted without authentication" }
    @{ Cat="Actuator Exposure"; Id="ACT-008"; Sev="High";     Re='\.requestMatchers\s*\(.*actuator.*\)\.permitAll|antMatchers\s*\(.*actuator.*\)\.permitAll'; Ext="*.java"; Msg="Actuator path permitted without auth via requestMatchers/antMatchers" }
    @{ Cat="Actuator Exposure"; Id="ACT-009"; Sev="Critical"; Re='management\.endpoints\.web\.exposure\.include\s*[:=]\s*\*|endpoints.*all.*enabled'; Ext="*.properties"; Msg="All actuator endpoints enabled and exposed" }
    @{ Cat="Actuator Exposure"; Id="ACT-010"; Sev="High";     Re='management\.endpoint\.\w+\.enabled\s*[:=]\s*true'; Ext="*.properties"; Msg="Individual actuator endpoint explicitly enabled - verify auth" }
)

function Write-Col {
    param([string]$Msg, [string]$C = "")
    if ($C -and $Colors[$C]) { Write-Host "$($Colors[$C])$Msg$($Colors.Reset)" }
    else { Write-Host $Msg }
}

function Add-Finding {
    param($File, [int]$LineNo, $LineText, $Rule, $Match)
    $rel = $File -replace [regex]::Escape($script:ResolvedRoot), "."
    $preview = $LineText.Trim()
    if ($preview.Length -gt 120) { $preview = $preview.Substring(0, 117) + "..." }

    [void]$script:Findings.Add([PSCustomObject]@{
        Category = $Rule.Cat; Id = $Rule.Id; Severity = $Rule.Sev
        File = $rel; Line = $LineNo; Code = $preview; Matched = $Match; Message = $Rule.Msg
    })
    $script:Stats.TotalFindings++
    $script:Stats[$Rule.Sev]++
}

try {
    if (-not (Test-Path $Folder)) { Write-Error "Folder not found: $Folder"; exit 1 }

    $script:ResolvedRoot = (Resolve-Path $Folder).Path
    $border = "=" * 70

    Write-Col $border "Header"
    Write-Col "  SPRING (JAVA) SECURITY AUDIT" "Header"
    Write-Col $border "Header"
    Write-Col "  Target: $($script:ResolvedRoot)" "Info"
    Write-Col "  Rules:  $($Patterns.Count) patterns (SQLi, RCE, SSRF, Deserialization, Actuator)" "Dim"
    Write-Col ""

    $idx = 0
    foreach ($rule in $Patterns) {
        $idx++
        Write-Progress -Activity "Scanning" -Status "$($rule.Cat) - $($rule.Id)" -PercentComplete ([math]::Round($idx / $Patterns.Count * 100))

        $rx = [regex]::new($rule.Re, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
        $files = Get-ChildItem -Path $script:ResolvedRoot -Recurse -Include $rule.Ext -File -ErrorAction SilentlyContinue

        foreach ($f in $files) {
            $script:Stats.FilesScanned++
            $ln = 0
            try {
                $reader = [System.IO.StreamReader]::new($f.FullName)
                while ($null -ne ($line = $reader.ReadLine())) {
                    $ln++
                    foreach ($m in $rx.Matches($line)) {
                        Add-Finding -File $f.FullName -LineNo $ln -LineText $line -Rule $rule -Match $m.Value
                    }
                }
                $reader.Close()
            } catch {}
        }
    }
    Write-Progress -Activity "Scanning" -Completed

    $deduped = $script:Findings | Sort-Object File, Line, Id -Unique
    $script:Findings = [System.Collections.ArrayList]::new($deduped)
    $script:Stats.TotalFindings = $script:Findings.Count
    $script:Stats.Critical = ($script:Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $script:Stats.High     = ($script:Findings | Where-Object { $_.Severity -eq "High" }).Count
    $script:Stats.Medium   = ($script:Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    $script:Stats.Low      = ($script:Findings | Where-Object { $_.Severity -eq "Low" }).Count
    $script:Stats.FilesScanned = (Get-ChildItem -Path $script:ResolvedRoot -Recurse -Include "*.java","*.xml","*.properties","*.yml","*.yaml" -File -ErrorAction SilentlyContinue).Count

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Col ""
    Write-Col $border "Header"
    Write-Col "  AUDIT REPORT" "Header"
    Write-Col $border "Header"
    Write-Col "  Generated:      $ts"
    Write-Col "  Files Scanned:  $($script:Stats.FilesScanned)"
    Write-Col "  Total Findings: $($script:Stats.TotalFindings)"
    Write-Col "  Critical: $($script:Stats.Critical)   High: $($script:Stats.High)   Medium: $($script:Stats.Medium)   Low: $($script:Stats.Low)"
    Write-Col ""

    if ($script:Findings.Count -eq 0) {
        Write-Col "  No vulnerabilities found." "Info"
    }
    else {
        $cats = $script:Findings | Group-Object Category | Sort-Object {
            ($_.Group | ForEach-Object { $SeverityOrder[$_.Severity] } | Measure-Object -Maximum).Maximum
        } -Descending
        foreach ($c in $cats) {
            Write-Col "[$($c.Name.ToUpper())] - $($c.Count) finding(s)" "Header"
            Write-Col ("-" * 60)
            foreach ($f in ($c.Group | Sort-Object { $SeverityOrder[$_.Severity] } -Descending)) {
                Write-Col "  $($f.Severity.PadRight(8)) $($f.Id)  $($f.Message)" $f.Severity
                Write-Col "           File: $($f.File):$($f.Line)"
                Write-Col "           Code: $($f.Code)"
                Write-Col ""
            }
        }

        Write-Col $border "Header"
        Write-Col "  RECOMMENDATIONS" "Header"
        Write-Col $border "Header"
        Write-Col ""

        if ($script:Findings | Where-Object { $_.Category -eq "SQL Injection" }) {
            Write-Col "  SQL Injection:" "High"
            Write-Col "    - Use parameterized queries (PreparedStatement, JPA named params)"
            Write-Col "    - In MyBatis, replace `${}` with `#{}`"
            Write-Col "    - For ORDER BY/LIMIT, use whitelist validation"
            Write-Col ""
        }
        if ($script:Findings | Where-Object { $_.Category -eq "RCE" }) {
            Write-Col "  RCE:" "High"
            Write-Col "    - Avoid Runtime.exec() / ProcessBuilder with user input"
            Write-Col "    - Use SafeConstructor for SnakeYAML: new Yaml(new SafeConstructor())"
            Write-Col "    - Disable SpEL with untrusted input"
            Write-Col ""
        }
        if ($script:Findings | Where-Object { $_.Category -eq "SSRF" }) {
            Write-Col "  SSRF:" "High"
            Write-Col "    - Implement URL allowlists (whitelist permitted domains/IPs)"
            Write-Col "    - Block internal IPs: 127.0.0.0/8, 10.0.0.0/8, 169.254.169.254"
            Write-Col "    - Validate URLs before HTTP calls"
            Write-Col ""
        }
        if ($script:Findings | Where-Object { $_.Category -match "Deserialization" }) {
            Write-Col "  Insecure Deserialization:" "High"
            Write-Col "    - Avoid ObjectInputStream with untrusted data"
            Write-Col "    - For Jackson: disable enableDefaultTyping()"
            Write-Col "    - For Fastjson: upgrade to >= 1.2.83 and disable autoType"
            Write-Col "    - For XStream: configure allowlist with XStream.allowTypes()"
            Write-Col ""
        }
        if ($script:Findings | Where-Object { $_.Category -eq "Actuator Exposure" }) {
            Write-Col "  Actuator Exposure:" "Critical"
            Write-Col "    - Never use management.endpoints.web.exposure.include=*"
            Write-Col "    - Expose only needed endpoints (health, info) and require auth"
            Write-Col "    - Secure actuator with Spring Security: require ROLE_ADMIN"
            Write-Col "    - Use management.server.port to isolate actuator on internal port"
            Write-Col ""
        }
    }

    Write-Col $border "Header"
    Write-Col "  END OF REPORT" "Header"
    Write-Col $border "Header"

    if ($script:Stats.Critical -gt 0) { exit 2 }
    elseif ($script:Stats.High -gt 0) { exit 1 }
    else { exit 0 }
}
catch {
    Write-Error "Audit failed: $_"
    exit 3
}
