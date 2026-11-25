#requires -Version 5.1
<#
    DNS 加速解析工具 V0.7
    ------------------------------------------------------------
    只读取 domains.txt，不再请求 GitHub520、SteamHostSync、TMM 等
    旧远程源。每个域名交给站长之家 DNS 查询页的 47 个监测节点投票，
    选择票数最高的 IPv4；通过 TCP 443 验证后生成 hosts，并：
      1. 合并写入本机系统 hosts（保留 Tailscale、其他映射和注释）；
      2. 通过 SSH 合并写入路由器 /etc/hosts。

    运行依赖：Windows PowerShell 5.1 + Node.js 22+。
    Node 只使用内置 fetch/WebSocket，不安装任何 npm 包；它负责完成
    站长之家页面要求的 WebSocket 查询，PowerShell 负责其余全部工作。
#>

[CmdletBinding()]
param(
    [string]$InputFile = '',
    [string]$OutputDir = '',
    [string]$ChinazScript = '',
    [string]$NodeExe = '',
    [ValidateRange(1, 10)]
    [int]$ChinazConcurrency = 5,
    [ValidateRange(10, 180)]
    [int]$ChinazTimeoutSec = 45,
    [ValidateRange(1, 65535)]
    [int]$Port = 443,
    [ValidateRange(200, 10000)]
    [int]$TimeoutMs = 1200,
    [ValidateRange(1, 10)]
    [int]$MaxTcpCandidates = 3,
    [ValidateRange(1, 10)]
    [int]$MaxIpsPerDomain = 3,
    [ValidateRange(0, 12)]
    [int]$CertTop = 8,
    [ValidateRange(1000, 15000)]
    [int]$CertTimeoutMs = 4000,
    [string]$SystemHostsPath = '',
    [switch]$NoSystemHosts,
    [switch]$NoFlushDns,
    [string]$RouterHost = '10.0.0.1',
    [string]$RouterUser = 'root',
    [ValidateRange(1, 65535)]
    [int]$RouterPort = 22,
    [string]$RouterHostsPath = '/etc/hosts',
    [string]$RouterSshKey = '',
    [switch]$NoRouterSync,
    [switch]$RouterFullOverwrite,
    [ValidateRange(3, 60)]
    [int]$RouterTimeoutSec = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # 旧系统不支持 TLS 1.2 时保持系统默认。
}

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}
catch {
    # 某些旧终端不允许修改编码，不影响核心功能。
}

$script:LatencyCache = @{}
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:SystemHostsMarkerStart = '# >>> DnsParse managed block >>>'
$script:SystemHostsMarkerEnd = '# <<< DnsParse managed block <<<'

function Write-Step {
    param(
        [string]$Message,
        [string]$Color = 'Gray'
    )
    Write-Host $Message -ForegroundColor $Color
}

function Get-RawDomainNameCount {
    param([string]$Path)

    $count = 0
    foreach ($raw in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        $line = $raw.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith('#') -or $line.StartsWith(';')) {
            continue
        }
        if ($line -match '^\[[^\]]+\]$') {
            continue
        }

        $commentAt = $line.IndexOf('#')
        if ($commentAt -ge 0) {
            $line = $line.Substring(0, $commentAt).Trim()
        }
        if ($line.Length -eq 0) {
            continue
        }

        $tokens = @($line -split '\s+')
        $candidates = @()
        if ($tokens.Count -ge 2 -and (Test-IPv4Text -Text $tokens[0])) {
            $candidates = @($tokens[1..($tokens.Count - 1)])
        }
        else {
            $candidates = @($tokens[0])
        }

        foreach ($token in $candidates) {
            if ($null -ne (ConvertTo-DomainName $token)) {
                $count++
            }
        }
    }

    return $count
}

function Test-IPv4Text {
    param([string]$Text)
    return ($Text -match '^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
}

function ConvertTo-DomainName {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $value = $Text.Trim().ToLowerInvariant()
    $value = $value -replace '^[a-z][a-z0-9+.-]*://', ''
    $value = ($value -split '[/?#]')[0]
    $value = $value -replace ':\d+$', ''
    $value = $value.TrimEnd('.')

    if ($value.StartsWith('*.')) {
        return $null
    }
    if ($value.Length -lt 4 -or $value.Length -gt 253) {
        return $null
    }
    if (Test-IPv4Text -Text $value) {
        return $null
    }

    # 支持中文等国际化域名，转换为 punycode 后再输出。
    try {
        $idn = New-Object System.Globalization.IdnMapping
        $value = $idn.GetAscii($value).ToLowerInvariant()
    }
    catch {
        return $null
    }

    if ($value -notmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') {
        return $null
    }

    return $value
}

function Get-DomainList {
    param([string]$Path)

    $items = New-Object 'System.Collections.Generic.List[psobject]'
    $invalid = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $section = '未分类'
    $lineNo = 0

    foreach ($raw in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        $lineNo++
        $line = $raw.Trim()

        if ($line.Length -eq 0) {
            continue
        }
        if ($line.StartsWith('#') -or $line.StartsWith(';')) {
            continue
        }

        if ($line -match '^\[([^\]]+)\]$') {
            $section = $Matches[1].Trim()
            if ($section.Length -eq 0) {
                $section = '未分类'
            }
            continue
        }

        $commentAt = $line.IndexOf('#')
        if ($commentAt -ge 0) {
            $line = $line.Substring(0, $commentAt).Trim()
        }
        if ($line.Length -eq 0) {
            continue
        }

        $tokens = @($line -split '\s+')
        $candidates = @()
        if ($tokens.Count -ge 2 -and (Test-IPv4Text -Text $tokens[0])) {
            # 兼容直接粘贴 hosts 行的情况，只取域名部分。
            $candidates = @($tokens[1..($tokens.Count - 1)])
        }
        else {
            $candidates = @($tokens[0])
        }

        foreach ($token in $candidates) {
            $domain = ConvertTo-DomainName $token
            if ($null -eq $domain) {
                $invalid.Add(('第 {0} 行: {1}' -f $lineNo, $token))
                continue
            }
            if ($seen.Add($domain)) {
                $items.Add([PSCustomObject]@{
                    Domain   = $domain
                    Category = $section
                    Line     = $lineNo
                })
            }
        }
    }

    return [PSCustomObject]@{
        Items   = $items
        Invalid = $invalid
    }
}

function Measure-TcpConnect {
    param(
        [string]$IP,
        [int]$TargetPort,
        [int]$Timeout
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $address = [System.Net.IPAddress]::Parse($IP)
        $task = $client.ConnectAsync($address, $TargetPort)
        if (-not $task.Wait($Timeout)) {
            return [PSCustomObject]@{
                Ok     = $false
                Ms     = $null
                Reason = '超时'
            }
        }

        $watch.Stop()
        if ($client.Connected) {
            return [PSCustomObject]@{
                Ok     = $true
                Ms     = [int]$watch.ElapsedMilliseconds
                Reason = ''
            }
        }

        return [PSCustomObject]@{
            Ok     = $false
            Ms     = $null
            Reason = '未连接'
        }
    }
    catch {
        $baseError = $_.Exception.GetBaseException()
        $reason = '连接错误'
        if ($baseError -is [System.Net.Sockets.SocketException]) {
            switch ($baseError.SocketErrorCode) {
                'ConnectionReset' { $reason = '连接重置' }
                'ConnectionRefused' { $reason = '拒绝连接' }
                'TimedOut' { $reason = '超时' }
                'HostUnreachable' { $reason = '主机不可达' }
                'NetworkUnreachable' { $reason = '网络不可达' }
                default { $reason = ('连接错误: {0}' -f $baseError.SocketErrorCode) }
            }
        }
        else {
            $reason = ('连接错误: {0}' -f $baseError.Message)
        }

        return [PSCustomObject]@{
            Ok     = $false
            Ms     = $null
            Reason = $reason
        }
    }
    finally {
        try {
            $client.Close()
        }
        catch {
        }
    }
}

function Get-TcpProbe {
    param(
        [string]$IP,
        [int]$TargetPort,
        [int]$Timeout
    )

    $key = '{0}:{1}' -f $IP, $TargetPort
    if ($script:LatencyCache.ContainsKey($key)) {
        return $script:LatencyCache[$key]
    }

    $measured = Measure-TcpConnect -IP $IP -TargetPort $TargetPort -Timeout $Timeout
    $value = [PSCustomObject]@{
        Ok     = [bool]$measured.Ok
        Ms     = $measured.Ms
        Reason = $measured.Reason
    }

    $script:LatencyCache[$key] = $value
    return $value
}

function Get-ProbesForIps {
    param(
        [string[]]$IPs,
        [int]$TargetPort,
        [int]$Timeout
    )

    $probes = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($ip in $IPs) {
        $probe = Get-TcpProbe -IP $ip -TargetPort $TargetPort -Timeout $Timeout
        $probes.Add([PSCustomObject]@{
            IP     = $ip
            Ok     = [bool]$probe.Ok
            Ms     = $probe.Ms
            Reason = $probe.Reason
        })
    }

    return $probes.ToArray()
}

function Write-Utf8File {
    param(
        [string]$Path,
        [string]$Content,
        [bool]$WithBom = $false
    )

    $encoding = $script:Utf8NoBom
    if ($WithBom) {
        $encoding = $script:Utf8Bom
    }

    $temporary = $Path + '.tmp'
    [System.IO.File]::WriteAllText($temporary, $Content, $encoding)

    if ([System.IO.File]::Exists($Path)) {
        [System.IO.File]::Delete($Path)
    }
    [System.IO.File]::Move($temporary, $Path)
}

function Get-BytesSha256 {
    param([object]$Bytes)

    if ($null -eq $Bytes) {
        return ''
    }
    $array = [byte[]]$Bytes
    if ($array.Length -eq 0) {
        return ''
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($array))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Read-HostsSnapshot {
    param([string]$Path)

    $result = [PSCustomObject]@{
        Exists          = $false
        Bytes           = [byte[]]@()
        Text            = ''
        Encoding        = $script:Utf8NoBom
        HasBom          = $false
        NewLine         = "`r`n"
        EndsWithNewLine = $false
        Hash            = ''
    }

    if (-not [System.IO.File]::Exists($Path)) {
        return $result
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $result.Exists = $true
    $result.Bytes = $bytes
    $result.Hash = Get-BytesSha256 -Bytes $bytes

    $encoding = $script:Utf8NoBom
    $hasBom = $false
    $offset = 0
    $text = ''

    if ($bytes.Length -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
        # UTF-32 LE BOM 必须先于 UTF-16 LE 判断。
        $encoding = [System.Text.Encoding]::UTF32
        $hasBom = $true
        $offset = 4
    }
    elseif ($bytes.Length -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
        $encoding = [System.Text.Encoding]::GetEncoding(12001)
        $hasBom = $true
        $offset = 4
    }
    elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $encoding = $script:Utf8Bom
        $hasBom = $true
        $offset = 3
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $encoding = [System.Text.Encoding]::Unicode
        $hasBom = $true
        $offset = 2
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $encoding = [System.Text.Encoding]::BigEndianUnicode
        $hasBom = $true
        $offset = 2
    }
    else {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        try {
            $text = $strictUtf8.GetString($bytes)
            $encoding = $script:Utf8NoBom
        }
        catch {
            $encoding = [System.Text.Encoding]::Default
            $text = $encoding.GetString($bytes)
        }
    }

    if ($offset -gt 0) {
        $text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset)
    }

    $result.Text = $text
    $result.Encoding = $encoding
    $result.HasBom = $hasBom
    $result.EndsWithNewLine = $text.EndsWith("`n")

    if ($text.Contains("`r`n")) {
        $result.NewLine = "`r`n"
    }
    elseif ($text.Contains("`n")) {
        $result.NewLine = "`n"
    }
    else {
        $result.NewLine = [Environment]::NewLine
    }

    return $result
}

function Get-HostsPathHash {
    param([string]$Path)

    if (-not [System.IO.File]::Exists($Path)) {
        return ''
    }
    return Get-BytesSha256 -Bytes ([System.IO.File]::ReadAllBytes($Path))
}

function Get-ManagedMappingLines {
    param([string]$Content)

    # V0.7：保留分类注释与每个域名的全部 IP 行。
    # 旧版按域名去重导致每域名只写入 1 个 IP 且丢失分类；
    # 现在按整行去重，同域名多个 IP 全部保留，# [分类] 注释一并写入管理块。
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $lines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($rawLine in ($Content -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) {
            continue
        }

        # 保留分类标题注释（# [xxx]），让管理块也带分类。
        if ($line.StartsWith('#')) {
            if ($line -match '^#\s*\[[^\]]+\]') {
                $lines.Add($line)
            }
            continue
        }

        $tokens = @($line -split '\s+')
        if ($tokens.Count -lt 2) {
            continue
        }
        if (-not (Test-IPv4Text -Text $tokens[0])) {
            continue
        }

        $domain = $tokens[1].Trim().TrimEnd('.').ToLowerInvariant()
        if ($domain.Length -eq 0) {
            continue
        }
        $mappingLine = ("{0}`t{1}" -f $tokens[0], $domain)
        # 按整行去重（IP+域名），不再按域名去重，确保同一域名多个 IP 都保留。
        if (-not $seen.Add($mappingLine)) {
            continue
        }
        $lines.Add($mappingLine)
    }

    return $lines.ToArray()
}

function Merge-HostsContent {
    param(
        [string]$Text,
        [string]$NewLine,
        [object]$ManagedDomains,
        [string[]]$MappingLines
    )

    if ([string]::IsNullOrWhiteSpace($NewLine)) {
        $NewLine = "`r`n"
    }

    $managed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $ManagedDomains) {
        foreach ($domain in $ManagedDomains) {
            $value = ([string]$domain).Trim().TrimEnd('.').ToLowerInvariant()
            if ($value.Length -gt 0) {
                [void]$managed.Add($value)
            }
        }
    }

    $rawLines = @()
    if (-not [string]::IsNullOrEmpty($Text)) {
        $rawLines = @($Text -split "`r?`n")
        if ($Text.EndsWith("`n") -and $rawLines.Count -gt 0 -and $rawLines[$rawLines.Count - 1] -eq '') {
            if ($rawLines.Count -eq 1) {
                $rawLines = @()
            }
            else {
                $rawLines = @($rawLines[0..($rawLines.Count - 2)])
            }
        }
    }

    $kept = New-Object 'System.Collections.Generic.List[string]'
    $inBlock = $false
    $unclosedBlock = $false
    $removedLines = 0
    $rewrittenLines = 0
    $preservedLines = 0

    foreach ($line in $rawLines) {
        $trimmed = $line.Trim()

        if ($trimmed -eq $script:SystemHostsMarkerStart) {
            $inBlock = $true
            continue
        }
        if ($inBlock) {
            if ($trimmed -eq $script:SystemHostsMarkerEnd) {
                $inBlock = $false
            }
            continue
        }
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            $kept.Add($line)
            $preservedLines++
            continue
        }

        $comment = ''
        $mappingText = $line
        $commentIndex = $line.IndexOf('#')
        if ($commentIndex -ge 0) {
            $comment = $line.Substring($commentIndex)
            $mappingText = $line.Substring(0, $commentIndex)
        }

        $match = [regex]::Match($mappingText, '^(\s*)(\S+)(\s+)(.+?)\s*$')
        if (-not $match.Success) {
            $kept.Add($line)
            $preservedLines++
            continue
        }

        $ipText = $match.Groups[2].Value
        $parsedIp = $null
        if (-not [System.Net.IPAddress]::TryParse($ipText, [ref]$parsedIp)) {
            $kept.Add($line)
            $preservedLines++
            continue
        }

        $hostText = $match.Groups[4].Value
        $hostNames = @($hostText -split '\s+' | Where-Object { $_.Length -gt 0 })
        if ($hostNames.Count -eq 0) {
            $kept.Add($line)
            $preservedLines++
            continue
        }

        $remaining = New-Object 'System.Collections.Generic.List[string]'
        $removedAny = $false
        foreach ($hostName in $hostNames) {
            $hostKey = $hostName.Trim().TrimEnd('.').ToLowerInvariant()
            if ($managed.Contains($hostKey)) {
                $removedAny = $true
            }
            else {
                $remaining.Add($hostName)
            }
        }

        if (-not $removedAny) {
            $kept.Add($line)
            $preservedLines++
            continue
        }

        if ($remaining.Count -eq 0) {
            $removedLines++
            if (-not [string]::IsNullOrWhiteSpace($comment)) {
                $kept.Add($comment.Trim())
            }
            continue
        }

        $rewrittenLines++
        $rewrittenLine = $match.Groups[1].Value + $ipText + "`t" + ($remaining -join ' ')
        if (-not [string]::IsNullOrWhiteSpace($comment)) {
            $rewrittenLine += ('  ' + $comment.Trim())
        }
        $kept.Add($rewrittenLine)
    }

    if ($inBlock) {
        $unclosedBlock = $true
    }

    $mapping = @($MappingLines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $output = New-Object 'System.Collections.Generic.List[string]'
    if ($mapping.Count -gt 0) {
        $output.Add($script:SystemHostsMarkerStart)
        $output.Add('# DnsParse V0.7 - auto-generated; other entries preserved')
        foreach ($mappingLine in $mapping) {
            $output.Add([string]$mappingLine)
        }
        $output.Add($script:SystemHostsMarkerEnd)

        if ($kept.Count -gt 0) {
            if ($kept[0] -ne '') {
                $output.Add('')
            }
            foreach ($keptLine in $kept) {
                $output.Add($keptLine)
            }
        }
    }
    else {
        foreach ($keptLine in $kept) {
            $output.Add($keptLine)
        }
    }

    $newText = ''
    if ($output.Count -gt 0) {
        $newText = ($output -join $NewLine) + $NewLine
    }

    # BlockCount 只统计真正的 IP 映射行（不含分类注释），与 Get-ManagedBlockCount 一致。
    $mappingLineCount = @($mapping | Where-Object {
        $value = [string]$_
        -not $value.StartsWith('#') -and -not [string]::IsNullOrWhiteSpace($value)
    }).Count

    return [PSCustomObject]@{
        Text           = $newText
        BlockCount     = $mappingLineCount
        RemovedLines   = $removedLines
        RewrittenLines = $rewrittenLines
        PreservedLines = $preservedLines
        UnclosedBlock  = $unclosedBlock
    }
}

function Test-IsAdministrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Update-SystemHosts {
    param(
        [string]$Path,
        [object]$ManagedDomains,
        [string[]]$MappingLines,
        [string]$OutputDir
    )

    $result = [PSCustomObject]@{
        Attempted      = $true
        Applied        = $false
        Skipped        = $false
        Path           = $Path
        BackupPath     = ''
        ManagedCount   = 0
        BlockCount     = 0
        RemovedLines   = 0
        RewrittenLines = 0
        PreservedLines = 0
        Attempts       = 0
        Error          = ''
        FlushAttempted = $false
        FlushOk        = $false
        FlushOutput    = ''
        FlushError     = ''
    }

    $mapping = @($MappingLines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $managed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $ManagedDomains) {
        foreach ($domain in $ManagedDomains) {
            $value = ([string]$domain).Trim().TrimEnd('.').ToLowerInvariant()
            if ($value.Length -gt 0) {
                [void]$managed.Add($value)
            }
        }
    }

    $result.ManagedCount = $managed.Count
    $result.BlockCount = $mapping.Count

    if ($mapping.Count -eq 0) {
        $result.Error = '没有可写入系统 hosts 的地址。'
        return $result
    }
    if ($managed.Count -eq 0) {
        $result.Error = '管理域名集合为空，已取消写入。'
        return $result
    }

    $tempPath = $Path + '.dnsparse.tmp'
    try {
        $parent = [System.IO.Path]::GetDirectoryName($Path)
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not [System.IO.Directory]::Exists($parent)) {
            [void][System.IO.Directory]::CreateDirectory($parent)
        }

        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $result.Attempts = $attempt
            $snapshot = Read-HostsSnapshot -Path $Path
            $merged = Merge-HostsContent -Text $snapshot.Text -NewLine $snapshot.NewLine -ManagedDomains $managed -MappingLines $mapping

            if ($merged.UnclosedBlock) {
                $result.Error = '旧的 DnsParse 管理块缺少结束标记，已取消写入。'
                return $result
            }

            if ($merged.BlockCount -eq 0) {
                $result.Error = '生成的 hosts 中没有可写入的 IP/域名条目。'
                return $result
            }

            $hashNow = Get-HostsPathHash -Path $Path
            if ($hashNow -ne $snapshot.Hash) {
                continue
            }

            # V0.7：按用户要求不再生成 hosts.backup-* 备份文件。
            [System.IO.File]::WriteAllText($tempPath, $merged.Text, $snapshot.Encoding)

            $hashBeforeReplace = Get-HostsPathHash -Path $Path
            if ($hashBeforeReplace -ne $snapshot.Hash) {
                if ([System.IO.File]::Exists($tempPath)) {
                    [System.IO.File]::Delete($tempPath)
                }
                continue
            }

            if ($snapshot.Exists) {
                try {
                    [System.IO.File]::Replace($tempPath, $Path, $null)
                }
                catch {
                    [System.IO.File]::Copy($tempPath, $Path, $true)
                    [System.IO.File]::Delete($tempPath)
                }
            }
            else {
                [System.IO.File]::Move($tempPath, $Path)
            }

            $result.Applied = $true
            $result.RemovedLines = $merged.RemovedLines
            $result.RewrittenLines = $merged.RewrittenLines
            $result.PreservedLines = $merged.PreservedLines
            $result.Error = ''
            break
        }

        if (-not $result.Applied -and [string]::IsNullOrWhiteSpace($result.Error)) {
            $result.Error = '系统 hosts 在运行期间被其他程序修改，已取消写入，请重试。'
        }
    }
    catch {
        $result.Applied = $false
        $exception = $_.Exception
        while ($null -ne $exception.InnerException -and $exception.InnerException -ne $exception) {
            $exception = $exception.InnerException
        }
        if ($exception -is [System.UnauthorizedAccessException]) {
            $result.Error = '没有权限写入系统 hosts，可能文件只读或当前不是管理员。'
        }
        else {
            $result.Error = $exception.Message
        }
        if (-not (Test-IsAdministrator)) {
            $result.Error += ' 请通过“一键解析DNS.bat”运行并同意 UAC。'
        }
        if ([System.IO.File]::Exists($tempPath)) {
            try {
                [System.IO.File]::Delete($tempPath)
            }
            catch {
                # 临时文件清理失败不影响原文件。
            }
        }
    }

    return $result
}

function Invoke-DnsFlush {
    $result = [PSCustomObject]@{
        Attempted = $true
        Ok        = $false
        Output    = ''
        Error     = ''
    }

    try {
        $exe = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
        if (-not [System.IO.File]::Exists($exe)) {
            $exe = 'ipconfig.exe'
        }
        $output = & $exe /flushdns 2>&1
        $code = 1
        if ($null -ne $LASTEXITCODE) {
            $code = $LASTEXITCODE
        }
        $result.Output = ($output | Out-String).Trim()
        $result.Ok = ($code -eq 0)
        if (-not $result.Ok) {
            $result.Error = ('ipconfig 退出码: {0}' -f $code)
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-OpenSshExe {
    param([string]$Name)

    $candidate = Join-Path $env:SystemRoot ('System32\OpenSSH\' + $Name)
    if ([System.IO.File]::Exists($candidate)) {
        return $candidate
    }
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    throw ('找不到 {0}，请确认 Windows 已安装 OpenSSH 客户端。' -f $Name)
}

function Invoke-RouterSsh {
    param([string]$Command)

    $result = [PSCustomObject]@{
        Ok       = $false
        ExitCode = 1
        Output   = ''
        Error    = ''
    }

    try {
        $ssh = Get-OpenSshExe -Name 'ssh.exe'
        $sshArgs = @(
            '-i', $RouterSshKey,
            '-p', [string]$RouterPort,
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', ('ConnectTimeout={0}' -f $RouterTimeoutSec),
            ('{0}@{1}' -f $RouterUser, $RouterHost),
            $Command
        )
        $output = & $ssh @sshArgs 2>&1
        $text = ($output | Out-String).Trim()
        $code = $LASTEXITCODE
        $result.ExitCode = $code
        $result.Output = $text
        $result.Ok = ($code -eq 0)
        if (-not $result.Ok) {
            $result.Error = $text
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-RouterHostsSnapshot {
    $result = [PSCustomObject]@{
        Ok     = $false
        Exists = $false
        Text   = ''
        Hash   = ''
        Error  = ''
    }

    $command = "if [ -f '{0}' ]; then cat '{0}'; else exit 44; fi" -f $RouterHostsPath
    $sshResult = Invoke-RouterSsh -Command $command
    if ($sshResult.ExitCode -eq 44) {
        $result.Ok = $true
        $result.Exists = $false
        $result.Hash = ''
        return $result
    }
    if (-not $sshResult.Ok) {
        $result.Error = $sshResult.Error
        return $result
    }

    $text = ($sshResult.Output -replace "`r`n", "`n")
    $result.Ok = $true
    $result.Exists = $true
    $result.Text = $text
    $result.Hash = Get-BytesSha256 -Bytes $script:Utf8NoBom.GetBytes($text)
    return $result
}

function Get-ManagedBlockCount {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) {
        return 0
    }

    $inBlock = $false
    $count = 0
    foreach ($line in ($Text -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -eq $script:SystemHostsMarkerStart) {
            $inBlock = $true
            continue
        }
        if ($trimmed -eq $script:SystemHostsMarkerEnd) {
            $inBlock = $false
            continue
        }
        if (-not $inBlock -or $trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            continue
        }
        $tokens = @($trimmed -split '\s+')
        if ($tokens.Count -ge 2 -and (Test-IPv4Text -Text $tokens[0])) {
            $count++
        }
    }
    return $count
}

function Send-RouterFile {
    param(
        [string]$LocalPath,
        [string]$RemotePath
    )

    $result = [PSCustomObject]@{
        Ok     = $false
        Method = ''
        Error  = ''
    }

    $target = ('{0}@{1}' -f $RouterUser, $RouterHost)
    try {
        $scp = Get-OpenSshExe -Name 'scp.exe'
        $scpArgs = @(
            '-O',
            '-i', $RouterSshKey,
            '-P', [string]$RouterPort,
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', ('ConnectTimeout={0}' -f $RouterTimeoutSec),
            $LocalPath,
            ('{0}:{1}' -f $target, $RemotePath)
        )
        $scpOutput = & $scp @scpArgs 2>&1
        $scpText = ($scpOutput | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) {
            $result.Ok = $true
            $result.Method = 'scp'
            return $result
        }

        # Dropbear 可能没有 SFTP/SCP 子系统，退回用 ssh 的 stdin 写入。
        $content = [System.IO.File]::ReadAllText($LocalPath, $script:Utf8NoBom)
        $ssh = Get-OpenSshExe -Name 'ssh.exe'
        $sshArgs = @(
            '-i', $RouterSshKey,
            '-p', [string]$RouterPort,
            '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', ('ConnectTimeout={0}' -f $RouterTimeoutSec),
            $target,
            ("cat > '{0}'" -f $RemotePath)
        )
        $sshOutput = $content | & $ssh @sshArgs 2>&1
        $sshText = ($sshOutput | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) {
            $result.Ok = $true
            $result.Method = 'ssh-stdin'
            return $result
        }

        $result.Error = ('scp 失败: {0}；ssh 管道失败: {1}' -f $scpText, $sshText)
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Sync-RouterHosts {
    param(
        [string]$HostName,
        [string]$UserName,
        [int]$Port,
        [string]$Path,
        [string]$KeyPath,
        [string]$OutputDir,
        [object]$ManagedDomains,
        [string[]]$MappingLines,
        [string]$FullContent,
        [bool]$FullOverwrite
    )

    $result = [PSCustomObject]@{
        Attempted        = $true
        Applied          = $false
        Skipped          = $false
        Status           = '失败'
        Host             = $HostName
        User             = $UserName
        Port             = $Port
        Path             = $Path
        BackupPath       = ''
        RemoteBackupPath = ($Path + '.dnsparse.bak')
        ManagedCount     = 0
        BlockCount       = @($MappingLines).Count
        PreservedLines   = 0
        FullOverwrite    = $FullOverwrite
        Verified         = $false
        Method           = ''
        Error            = ''
    }

    $managed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $ManagedDomains) {
        foreach ($domain in $ManagedDomains) {
            $value = ([string]$domain).Trim().TrimEnd('.').ToLowerInvariant()
            if ($value.Length -gt 0) {
                [void]$managed.Add($value)
            }
        }
    }
    $result.ManagedCount = $managed.Count
    $mapping = @($MappingLines | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    if (-not [System.IO.File]::Exists($KeyPath)) {
        $result.Attempted = $false
        $result.Skipped = $true
        $result.Status = '未配置'
        $result.Error = '没有找到路由器 SSH 密钥。请先运行“配置路由器SSH.bat”。'
        return $result
    }
    if ($mapping.Count -eq 0 -or $managed.Count -eq 0) {
        $result.Skipped = $true
        $result.Status = '已跳过'
        $result.Error = '没有可同步到路由器的映射。'
        return $result
    }
    if ($HostName -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$' -or $UserName -notmatch '^[A-Za-z0-9._-]+$') {
        $result.Error = '路由器地址或用户名格式不正确。'
        return $result
    }
    if ($Path -notmatch '^/[A-Za-z0-9._/-]+$') {
        $result.Error = '路由器 hosts 路径必须是绝对路径，且不能包含空格或特殊字符。'
        return $result
    }

    $localTemp = Join-Path $OutputDir 'router-hosts.upload.tmp'
    $remoteTemp = '/tmp/dnsparse-hosts.new'

    try {
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            $snapshot = Get-RouterHostsSnapshot
            if (-not $snapshot.Ok) {
                $result.Error = ('读取路由器 hosts 失败: {0}' -f $snapshot.Error)
                break
            }

            $baseText = $snapshot.Text
            if ($FullOverwrite -and -not [string]::IsNullOrWhiteSpace($FullContent)) {
                $baseText = ($FullContent -replace "`r`n", "`n")
            }

            $merged = Merge-HostsContent -Text $baseText -NewLine "`n" -ManagedDomains $managed -MappingLines $mapping
            if ($merged.UnclosedBlock) {
                $result.Error = '路由器 hosts 里的旧 DnsParse 管理块缺少结束标记，已取消写入。'
                break
            }
            if ($merged.BlockCount -eq 0) {
                $result.Error = '生成的映射为空，已取消写入路由器 hosts。'
                break
            }

            [System.IO.File]::WriteAllText($localTemp, $merged.Text, $script:Utf8NoBom)
            $recheck = Get-RouterHostsSnapshot
            if (-not $recheck.Ok) {
                $result.Error = ('写入前复查路由器 hosts 失败: {0}' -f $recheck.Error)
                break
            }
            if ($recheck.Hash -ne $snapshot.Hash) {
                continue
            }

            # V0.7：按用户要求不再生成本地/远端路由器备份文件。
            $sendResult = Send-RouterFile -LocalPath $localTemp -RemotePath $remoteTemp
            if (-not $sendResult.Ok) {
                $result.Error = ('上传路由器 hosts 失败: {0}' -f $sendResult.Error)
                break
            }
            $result.Method = $sendResult.Method

            $applyCommand = "cat '{0}' > '{1}' && rm -f '{0}' && echo DNSPARSE_WRITTEN" -f $remoteTemp, $Path
            $applyResult = Invoke-RouterSsh -Command $applyCommand
            if (-not $applyResult.Ok) {
                $result.Error = ('写入路由器 hosts 失败: {0}' -f $applyResult.Error)
                break
            }

            $after = Get-RouterHostsSnapshot
            if (-not $after.Ok) {
                $result.Applied = $true
                $result.Error = ('写入后读取路由器 hosts 失败: {0}' -f $after.Error)
                break
            }
            $actualCount = Get-ManagedBlockCount -Text $after.Text
            if ($actualCount -ne $merged.BlockCount) {
                $result.Applied = $true
                $result.Error = ('写入后校验失败: 期望 {0} 条，实际 {1} 条。' -f $merged.BlockCount, $actualCount)
                break
            }

            $result.Applied = $true
            $result.Verified = $true
            $result.Status = '已同步'
            $result.PreservedLines = $merged.PreservedLines
            $result.Error = ''
            break
        }

        if (-not $result.Applied -and [string]::IsNullOrWhiteSpace($result.Error)) {
            $result.Error = '路由器 hosts 在运行期间被其他程序修改，已取消写入，请重试。'
        }
        if ($result.Applied -and $result.Verified) {
            $result.PreservedLines = $merged.PreservedLines
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ([System.IO.File]::Exists($localTemp)) {
            try {
                [System.IO.File]::Delete($localTemp)
            }
            catch {
                # 临时文件清理失败不影响结果。
            }
        }
    }

    return $result
}

function Get-NodeExecutable {
    param([string]$ConfiguredPath)

    if (-not [string]::IsNullOrWhiteSpace($ConfiguredPath)) {
        if ([System.IO.File]::Exists($ConfiguredPath)) {
            return $ConfiguredPath
        }
        throw ('指定的 Node.js 不存在: {0}' -f $ConfiguredPath)
    }

    $command = Get-Command 'node.exe' -ErrorAction SilentlyContinue
    if ($null -ne $command -and $command.Source) {
        return $command.Source
    }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates += (Join-Path $env:ProgramFiles 'nodejs\node.exe')
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} 'nodejs\node.exe')
    }
    foreach ($candidate in $candidates) {
        if ([System.IO.File]::Exists($candidate)) {
            return $candidate
        }
    }

    throw '找不到 Node.js。V0.7 需要 Node.js 22 或更高版本（不安装 npm 包），请先安装 Node.js 后重试。'
}

function Invoke-ChinazVote {
    param(
        [object[]]$DomainItems,
        [string]$NodePath,
        [string]$ScriptPath,
    [string]$OutputDir,
    [int]$Concurrency,
    [int]$TimeoutSec,
    [int]$CertTop,
    [int]$CertTimeoutMs
)

    $result = [PSCustomObject]@{
        Ok         = $false
        ExitCode   = 1
        Output     = ''
        Results    = @()
        Error      = ''
        InputPath  = ''
        OutputPath = ''
    }

    if (-not [System.IO.File]::Exists($ScriptPath)) {
        $result.Error = ('找不到站长之家查询脚本: {0}' -f $ScriptPath)
        return $result
    }
    if (-not [System.IO.Directory]::Exists($OutputDir)) {
        [void][System.IO.Directory]::CreateDirectory($OutputDir)
    }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
    $inputPath = Join-Path $OutputDir ('chinaz-input-{0}.json' -f $stamp)
    $outputPath = Join-Path $OutputDir ('chinaz-votes-{0}.json' -f $stamp)
    $stderrPath = Join-Path $OutputDir ('chinaz-stderr-{0}.txt' -f $stamp)
    $stdoutPath = Join-Path $OutputDir ('chinaz-stdout-{0}.txt' -f $stamp)
    $result.InputPath = $inputPath
    $result.OutputPath = $outputPath

    try {
        $payload = [PSCustomObject]@{
            domains = @($DomainItems | ForEach-Object {
                [PSCustomObject]@{
                    domain   = [string]$_.Domain
                    category = [string]$_.Category
                }
            })
        }
        $json = $payload | ConvertTo-Json -Depth 6 -Compress
        [System.IO.File]::WriteAllText($inputPath, $json, $script:Utf8NoBom)

        $arguments = @(
            $ScriptPath,
            '--input', $inputPath,
            '--output', $outputPath,
            '--concurrency', [string]$Concurrency,
            '--timeout', [string]$TimeoutSec,
            '--cert-top', [string]$CertTop,
            '--cert-timeout', [string]$CertTimeoutMs
        )

        $cmdLine = New-Object System.Text.StringBuilder
        [void]$cmdLine.Append('"')
        [void]$cmdLine.Append($NodePath.Replace('"', '""'))
        [void]$cmdLine.Append('"')
        foreach ($argument in $arguments) {
            [void]$cmdLine.Append(' "')
            [void]$cmdLine.Append(([string]$argument).Replace('"', '""'))
            [void]$cmdLine.Append('"')
        }
        [void]$cmdLine.Append(' > "')
        [void]$cmdLine.Append($stdoutPath.Replace('"', '""'))
        [void]$cmdLine.Append('" 2> "')
        [void]$cmdLine.Append($stderrPath.Replace('"', '""'))
        [void]$cmdLine.Append('"')

        $cmdExe = $env:ComSpec
        if ([string]::IsNullOrWhiteSpace($cmdExe) -or -not [System.IO.File]::Exists($cmdExe)) {
            $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
        }
        $oldPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $cmdOutput = & $cmdExe '/d' '/c' $cmdLine.ToString()
            $code = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $oldPreference
        }

        $result.ExitCode = $code
        $stdoutText = ''
        if ([System.IO.File]::Exists($stdoutPath)) {
            $stdoutText = ([System.IO.File]::ReadAllText($stdoutPath, [System.Text.Encoding]::UTF8)).Trim()
        }
        $stderrText = ''
        if ([System.IO.File]::Exists($stderrPath)) {
            $stderrText = ([System.IO.File]::ReadAllText($stderrPath, [System.Text.Encoding]::UTF8)).Trim()
        }
        if ($stderrText.Length -gt 0) {
            if ($stdoutText.Length -gt 0) {
                $result.Output = $stdoutText + "`r`n" + $stderrText
            }
            else {
                $result.Output = $stderrText
            }
        }
        else {
            $result.Output = $stdoutText
        }
        $result.Output = ((@($result.Output -split "`r?`n") | Where-Object { $_ -notmatch '结果已写入' }) -join "`r`n").Trim()
        if ($code -ne 0) {
            $result.Error = ('Node 查询退出码 {0}: {1}' -f $code, $result.Output)
            return $result
        }
        if (-not [System.IO.File]::Exists($outputPath)) {
            $result.Error = 'Node 查询没有生成结果文件。'
            return $result
        }

        $parsed = [System.IO.File]::ReadAllText($outputPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        $result.Results = @($parsed.results)
        $result.Ok = $true
        return $result
    }
    catch {
        $result.Error = $_.Exception.Message
        return $result
    }
    finally {
        foreach ($path in @($inputPath, $stderrPath, $stdoutPath, $outputPath)) {
            if ([System.IO.File]::Exists($path)) {
                try {
                    [System.IO.File]::Delete($path)
                }
                catch {
                }
            }
        }
    }
}

function Resolve-DomainViaChinaz {
    param(
        [string]$Domain,
        [string]$Category,
        [object]$VoteResult,
        [int]$TargetPort,
        [int]$Timeout,
        [int]$MaxCandidates,
        [int]$MaxIps
    )

    $item = [PSCustomObject]@{
        Domain        = $Domain
        Category      = $Category
        Status        = '解析失败'
        TopIp         = ''
        TopCount      = 0
        Total         = 0
        Messages      = 0
        Errors        = 0
        Ip            = ''
        Ips           = @()
        Ms            = $null
        Candidates    = @()
        Probes        = @()
        CertStatus    = ''
        CertName      = ''
        Note          = ''
        SourceError   = ''
    }

    if ($null -eq $VoteResult) {
        $item.Note = '没有收到站长之家查询结果。'
        return $item
    }

    $item.Total = [int]$VoteResult.total
    $item.Messages = [int]$VoteResult.messages
    $item.Errors = [int]$VoteResult.errors
    $item.SourceError = [string]$VoteResult.error

    if ([string]$VoteResult.status -ne 'ok' -or [string]::IsNullOrWhiteSpace([string]$VoteResult.topIp)) {
        $item.Note = '站长之家没有返回有效 IPv4 投票。'
        return $item
    }

    $item.TopIp = [string]$VoteResult.topIp
    $item.TopCount = [int]$VoteResult.topCount

    # 建立 IP -> 证书校验结果 映射（V0.7）。
    $certMap = @{}
    foreach ($vote in @($VoteResult.votes)) {
        $voteIp = [string]$vote.ip
        if (-not $certMap.ContainsKey($voteIp)) {
            $certMap[$voteIp] = [PSCustomObject]@{
                Cert     = [string]$vote.cert
                CertName = [string]$vote.certName
            }
        }
    }

    # 建立 IP -> 票数排名 映射（V0.7：按站长之家票数高低排序）。
    $rankMap = @{}
    $rank = 0
    foreach ($vote in @($VoteResult.votes)) {
        $voteIp = [string]$vote.ip
        if (-not $rankMap.ContainsKey($voteIp)) {
            $rankMap[$voteIp] = $rank
            $rank++
        }
    }

    # 候选池需大于要写入的 IP 数，留出被淘汰地址的余量。
    $candidatePool = [Math]::Max($MaxCandidates, $MaxIps + 4)
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if (Test-IPv4Text -Text $item.TopIp) {
        $candidates.Add($item.TopIp)
    }
    foreach ($vote in @($VoteResult.votes)) {
        if ($candidates.Count -ge $candidatePool) {
            break
        }
        $ip = [string]$vote.ip
        if ((Test-IPv4Text -Text $ip) -and -not $candidates.Contains($ip)) {
            $candidates.Add($ip)
        }
    }

    $item.Candidates = $candidates.ToArray()
    if ($candidates.Count -eq 0) {
        $item.Note = '投票结果里没有合法 IPv4。'
        return $item
    }

    $probes = Get-ProbesForIps -IPs $item.Candidates -TargetPort $TargetPort -Timeout $Timeout
    $item.Probes = $probes

    # 把证书状态附加到每个探针上。
    $decorated = @($probes | ForEach-Object {
        $cert = 'unknown'
        $certName = ''
        if ($certMap.ContainsKey($_.IP)) {
            $cert = $certMap[$_.IP].Cert
            $certName = $certMap[$_.IP].CertName
        }
        if ([string]::IsNullOrWhiteSpace($cert)) { $cert = 'unknown' }
        $probeRank = 9999
        if ($rankMap.ContainsKey($_.IP)) { $probeRank = [int]$rankMap[$_.IP] }
        [PSCustomObject]@{
            IP       = $_.IP
            Ok       = [bool]$_.Ok
            Ms       = $_.Ms
            Reason   = $_.Reason
            Cert     = $cert
            CertName = $certName
            Rank     = $probeRank
        }
    })
    $item.Probes = $decorated

    # V0.7：按站长之家票数排名取最高的 N 个可用 IP。
    # 先淘汰证书 mismatch 与 TCP 不通的地址；再按票数排名（小=高票）升序取前 N 个。
    $reachable = @($decorated | Where-Object { $_.Ok -and $_.Cert -ne 'mismatch' })
    $mismatchReachable = @($decorated | Where-Object { $_.Ok -and $_.Cert -eq 'mismatch' })
    if ($reachable.Count -gt 0) {
        $ordered = @($reachable | Sort-Object Rank, Ms)
        $picked = @($ordered | Select-Object -First $MaxIps)
        $item.Status = '可达'
        $item.Ips = @($picked | ForEach-Object { [string]$_.IP })
        $item.Ip = [string]$picked[0].IP
        $item.Ms = [int]$picked[0].Ms
        $item.CertStatus = [string]$picked[0].Cert
        $item.CertName = [string]$picked[0].CertName
        if ($item.Ip -ne $item.TopIp) {
            $item.Note = ('最高票地址 TCP {0} 不通或证书不符，改用同票池中可达地址。' -f $TargetPort)
        }
        return $item
    }

    $reasons = @($decorated | ForEach-Object { '{0}: {1}' -f $_.IP, $_.Reason })
    $item.Status = '阻断'
    $item.Note = ('最高票及其候选地址均未通过 TCP {0}：{1}' -f $TargetPort, ($reasons -join '；'))
    if ($mismatchReachable.Count -gt 0) {
        $badNames = @($mismatchReachable | ForEach-Object { '{0}(证书={1})' -f $_.IP, $_.CertName })
        $item.Note = ('候选地址证书均属于其他域名，已淘汰以防 DNS 污染：{0}' -f ($badNames -join '；'))
    }
    return $item
}

function New-HostsContent {
    param(
        [object[]]$Entries,
        [string]$GeneratedAt,
        [string[]]$CategoryOrderFromDomains = @()
    )

    $reachable = @($Entries | Where-Object { $_.Status -eq '可达' -and -not [string]::IsNullOrWhiteSpace([string]$_.Ip) })

    # V0.7：分类顺序严格按 domains.txt 里出现的先后排列。
    $categoryOrder = New-Object 'System.Collections.Generic.List[string]'
    $seenCategory = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($category in @($CategoryOrderFromDomains)) {
        if ([string]::IsNullOrWhiteSpace($category)) { continue }
        if ($seenCategory.Add($category)) {
            $categoryOrder.Add($category)
        }
    }
    foreach ($entry in $reachable) {
        $category = [string]$entry.Category
        if ([string]::IsNullOrWhiteSpace($category)) {
            $category = '未分类'
        }
        if ($seenCategory.Add($category)) {
            $categoryOrder.Add($category)
        }
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('# ============================================================')
    $lines.Add('# DNS 加速解析工具 V0.7')
    $lines.Add(('# 生成时间: {0}' -f $GeneratedAt))
    $lines.Add('# 数据来源: 站长之家 DNS 查询（多监测节点投票）')
    $lines.Add('# 规则: 每个域名取票数最高的多个 IPv4，通过 TCP 443 及 TLS 证书校验后写入。')
    $lines.Add('# 注意: 本文件由程序生成；合并到系统 hosts 时只替换')
    $lines.Add('#       DnsParse 管理块，其他映射和注释不会丢失。')
    $lines.Add('# ============================================================')
    $lines.Add('')

    $written = 0
    foreach ($category in $categoryOrder) {
        $group = @($reachable | Where-Object {
            $value = [string]$_.Category
            if ([string]::IsNullOrWhiteSpace($value)) { $value = '未分类' }
            $value -eq $category
        })
        if ($group.Count -eq 0) {
            continue
        }

        $lines.Add(('# [{0}]' -f $category))
        foreach ($entry in $group) {
            $ips = @($entry.Ips)
            if ($ips.Count -eq 0) {
                $ips = @([string]$entry.Ip)
            }
            foreach ($address in $ips) {
                if ([string]::IsNullOrWhiteSpace([string]$address)) { continue }
                $lines.Add(("{0}`t{1}" -f $address, $entry.Domain))
                $written++
            }
        }
        $lines.Add('')
    }

    return [PSCustomObject]@{
        Content       = (($lines -join "`r`n") + "`r`n")
        TotalCount    = $written
        CategoryCount = $categoryOrder.Count
    }
}

function New-SystemHostsSkippedResult {
    param([string]$Path)

    return [PSCustomObject]@{
        Attempted      = $false
        Applied        = $false
        Skipped        = $true
        Path           = $Path
        BackupPath     = ''
        ManagedCount   = 0
        BlockCount     = 0
        RemovedLines   = 0
        RewrittenLines = 0
        PreservedLines = 0
        Attempts       = 0
        Error          = ''
        FlushAttempted = $false
        FlushOk        = $false
        FlushOutput    = ''
        FlushError     = ''
    }
}

function New-RouterSkippedResult {
    param(
        [string]$HostName,
        [string]$UserName,
        [int]$Port,
        [string]$Path,
        [bool]$FullOverwrite
    )

    return [PSCustomObject]@{
        Attempted        = $false
        Applied          = $false
        Skipped          = $true
        Status           = '已跳过'
        Host             = $HostName
        User             = $UserName
        Port             = $Port
        Path             = $Path
        BackupPath       = ''
        RemoteBackupPath = ($Path + '.dnsparse.bak')
        ManagedCount     = 0
        BlockCount       = 0
        PreservedLines   = 0
        FullOverwrite    = $FullOverwrite
        Verified         = $false
        Method           = ''
        Error            = ''
    }
}

function New-ReportContent {
    param(
        [object[]]$Entries,
        [string]$GeneratedAt,
        [int]$RawDomainCount,
        [object[]]$InvalidItems,
        [object]$HostsPlan,
        [object]$SystemHostsResult,
        [object]$RouterResult,
        [string]$NodeOutput,
        [string]$OutputDir
    )

    $total = @($Entries).Count
    $reachable = @($Entries | Where-Object { $_.Status -eq '可达' })
    $blocked = @($Entries | Where-Object { $_.Status -eq '阻断' })
    $failed = @($Entries | Where-Object { $_.Status -eq '解析失败' })
    $duplicateCount = [Math]::Max(0, $RawDomainCount - $total)

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('============================================================')
    $lines.Add('DNS 加速解析报告 V0.7')
    $lines.Add('============================================================')
    $lines.Add(('生成时间: {0}' -f $GeneratedAt))
    $lines.Add('数据来源: 站长之家 DNS 查询 https://tool.chinaz.com/dns/')
    $lines.Add('查询方式: 每个域名由监测节点返回 IP，按票数取最高票 IPv4。')
    $lines.Add('验证方式: 对候选 IP 做 TCP 443 连接与 TLS 证书校验；每域名取票数最高的多个 IP。')
    $lines.Add('')
    $lines.Add('------------------------------------------------------------')
    $lines.Add('一、统计')
    $lines.Add('------------------------------------------------------------')
    $lines.Add(('域名总数: {0}' -f $total))
    $lines.Add(('重复条目: {0}' -f $duplicateCount))
    $lines.Add(('可达并写入: {0}' -f $reachable.Count))
    $lines.Add(('TCP 阻断: {0}' -f $blocked.Count))
    $lines.Add(('解析失败: {0}' -f $failed.Count))
    $lines.Add(('写入 hosts: {0}' -f $HostsPlan.TotalCount))
    $lines.Add('')

    $lines.Add('------------------------------------------------------------')
    $lines.Add('二、本机系统 hosts')
    $lines.Add('------------------------------------------------------------')
    if ($null -eq $SystemHostsResult) {
        $lines.Add('状态: 未执行')
    }
    elseif ($SystemHostsResult.Skipped) {
        $lines.Add('状态: 已跳过（-NoSystemHosts）')
        $lines.Add(('路径: {0}' -f $SystemHostsResult.Path))
    }
    elseif ($SystemHostsResult.Applied) {
        $lines.Add('状态: 已合并')
        $lines.Add(('路径: {0}' -f $SystemHostsResult.Path))
        $lines.Add('备份: 已按 V0.7 配置关闭，不生成备份文件')
        $lines.Add(('管理域名: {0} 个；写入映射: {1} 条' -f $SystemHostsResult.ManagedCount, $SystemHostsResult.BlockCount))
        $lines.Add('排列: DnsParse 管理块在前；原保留内容在文件末尾')
        $lines.Add(('删除旧管理行: {0}；改写多主机名行: {1}；保留原行: {2}' -f $SystemHostsResult.RemovedLines, $SystemHostsResult.RewrittenLines, $SystemHostsResult.PreservedLines))
        if ($SystemHostsResult.FlushAttempted) {
            if ($SystemHostsResult.FlushOk) {
                $lines.Add('DNS 缓存: 已刷新')
            }
            else {
                $lines.Add(('DNS 缓存: 刷新失败（{0}）' -f $SystemHostsResult.FlushError))
            }
        }
        else {
            $lines.Add('DNS 缓存: 未刷新（-NoFlushDns）')
        }
    }
    else {
        $lines.Add('状态: 失败')
        $lines.Add(('路径: {0}' -f $SystemHostsResult.Path))
        $lines.Add(('原因: {0}' -f $SystemHostsResult.Error))
        $lines.Add('提示: 请使用“一键解析DNS.bat”运行并同意 UAC。')
    }
    $lines.Add('')

    $lines.Add('------------------------------------------------------------')
    $lines.Add('三、路由器 hosts')
    $lines.Add('------------------------------------------------------------')
    if ($null -eq $RouterResult) {
        $lines.Add('状态: 未执行')
    }
    elseif ($RouterResult.Skipped) {
        $lines.Add(('状态: {0}' -f $RouterResult.Status))
        if (-not [string]::IsNullOrWhiteSpace($RouterResult.Error)) {
            $lines.Add(('说明: {0}' -f $RouterResult.Error))
        }
        $lines.Add(('路径: {0}@{1}:{2}' -f $RouterResult.User, $RouterResult.Host, $RouterResult.Path))
    }
    elseif ($RouterResult.Applied) {
        $lines.Add('状态: 已同步')
        $lines.Add(('路径: {0}@{1}:{2}' -f $RouterResult.User, $RouterResult.Host, $RouterResult.Path))
        $lines.Add(('写入映射: {0} 条；保留原行: {1}' -f $RouterResult.BlockCount, $RouterResult.PreservedLines))
        $lines.Add('排列: DnsParse 管理块在前；路由器原保留内容在文件末尾')
        $lines.Add('备份: 已按 V0.7 配置关闭，不生成备份文件')
        $lines.Add(('上传方式: {0}' -f $RouterResult.Method))
        if (-not $RouterResult.Verified) {
            $lines.Add(('警告: {0}' -f $RouterResult.Error))
        }
    }
    else {
        $lines.Add('状态: 失败')
        $lines.Add(('路径: {0}@{1}:{2}' -f $RouterResult.User, $RouterResult.Host, $RouterResult.Path))
        $lines.Add(('原因: {0}' -f $RouterResult.Error))
        $lines.Add('提示: 首次使用请先运行“配置路由器SSH.bat”。')
    }
    $lines.Add('')

    $lines.Add('------------------------------------------------------------')
    $lines.Add('四、逐域名结果')
    $lines.Add('------------------------------------------------------------')
    $lines.Add('分类	域名	状态	最高票 IP(票数)	实际写入 IP	TCP	证书	节点/错误')
    foreach ($entry in @($Entries)) {
        $top = '-'
        if (-not [string]::IsNullOrWhiteSpace($entry.TopIp)) {
            $top = ('{0} ({1})' -f $entry.TopIp, $entry.TopCount)
        }
        $ipList = @($entry.Ips)
        if ($ipList.Count -eq 0) {
            $ipList = @([string]$entry.Ip)
        }
        $ip = (($ipList | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join ',')
        if ([string]::IsNullOrWhiteSpace($ip)) {
            $ip = '-'
        }
        $ms = '-'
        if ($null -ne $entry.Ms) {
            $ms = ('{0} ms' -f $entry.Ms)
        }
        $certText = [string]$entry.CertStatus
        if ([string]::IsNullOrWhiteSpace($certText)) { $certText = '-' }
        $node = ('{0}/{1}' -f $entry.Messages, $entry.Total)
        if ($entry.Errors -gt 0) {
            $node += ('，错误 {0}' -f $entry.Errors)
        }
        $lines.Add(('{0}	{1}	{2}	{3}	{4}	{5}	{6}	{7}' -f $entry.Category, $entry.Domain, $entry.Status, $top, $ip, $ms, $certText, $node))
    }
    $lines.Add('')

    $certVerified = @($reachable | Where-Object { $_.CertStatus -eq 'match' })
    $certUnknown = @($reachable | Where-Object { $_.CertStatus -ne 'match' })
    $lines.Add('------------------------------------------------------------')
    $lines.Add('TLS 证书校验（V0.5 起）')
    $lines.Add('------------------------------------------------------------')
    $lines.Add(('证书匹配域名: {0} 条；证书无法判定(保留): {1} 条' -f $certVerified.Count, $certUnknown.Count))
    $lines.Add('说明: 证书明确属于其他域名的候选地址会被淘汰，避免 DNS 污染写入错误 IP。')
    $lines.Add('')

    if ($blocked.Count -gt 0) {
        $lines.Add('------------------------------------------------------------')
        $lines.Add('TCP 阻断明细')
        $lines.Add('------------------------------------------------------------')
        foreach ($entry in $blocked) {
            $lines.Add(('{0}  [{1}]  {2}' -f $entry.Domain, $entry.TopIp, $entry.Note))
        }
        $lines.Add('')
        $lines.Add('说明: TCP 超时类地址通常被网络层阻断，hosts 无法修复，建议用加速器；')
        $lines.Add('       “证书属于其他域名”类为 DNS 污染，已主动淘汰，属预期保护行为。')
        $lines.Add('')
    }

    if ($failed.Count -gt 0) {
        $lines.Add('------------------------------------------------------------')
        $lines.Add('解析失败明细')
        $lines.Add('------------------------------------------------------------')
        foreach ($entry in $failed) {
            $lines.Add(('{0}  {1}' -f $entry.Domain, $entry.Note))
        }
        $lines.Add('')
    }

    if (@($InvalidItems).Count -gt 0) {
        $lines.Add('------------------------------------------------------------')
        $lines.Add('无效输入')
        $lines.Add('------------------------------------------------------------')
        foreach ($invalid in @($InvalidItems)) {
            $lines.Add([string]$invalid)
        }
        $lines.Add('')
    }

    $lines.Add('------------------------------------------------------------')
    $lines.Add('说明')
    $lines.Add('------------------------------------------------------------')
    $lines.Add('1. 本版本不再请求 GitHub520、SteamHostSync、TMM 等旧远程源。')
    $lines.Add('2. 站长之家各节点结果可能随网络和地区变化；本报告保留最高票和实际写入地址，便于复核。')
    $lines.Add('3. 若最高票地址 TCP 443 不通，程序会尝试同票池中票数靠前的候选地址。')
    $lines.Add('4. 系统 hosts 采用标记块合并；Tailscale、其他映射和注释不会被删除。')
    $lines.Add('5. 路由器 hosts 默认同样采用标记块合并；-RouterFullOverwrite 才会整文件覆盖。')
    $lines.Add(('6. 输出目录: {0}' -f $OutputDir))
    $lines.Add('')

    if (-not [string]::IsNullOrWhiteSpace($NodeOutput)) {
        $lines.Add('------------------------------------------------------------')
        $lines.Add('Node 查询日志（最后部分）')
        $lines.Add('------------------------------------------------------------')
        $lines.Add($NodeOutput)
        $lines.Add('')
    }

    return (($lines -join "`r`n") + "`r`n")
}

try {
    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $root = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($root)) {
        $root = (Get-Location).Path
    }

    if ([string]::IsNullOrWhiteSpace($InputFile)) {
        $InputFile = Join-Path $root 'domains.txt'
    }
    elseif (-not [System.IO.Path]::IsPathRooted($InputFile)) {
        $InputFile = Join-Path $root $InputFile
    }

    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = $root
    }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
        $OutputDir = Join-Path $root $OutputDir
    }

    if ([string]::IsNullOrWhiteSpace($ChinazScript)) {
        $ChinazScript = Join-Path $root 'chinaz-vote.js'
    }
    elseif (-not [System.IO.Path]::IsPathRooted($ChinazScript)) {
        $ChinazScript = Join-Path $root $ChinazScript
    }

    if ([string]::IsNullOrWhiteSpace($SystemHostsPath)) {
        $SystemHostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    }

    if ([string]::IsNullOrWhiteSpace($RouterSshKey)) {
        $userProfile = [Environment]::GetFolderPath('UserProfile')
        if ([string]::IsNullOrWhiteSpace($userProfile)) {
            $userProfile = $HOME
        }
        $RouterSshKey = Join-Path $userProfile '.ssh\dnsparse_router_ed25519'
    }

    if (-not [System.IO.Directory]::Exists($OutputDir)) {
        [void][System.IO.Directory]::CreateDirectory($OutputDir)
    }

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host '        DNS 加速解析工具 V0.7' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ('输入: {0}' -f $InputFile)
    Write-Host ('输出: {0}' -f $OutputDir)
    Write-Host ''

    if (-not [System.IO.File]::Exists($InputFile)) {
        throw ('找不到域名文件: {0}' -f $InputFile)
    }

    $nodePath = Get-NodeExecutable -ConfiguredPath $NodeExe
    Write-Host ('Node.js: {0}' -f $nodePath)
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $nodeVersion = (& $nodePath '--version' 2>&1 | Out-String).Trim()
        $nodeCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    if ($nodeCode -ne 0) {
        throw ('无法运行 Node.js: {0}' -f ($nodeVersion))
    }
    if ($nodeVersion -notmatch '^v(\d+)\.') {
        throw ('无法识别 Node.js 版本: {0}' -f $nodeVersion)
    }
    if ([int]$Matches[1] -lt 22) {
        throw ('V0.7 需要 Node.js 22 或更高版本，当前为 {0}。' -f $nodeVersion)
    }
    Write-Host ('Node 版本: {0}' -f $nodeVersion)
    Write-Host ''

    $domainList = Get-DomainList -Path $InputFile
    $domainItems = $domainList.Items.ToArray()
    $invalidItems = $domainList.Invalid.ToArray()
    $rawCount = Get-RawDomainNameCount -Path $InputFile
    $uniqueCount = $domainItems.Count

    Write-Host ('读取域名: 有效唯一 {0} 个；原始有效条目 {1} 个。' -f $uniqueCount, $rawCount)
    if ($uniqueCount -eq 0) {
        throw 'domains.txt 中没有有效域名。'
    }

    Write-Host ('正在请求站长之家（{0} 个域名，并发 {1}，超时 {2} 秒）...' -f $uniqueCount, $ChinazConcurrency, $ChinazTimeoutSec) -ForegroundColor DarkCyan
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $nodeResult = Invoke-ChinazVote -DomainItems $domainItems -NodePath $nodePath -ScriptPath $ChinazScript -OutputDir $OutputDir -Concurrency $ChinazConcurrency -TimeoutSec $ChinazTimeoutSec -CertTop $CertTop -CertTimeoutMs $CertTimeoutMs
    $watch.Stop()

    if (-not $nodeResult.Ok) {
        Write-Host ('[错误] 站长之家查询失败: {0}' -f $nodeResult.Error) -ForegroundColor Red
        exit 1
    }
    Write-Host ('站长之家查询完成，用时 {0:N1} 秒。' -f ($watch.Elapsed.TotalSeconds)) -ForegroundColor DarkGray
    Write-Host ''

    $voteByDomain = @{}
    foreach ($vote in @($nodeResult.Results)) {
        if ($null -eq $vote) {
            continue
        }
        $key = ([string]$vote.domain).Trim().ToLowerInvariant()
        if ($key.Length -gt 0) {
            $voteByDomain[$key] = $vote
        }
    }

    $results = New-Object 'System.Collections.Generic.List[psobject]'
    $index = 0
    foreach ($item in $domainItems) {
        $index++
        $domain = [string]$item.Domain
        $category = [string]$item.Category
        $vote = $null
        if ($voteByDomain.ContainsKey($domain.ToLowerInvariant())) {
            $vote = $voteByDomain[$domain.ToLowerInvariant()]
        }

        $resolved = Resolve-DomainViaChinaz -Domain $domain -Category $category -VoteResult $vote -TargetPort $Port -Timeout $TimeoutMs -MaxCandidates $MaxTcpCandidates -MaxIps $MaxIpsPerDomain
        $results.Add($resolved)

        $prefix = ('[{0,3}/{1,3}]' -f $index, $uniqueCount)
        switch ($resolved.Status) {
            '可达' {
                $ipCount = @($resolved.Ips).Count
                if ($ipCount -eq 0) { $ipCount = 1 }
                $suffix = ('{0} 个IP [{1}]  {2} ms  ({3}/{4})' -f $ipCount, $resolved.Ip, $resolved.Ms, $resolved.TopCount, $resolved.Total)
                Write-Host ('{0} {1,-30} [OK]   {2}' -f $prefix, $domain, $suffix) -ForegroundColor Green
            }
            '阻断' {
                Write-Host ('{0} {1,-30} [阻断] {2}  ({3})' -f $prefix, $domain, $resolved.TopIp, $resolved.Note) -ForegroundColor Yellow
            }
            default {
                Write-Host ('{0} {1,-30} [失败] {2}' -f $prefix, $domain, $resolved.Note) -ForegroundColor Red
            }
        }
    }
    Write-Host ''

    $entryArray = $results.ToArray()
    $domainsCategoryOrder = @($domainItems | ForEach-Object { [string]$_.Category } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $hostsPlan = New-HostsContent -Entries $entryArray -GeneratedAt $generatedAt -CategoryOrderFromDomains $domainsCategoryOrder
    $hostsPath = Join-Path $OutputDir 'hosts'
    $reportPath = Join-Path $OutputDir '解析报告.txt'
    Write-Utf8File -Path $hostsPath -Content $hostsPlan.Content -WithBom $true

    $reachableCount = @($entryArray | Where-Object { $_.Status -eq '可达' }).Count
    $blockedCount = @($entryArray | Where-Object { $_.Status -eq '阻断' }).Count
    $failedCount = @($entryArray | Where-Object { $_.Status -eq '解析失败' }).Count

    $managedDomains = @($domainItems | ForEach-Object { [string]$_.Domain })
    $mappingLines = @(Get-ManagedMappingLines -Content $hostsPlan.Content)

    $systemHostsResult = $null
    if ($reachableCount -eq 0) {
        $systemHostsResult = New-SystemHostsSkippedResult -Path $SystemHostsPath
    }
    elseif ($NoSystemHosts) {
        $systemHostsResult = New-SystemHostsSkippedResult -Path $SystemHostsPath
    }
    else {
        Write-Host '正在合并本机系统 hosts（保留其他条目）...' -ForegroundColor DarkCyan
        $systemHostsResult = Update-SystemHosts -Path $SystemHostsPath -ManagedDomains $managedDomains -MappingLines $mappingLines -OutputDir $OutputDir
        if ($systemHostsResult.Applied) {
            if (-not $NoFlushDns) {
                $flushResult = Invoke-DnsFlush
                $systemHostsResult.FlushAttempted = $flushResult.Attempted
                $systemHostsResult.FlushOk = $flushResult.Ok
                $systemHostsResult.FlushOutput = $flushResult.Output
                $systemHostsResult.FlushError = $flushResult.Error
            }
            else {
                $systemHostsResult.FlushAttempted = $false
            }
        }
    }

    $routerResult = $null
    if ($reachableCount -eq 0 -or $NoRouterSync) {
        $routerResult = New-RouterSkippedResult -HostName $RouterHost -UserName $RouterUser -Port $RouterPort -Path $RouterHostsPath -FullOverwrite ([bool]$RouterFullOverwrite)
    }
    else {
        Write-Host ('正在同步路由器 hosts: {0}@{1}:{2} ...' -f $RouterUser, $RouterHost, $RouterHostsPath) -ForegroundColor DarkCyan
        $routerResult = Sync-RouterHosts -HostName $RouterHost -UserName $RouterUser -Port $RouterPort -Path $RouterHostsPath -KeyPath $RouterSshKey -OutputDir $OutputDir -ManagedDomains $managedDomains -MappingLines $mappingLines -FullContent $hostsPlan.Content -FullOverwrite ([bool]$RouterFullOverwrite)
    }

    $report = New-ReportContent -Entries $entryArray -GeneratedAt $generatedAt -RawDomainCount $rawCount -InvalidItems $invalidItems -HostsPlan $hostsPlan -SystemHostsResult $systemHostsResult -RouterResult $routerResult -NodeOutput $nodeResult.Output -OutputDir $OutputDir
    Write-Utf8File -Path $reportPath -Content $report -WithBom $true

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ('完成: 共 {0} 个域名 | 写入 hosts {1} | 阻断 {2} | 失败 {3}' -f $uniqueCount, $hostsPlan.TotalCount, $blockedCount, $failedCount) -ForegroundColor Cyan
    Write-Host ('hosts: {0}' -f $hostsPath)
    Write-Host ('报告:  {0}' -f $reportPath)

    if ($null -ne $systemHostsResult) {
        if ($systemHostsResult.Applied) {
            Write-Host ('系统 hosts: 已合并（{0} 条映射）' -f $systemHostsResult.BlockCount) -ForegroundColor Green
        }
        elseif ($systemHostsResult.Skipped) {
            Write-Host '系统 hosts: 已跳过' -ForegroundColor Yellow
        }
        else {
            Write-Host ('系统 hosts: 未写入（{0}）' -f $systemHostsResult.Error) -ForegroundColor Yellow
        }
    }

    if ($null -ne $routerResult) {
        if ($routerResult.Applied) {
            Write-Host ('路由器 hosts: 已同步（{0} 条映射）' -f $routerResult.BlockCount) -ForegroundColor Green
        }
        elseif ($routerResult.Skipped) {
            Write-Host ('路由器 hosts: {0}' -f $routerResult.Status) -ForegroundColor Yellow
            if (-not [string]::IsNullOrWhiteSpace($routerResult.Error)) {
                Write-Host ('  {0}' -f $routerResult.Error) -ForegroundColor DarkYellow
            }
        }
        else {
            Write-Host ('路由器 hosts: 未同步（{0}）' -f $routerResult.Error) -ForegroundColor Yellow
        }
    }

    if ($reachableCount -eq 0) {
        Write-Host '"hosts" 中没有可写入的地址，请查看解析报告。' -ForegroundColor Yellow
        exit 2
    }
    if ($null -ne $systemHostsResult -and -not $systemHostsResult.Applied -and -not $systemHostsResult.Skipped) {
        exit 3
    }
    if ($null -ne $routerResult -and -not $routerResult.Applied -and -not $NoRouterSync) {
        if (-not $routerResult.Skipped) {
            exit 4
        }
        if ($routerResult.Status -eq '未配置') {
            exit 4
        }
    }

    exit 0
}
catch {
    Write-Host ''
    Write-Host ('[错误] {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '请查看上面的提示；如果问题持续，请把本窗口内容发给维护者。' -ForegroundColor DarkGray
    exit 1
}
