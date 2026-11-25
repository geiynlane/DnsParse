#requires -Version 5.1
<#
    配置路由器 SSH 免密登录（一次性）
    ------------------------------------------------------------
    只使用 Windows 自带 OpenSSH。生成专用 ed25519 密钥，把公钥
    追加到路由器的 /root/.ssh/authorized_keys 和 /etc/dropbear/authorized_keys
    （兼容 OpenWrt 的 Dropbear）。路由器密码只在本次交互中由 ssh 提示输入，
    不写入脚本、配置文件或报告。
#>

[CmdletBinding()]
param(
    [string]$RouterHost = '10.0.0.1',
    [string]$RouterUser = 'root',
    [ValidateRange(1, 65535)]
    [int]$Port = 22,
    [string]$KeyPath = '',
    [ValidateRange(3, 60)]
    [int]$TimeoutSec = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}
catch {
    # 终端不支持修改编码时继续。
}

function Write-Step {
    param(
        [string]$Message,
        [string]$Color = 'Gray'
    )
    Write-Host $Message -ForegroundColor $Color
}

function Resolve-OpenSshExe {
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

function Invoke-OpenSshNative {
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [switch]$Capture
    )

    # ssh 在“尚未配置免密”时会把 Permission denied 写到 stderr。
    # 这里临时关闭 Stop，避免预期内的 stderr 变成终止错误。
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Capture) {
            $output = & $Exe @Arguments 2>&1
            $code = $LASTEXITCODE
            if ($null -eq $code) { $code = 1 }

            # 只保留可读消息，避免把 PowerShell 的 NativeCommandError 堆栈写进提示。
            $parts = @()
            foreach ($item in @($output)) {
                if ($item -is [System.Management.Automation.ErrorRecord]) {
                    $parts += $item.Exception.Message
                }
                else {
                    $parts += [string]$item
                }
            }
            return [PSCustomObject]@{
                Code = $code
                Text = (($parts -join [Environment]::NewLine).Trim())
            }
        }

        # 交互模式：输出直接送到控制台，不能进入函数返回值，
        # 否则调用方拿到的是“字符串数组 + 结果对象”，访问 .Code 会失败。
        & $Exe @Arguments | Out-Host
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 1 }
        return [PSCustomObject]@{
            Code = $code
            Text = ''
        }
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
}

if ([string]::IsNullOrWhiteSpace($KeyPath)) {
    $KeyPath = Join-Path $HOME '.ssh\dnsparse_router_ed25519'
}
else {
    $KeyPath = [System.IO.Path]::GetFullPath($KeyPath)
}

$keyDir = [System.IO.Path]::GetDirectoryName($KeyPath)
$pubPath = $KeyPath + '.pub'
$ssh = Resolve-OpenSshExe -Name 'ssh.exe'
$keygen = Resolve-OpenSshExe -Name 'ssh-keygen.exe'
$target = ('{0}@{1}' -f $RouterUser, $RouterHost)

Write-Step ''
Write-Step '============================================================' 'Cyan'
Write-Step '        路由器 SSH 免密配置（一次性）' 'Cyan'
Write-Step '============================================================' 'Cyan'
Write-Step ('路由器: {0}:{1}' -f $RouterHost, $Port) 'DarkGray'
Write-Step ('账号  : {0}' -f $RouterUser) 'DarkGray'
Write-Step ('密钥  : {0}' -f $KeyPath) 'DarkGray'
Write-Step ''

if (-not [System.IO.Directory]::Exists($keyDir)) {
    [void][System.IO.Directory]::CreateDirectory($keyDir)
}

function Get-RouterPublicKey {
    param(
        [string]$PrivateKey,
        [string]$PublicKeyPath,
        [string]$KeygenExe
    )

    # 从私钥导出公钥；.pub 可能缺失、带 CRLF，甚至与私钥不匹配。
    $derived = Invoke-OpenSshNative -Exe $KeygenExe -Arguments @(
        '-y', '-P', '""', '-f', $PrivateKey
    ) -Capture
    if ($derived.Code -ne 0) {
        return [PSCustomObject]@{ Key = ''; Error = $derived.Text }
    }

    $line = $derived.Text -split "`r?`n" |
        Where-Object { $_ -match '^(ssh-|ecdsa-)' } |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($line)) {
        return [PSCustomObject]@{ Key = ''; Error = 'ssh-keygen 输出中没有公钥行' }
    }

    $key = $line.Trim()
    $existingPub = ''
    if ([System.IO.File]::Exists($PublicKeyPath)) {
        $rawPub = Get-Content -LiteralPath $PublicKeyPath -Raw
        if ($null -ne $rawPub) {
            $existingPub = ([string]$rawPub).Trim()
        }
    }
    if ($existingPub -ne $key) {
        try {
            [System.IO.File]::WriteAllText($PublicKeyPath, ($key + "`n"), (New-Object System.Text.UTF8Encoding($false)))
        }
        catch {
            # .pub 只是方便下次查看；写不进去不影响本次安装，公钥已从私钥导出。
        }
    }
    return [PSCustomObject]@{ Key = $key; Error = '' }
}

function New-RouterKey {
    param(
        [string]$PrivateKey,
        [string]$PublicKeyPath,
        [string]$KeygenExe
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ([System.IO.File]::Exists($PrivateKey)) {
        [void](Move-Item -LiteralPath $PrivateKey -Destination ($PrivateKey + '.bak-' + $stamp) -Force)
    }
    if ([System.IO.File]::Exists($PublicKeyPath)) {
        [void](Move-Item -LiteralPath $PublicKeyPath -Destination ($PublicKeyPath + '.bak-' + $stamp) -Force)
    }

    # Windows PowerShell 5.1 传递给原生程序时，'""' 表示空口令。
    $result = Invoke-OpenSshNative -Exe $KeygenExe -Arguments @(
        '-t', 'ed25519', '-N', '""', '-f', $PrivateKey, '-C', 'dnsparse@pc'
    ) -Capture
    if (-not [System.IO.File]::Exists($PrivateKey)) {
        throw ('ssh-keygen 生成密钥失败: {0}' -f $result.Text)
    }
}

if (-not [System.IO.File]::Exists($KeyPath)) {
    Write-Step '正在生成专用 ed25519 密钥（无口令，仅用于这台路由器）...' 'Yellow'
    New-RouterKey -PrivateKey $KeyPath -PublicKeyPath $pubPath -KeygenExe $keygen
    Write-Step '密钥已生成。' 'Green'
}
else {
    Write-Step '已存在专用密钥，继续检查登录状态。' 'DarkGray'
}

$pubInfo = Get-RouterPublicKey -PrivateKey $KeyPath -PublicKeyPath $pubPath -KeygenExe $keygen
$pubKey = $pubInfo.Key

# 旧密钥可能带口令、损坏或 .pub 丢失导致无法导出。既然路由器端还没有
# 可用的免密登录，备份旧密钥并重新生成一把无口令密钥是最稳妥的恢复方式。
if ([string]::IsNullOrWhiteSpace($pubKey)) {
    Write-Step '现有密钥无法导出公钥，将备份旧密钥并重新生成。' 'Yellow'
    New-RouterKey -PrivateKey $KeyPath -PublicKeyPath $pubPath -KeygenExe $keygen
    $pubInfo = Get-RouterPublicKey -PrivateKey $KeyPath -PublicKeyPath $pubPath -KeygenExe $keygen
    $pubKey = $pubInfo.Key
}

if ([string]::IsNullOrWhiteSpace($pubKey)) {
    throw ('无法生成或导出公钥。ssh-keygen: {0}' -f $pubInfo.Error)
}

# 必须是一行，且不能带 CR；否则路由器 authorized_keys 里的键会失效。
$pubKey = ($pubKey -replace "`r", '' -replace "`n", '').Trim()

# 私钥只允许当前用户读取，避免被其他本机账号读取。
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $grant = ('{0}:(R)' -f $identity)
    $aclResult = Invoke-OpenSshNative -Exe "$env:SystemRoot\System32\icacls.exe" -Arguments @(
        $KeyPath, '/inheritance:r', '/grant:r', $grant
    ) -Capture
    if ($aclResult.Code -ne 0) {
        Write-Step '提示: 无法自动收紧私钥权限（可能文件由管理员创建）；如果 ssh 能正常登录，可继续。' 'DarkYellow'
    }
}
catch {
    Write-Step ('提示: 私钥权限收紧失败: {0}' -f $_.Exception.Message) 'DarkYellow'
}

$testArgs = @(
    '-i', $KeyPath,
    '-p', [string]$Port,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'PreferredAuthentications=publickey',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', ('ConnectTimeout={0}' -f $TimeoutSec),
    $target,
    'echo DNSPARSE_OK'
)

Write-Step '检查是否已经可以免密登录...' 'DarkGray'
$testResult = Invoke-OpenSshNative -Exe $ssh -Arguments $testArgs -Capture
$testCode = $testResult.Code
$testText = $testResult.Text

if ($testCode -eq 0 -and $testText -match 'DNSPARSE_OK') {
    Write-Step ''
    Write-Step '免密登录已经可用，无需重复配置。' 'Green'
    Write-Step ('现在可以直接运行“一键解析DNS V0.7”。') 'Green'
    exit 0
}

# 只有“认证未通过”才继续安装公钥；网络层错误直接提示，避免让用户反复输密码。
if ($testCode -ne 0 -and $testText -match 'Could not resolve|Connection refused|Connection timed out|Connection reset|No route to host|Network is unreachable') {
    Write-Step ''
    Write-Step '无法连接到路由器，请检查地址、端口和网络。' 'Red'
    Write-Step ('ssh 输出: {0}' -f $testText) 'DarkYellow'
    exit 1
}

Write-Step '尚未配置免密登录，开始安装公钥。' 'Yellow'
Write-Step '接下来 ssh 会提示输入路由器密码；密码不会保存。' 'Yellow'
Write-Step ''

# OpenWrt 的 Dropbear 常用 /etc/dropbear/authorized_keys，
# 普通 OpenSSH 用 /root/.ssh/authorized_keys；两边都写，避免路由器类型差异。
$remoteLines = @(
    'set -e'
    'umask 077'
    'mkdir -p /root/.ssh /etc/dropbear'
    'touch /root/.ssh/authorized_keys /etc/dropbear/authorized_keys'
    ("grep -qxF '{0}' /root/.ssh/authorized_keys 2>/dev/null || echo '{0}' >> /root/.ssh/authorized_keys" -f $pubKey)
    ("grep -qxF '{0}' /etc/dropbear/authorized_keys 2>/dev/null || echo '{0}' >> /etc/dropbear/authorized_keys" -f $pubKey)
    'chmod 700 /root/.ssh /etc/dropbear'
    'chmod 600 /root/.ssh/authorized_keys /etc/dropbear/authorized_keys'
    'echo DNSPARSE_KEY_INSTALLED'
)
$remoteCommand = ($remoteLines -join "`n")

$installArgs = @(
    '-p', [string]$Port,
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', ('ConnectTimeout={0}' -f $TimeoutSec),
    '-o', 'NumberOfPasswordPrompts=1',
    $target,
    $remoteCommand
)

# 这里不重定向输出，确保 ssh 的密码提示能直接显示在控制台。
$installResult = Invoke-OpenSshNative -Exe $ssh -Arguments $installArgs
$installCode = $installResult.Code

if ($installCode -ne 0) {
    Write-Step ''
    Write-Step '自动安装公钥失败。可以手动完成：' 'Red'
    Write-Step ''
    Write-Step '1. 复制下面这一整行公钥：' 'Yellow'
    Write-Step $pubKey 'White'
    Write-Step ''
    Write-Step '2. 登录路由器后执行：' 'Yellow'
    Write-Step '   mkdir -p /root/.ssh /etc/dropbear' 'White'
    Write-Step '   chmod 700 /root/.ssh /etc/dropbear' 'White'
    Write-Step ('   echo ''{0}'' >> /root/.ssh/authorized_keys' -f $pubKey) 'White'
    Write-Step ('   echo ''{0}'' >> /etc/dropbear/authorized_keys' -f $pubKey) 'White'
    Write-Step '   chmod 600 /root/.ssh/authorized_keys /etc/dropbear/authorized_keys' 'White'
    Write-Step ''
    Write-Step '3. 再运行一次本配置脚本验证。' 'Yellow'
    exit 1
}

Write-Step ''
Write-Step '公钥已写入，正在验证免密登录...' 'DarkGray'
Start-Sleep -Milliseconds 300
$verifyResult = Invoke-OpenSshNative -Exe $ssh -Arguments $testArgs -Capture
$verifyCode = $verifyResult.Code
$verifyText = $verifyResult.Text

if ($verifyCode -eq 0 -and $verifyText -match 'DNSPARSE_OK') {
    Write-Step ''
    Write-Step '配置成功：现在可以免密登录路由器。' 'Green'
    Write-Step '之后双击“一键解析DNS V0.7”会自动同步路由器 hosts。' 'Green'
    exit 0
}

Write-Step ''
Write-Step '公钥已写入，但免密验证失败。' 'Red'
Write-Step ('ssh 输出: {0}' -f $verifyText) 'DarkYellow'
Write-Step '请检查这两个文件里是否有刚写入的公钥：' 'Yellow'
Write-Step '  /root/.ssh/authorized_keys' 'White'
Write-Step '  /etc/dropbear/authorized_keys' 'White'
Write-Step '并确认 Dropbear 允许 root 使用公钥登录、文件权限为 600、目录为 700。' 'Yellow'
exit 1
