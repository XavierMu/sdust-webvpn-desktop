<#
.SYNOPSIS
    构建便携版 zip（dist\SDUST-WebVPN-<版本>-portable.zip）

.DESCRIPTION
    本项目的发布形态是「便携版」：数据目录跟随 exe，不写注册表和系统目录，
    所以不产出 NSIS 安装包，只打包成 zip。

    流程：cargo 构建 release exe → 连同使用说明和许可证一起压缩。

.EXAMPLE
    pwsh -File scripts\build-portable.ps1
#>
[CmdletBinding()]
param(
    # 跳过 cargo 构建，直接拿现有的 release exe 打包
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# 显式按 UTF-8 读：Windows PowerShell 5.1 的 Get-Content 默认用系统代码页，会把中文读坏
$confText = [System.IO.File]::ReadAllText((Join-Path $root 'src-tauri\tauri.conf.json'), [System.Text.Encoding]::UTF8)
$conf = $confText | ConvertFrom-Json
$version = $conf.version
$exeName = 'SDUST WebVPN.exe'

if (-not $SkipBuild) {
    Write-Host "==> 构建 release（版本 $version）" -ForegroundColor Cyan
    Push-Location $root
    try {
        pnpm tauri build
        if ($LASTEXITCODE -ne 0) { throw "构建失败，退出码 $LASTEXITCODE" }
    }
    finally { Pop-Location }
}

$exe = Join-Path $root 'src-tauri\target\release\sdust-webvpn.exe'
if (-not (Test-Path $exe)) { throw "找不到 exe：$exe（先跑一次不带 -SkipBuild 的构建）" }

$stageRoot = Join-Path $env:TEMP "vpn-pack-$(Get-Random)"
$stage = Join-Path $stageRoot "SDUST-WebVPN-$version-portable"
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Copy-Item $exe (Join-Path $stage $exeName)
foreach ($f in @('使用说明.txt', 'LICENSE.txt')) {
    $src = Join-Path $root "dist\$f"
    if (Test-Path $src) { Copy-Item $src $stage } else { Write-Warning "缺少 $f（$src）" }
}

$outDir = Join-Path $root 'dist'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$zip = Join-Path $outDir "SDUST-WebVPN-$version-portable.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
Remove-Item $stageRoot -Recurse -Force -ErrorAction SilentlyContinue

$mb = [math]::Round((Get-Item $zip).Length / 1MB, 2)
Write-Host "==> 完成：$zip（$mb MB）" -ForegroundColor Green
