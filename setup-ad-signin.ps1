# setup-ad-signin.ps1 - from your PC: copy the AD sign-in files to the platform server and run the guided setup there.
# Usage (PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\setup-ad-signin.ps1
#   powershell -ExecutionPolicy Bypass -File .\setup-ad-signin.ps1 -Server asicoad@10.100.12.134 -Repo C:\Users\Syed\as-auth
# Gets (or updates) the as-auth repository, copies the five files the setup needs to /tmp/as-auth-ad on the server and
# starts setup-ad-signin.sh in an SSH terminal. The server asks for the asicoad password (and sudo); the service-account
# and test-user passwords are typed at the server's own hidden prompts - they never pass through this script.
param(
  [string]$Server = 'asicoad@10.100.12.134',
  [string]$Repo   = 'C:\Users\Syed\as-auth'
)
$ErrorActionPreference = 'Stop'
$files = 'as-auth.js', 'ldap-client.js', 'as-auth-ldap.js', 'install-ad.sh', 'setup-ad-signin.sh'

Write-Host "=== 1. the as-auth repository ($Repo)" -ForegroundColor Cyan
if (Test-Path (Join-Path $Repo '.git')) {
  Push-Location $Repo; try { git pull --ff-only; if ($LASTEXITCODE) { throw "git pull failed in $Repo" } } finally { Pop-Location }
} else {
  git clone https://github.com/meeranpmo-svg/as-auth $Repo; if ($LASTEXITCODE) { throw "git clone failed - check your GitHub sign-in" }
}
foreach ($f in $files) { if (-not (Test-Path (Join-Path $Repo $f))) { throw "$f is missing in $Repo - git pull first" } }

Write-Host "`n=== 2. copy to ${Server}:/tmp/as-auth-ad" -ForegroundColor Cyan
ssh $Server 'rm -rf /tmp/as-auth-ad && mkdir -m 700 /tmp/as-auth-ad'; if ($LASTEXITCODE) { throw "ssh to $Server failed" }
$paths = $files | ForEach-Object { Join-Path $Repo $_ }
scp @paths "${Server}:/tmp/as-auth-ad/"; if ($LASTEXITCODE) { throw "scp failed" }
# a Windows checkout may have CRLF line ends: bash and node need LF
ssh $Server "sed -i 's/\r$//' /tmp/as-auth-ad/*.sh /tmp/as-auth-ad/*.js"; if ($LASTEXITCODE) { throw "could not prepare the files" }

Write-Host "`n=== 3. guided setup on the server (answer its questions)" -ForegroundColor Cyan
ssh -t $Server 'sudo bash /tmp/as-auth-ad/setup-ad-signin.sh; rc=$?; rm -rf /tmp/as-auth-ad; exit $rc'
if ($LASTEXITCODE) { Write-Host "`nThe setup stopped - the message above says why. Fix it and run this script again (it is safe to repeat)." -ForegroundColor Yellow; exit $LASTEXITCODE }
Write-Host "`nDone." -ForegroundColor Green
