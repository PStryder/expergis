param(
    [Parameter(Mandatory=$true)][string]$PythonExe,
    [Parameter(Mandatory=$true)][string]$StateDirectory,
    [ValidateSet('Install','Disable','Remove')][string]$Action='Install',
    [switch]$Apply
)
$ErrorActionPreference='Stop'
$name='Expergis User Runtime'
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$python=(Resolve-Path -LiteralPath $PythonExe).Path
$state=(Resolve-Path -LiteralPath $StateDirectory).Path
$runtimeExe=Join-Path (Split-Path -Parent $python) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $runtimeExe -PathType Leaf)) { throw 'Dedicated venv pythonw.exe is required for hidden logon execution' }
if ($python.Contains('"') -or $state.Contains('"')) { throw 'Unsupported quote in path' }
$arguments='-I -m expergis.windows_runtime run --directory "' + $state + '"'
$plan=@{task=$name; action=$Action; apply=[bool]$Apply; user=$identity.Name;
    executable=$runtimeExe; arguments=$arguments; trigger='At user logon'; privilege='Limited';
    restart='3 attempts, one minute apart'; beforeLogin=$false; wakeComputer=$false;
    secrets='No passwords or runtime keys in task definition'}
$plan | ConvertTo-Json
if (-not $Apply) { Write-Output 'REVIEW ONLY: no task or process changed.'; exit 0 }
# Explicit action-time approval is required before invoking -Apply.
$existing=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($Action -eq 'Install') {
    & $python -I -m expergis.windows_runtime preflight --directory $state
    if ($LASTEXITCODE -ne 0) { throw 'Offline preflight failed' }
    if ($existing) { throw 'Task already exists; do not overwrite without reviewing it.' }
    $a=New-ScheduledTaskAction -Execute $runtimeExe -Argument $arguments -WorkingDirectory $state
    $t=New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
    $p=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $s=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $name -Action $a -Trigger $t -Principal $p -Settings $s | Out-Null
    Write-Output 'Installed for next sign-in. No process started; manual first run remains separate.'
} else {
    if (-not $existing) { throw 'Expected task is absent' }
    if ($existing.Actions.Count -ne 1 -or $existing.Actions[0].Execute -ne $runtimeExe -or
        $existing.Actions[0].Arguments -ne $arguments) { throw 'Task identity does not match; no changes made.' }
    Disable-ScheduledTask -TaskName $name | Out-Null
    & $python -I -m expergis.windows_runtime stop --directory $state
    if ($LASTEXITCODE -ne 0) { throw 'Stop request failed; task disabled, state retained.' }
    if ($Action -eq 'Remove') { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
    Write-Output 'Future startup disabled; graceful stop requested. Private state and credentials retained.'
}
