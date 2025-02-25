if ($funciones_previas.count -le 1) {$funciones_previas = (ls function:).Name}
function menu {
[array]$funciones_nuevas = (ls function: | Where-Object {($_.name).Length -ge "4" -and $_.name -notlike "Clear-Host*" -and $_.name -notlike "ConvertFrom-SddlString*" -and $_.name -notlike "Format-Hex*" -and $_.name -notlike "Get-FileHash*" -and $_.name -notlike "Get-Verb*" -and $_.name -notlike "help" -and $_.name -notlike "Import-PowerShellDataFile*" -and $_.name -notlike "ImportSystemModules*" -and $_.name -ne "Main" -and $_.name -ne "mkdir" -and $_.name -ne "cd.." -and $_.name -ne "mkdir" -and $_.name -ne "more" -and $_.name -notlike "New-Guid*" -and $_.name -notlike "New-TemporaryFile*" -and $_.name -ne "Pause" -and $_.name -notlike "TabExpansion2*" -and $_.name -ne "prompt" -and $_.name -ne "menu" -and $_.name -ne "auto" -and $_.name -notlike "show-methods-loaded*" } | select-object name ).name
$muestra_funciones = ($funciones_nuevas | where {$funciones_precargadas -notcontains $_}) | foreach {"`n[+] $_"}
$muestra_funciones = $muestra_funciones -replace "  ","" 
$menu = $muestra_funciones + "`n"
$menu = $menu -replace " [+]","[+]"
Write-Host $menu
}

function auto {
[array]$funciones_nuevas = (ls function: | Where-Object {($_.name).Length -ge "4" -and $_.name -notlike "Clear-Host*" -and $_.name -notlike "ConvertFrom-SddlString" -and $_.name -notlike "Format-Hex" -and $_.name -notlike "Get-FileHash*" -and $_.name -notlike "Get-Verb*" -and $_.name -notlike "help" -and $_.name -ne "Import-PowerShellDataFile" -and $_.name -ne "ImportSystemModules" -and $_.name -ne "Main" -and $_.name -ne "mkdir" -and $_.name -ne "cd.." -and $_.name -ne "mkdir" -and $_.name -ne "more" -and $_.name -ne "New-Guid" -and $_.name -ne "New-TemporaryFile" -and $_.name -ne "Pause" -and $_.name -ne "TabExpansion2" -and $_.name -ne "prompt" -and $_.name -ne "menu" -and $_.name -ne "show-methods-loaded"} | select-object name ).name
$muestra_funciones = ($funciones_nuevas | where {$funciones_precargadas -notcontains $_}) | foreach {"$_`n"}
$muestra_funciones = $muestra_funciones -replace "  ","" 
$muestra_funciones
}

function show-methods-loaded {$global:showmethods}
