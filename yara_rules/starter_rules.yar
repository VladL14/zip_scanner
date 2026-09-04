rule EICAR_Test_String {
    meta:
        description = "Standard AV test string"
        author = "Clean-Room"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell execution policies and commands"
        author = "Clean-Room"
    strings:
        $ps1 = "powershell -ExecutionPolicy Bypass" nocase
        $ps2 = "powershell.exe -ep bypass" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "Invoke-Mimikatz" nocase
    condition:
        any of them
}

rule Embedded_PE {
    meta:
        description = "Detects embedded Windows PE executables inside other files"
        author = "Clean-Room"
    strings:
        $mz = "MZ"
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 or ($mz and $dos_stub)
}
