rule Malicious_Office_Macro {
    meta:
        description = "Detects strings common in malicious VBA macros"
        author = "Clean-Room"
    strings:
        $s1 = "AutoOpen" nocase
        $s2 = "Document_Open" nocase
        $s3 = "WScript.Shell" nocase
        $s4 = "CreateObject" nocase
        $s5 = "ShellExecute" nocase
    condition:
        3 of them
}

rule Ransomware_Behavior_Indicators {
    meta:
        description = "Detects common ransomware commands used to disable recovery"
        author = "Clean-Room"
    strings:
        $cmd1 = "vssadmin.exe Delete Shadows /All /Quiet" nocase
        $cmd2 = "vssadmin Delete Shadows /All /Quiet" nocase
        $cmd3 = "bcdedit /set {default} recoveryenabled No" nocase
        $cmd4 = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase
    condition:
        any of them
}

rule Webshell_Generic {
    meta:
        description = "Detects common webshell execution patterns"
        author = "Clean-Room"
    strings:
        $php = "eval(base64_decode(" nocase
        $asp = "<% Execute(request(" nocase
        $aspx = "System.Diagnostics.ProcessStartInfo" nocase
    condition:
        any of them
}

rule Credential_Stealer_SQLite {
    meta:
        description = "Detects binaries trying to access browser credential databases"
        author = "Clean-Room"
    strings:
        $s1 = "Login Data" nocase
        $s2 = "Cookies" nocase
        $s3 = "Web Data" nocase
        $s4 = "\\\\Google\\\\Chrome\\\\User Data\\\\" nocase
        $s5 = "sqlite3.dll" nocase
    condition:
        3 of them
}

rule CobaltStrike_Beacon_Strings {
    meta:
        description = "Detects common default strings in un-obfuscated Cobalt Strike payloads"
        author = "Clean-Room"
    strings:
        $s1 = "%s as %s\\\\%s: %d"
        $s2 = "beacon.x64.dll" nocase
        $s3 = "ReflectiveLoader"
    condition:
        any of them
}
