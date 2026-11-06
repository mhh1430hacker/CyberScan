rule EncodedPowerShell {
  meta:
    description = "Encoded PowerShell execution pattern"
    tags = "powershell, obfuscation"
  strings:
    $p1 = "powershell" nocase
    $p2 = "-enc" nocase
    $p3 = "FromBase64String" nocase
  condition:
    ($p1 and $p2) or $p3
}

rule SuspiciousProcessInjection {
  meta:
    description = "Memory and remote thread APIs associated with process injection"
    tags = "injection, memory"
  strings:
    $a = "VirtualAlloc" ascii
    $b = "WriteProcessMemory" ascii
    $c = "CreateRemoteThread" ascii
    $d = "IsDebuggerPresent" ascii
  condition:
    2 of ($a,$b,$c,$d)
}

rule ShadowCopyDeletion {
  meta:
    description = "Shadow copy deletion associated with ransomware behavior"
    tags = "ransomware, persistence"
  strings:
    $s1 = "vssadmin delete shadows" nocase
    $s2 = "wmic shadowcopy delete" nocase
  condition:
    1 of ($s1,$s2)
}
