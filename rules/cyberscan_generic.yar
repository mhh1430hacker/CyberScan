// Claude (AI assistant, Anthropic) worked on this file, 2026-11-06: tightened EncodedPowerShell and SuspiciousProcessInjection against benign false alarms.
rule EncodedPowerShell {
  meta:
    description = "Encoded PowerShell execution pattern"
    tags = "powershell, obfuscation"
  strings:
    $p1 = "powershell" nocase
    $p2 = "-enc" nocase
    $p3 = "FromBase64String" nocase
    $x1 = "Invoke-Expression" nocase
    $x2 = "IEX(" nocase
    $x3 = "IEX (" nocase
  condition:
    // FromBase64String alone is any .NET program decoding Base64; it counts only with script execution.
    ($p1 and $p2) or ($p3 and ($p1 or any of ($x*)))
}

rule SuspiciousProcessInjection {
  meta:
    description = "Memory and remote thread APIs associated with process injection"
    tags = "injection, memory"
  strings:
    $b = "WriteProcessMemory" ascii wide
    $c = "CreateRemoteThread" ascii wide
    $e = "NtCreateThreadEx" ascii wide
    $f = "QueueUserAPC" ascii wide
  condition:
    // Writing into another process, then starting code there. VirtualAlloc and
    // IsDebuggerPresent are imported by the ordinary Microsoft C runtime.
    $b and 1 of ($c, $e, $f)
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
