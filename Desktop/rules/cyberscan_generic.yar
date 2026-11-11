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
    description = "Remote allocate + write + execute APIs associated with process injection"
    tags = "injection, memory"
    // Previously "2 of (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, IsDebuggerPresent)", which
    // matched most MSVC binaries (the C runtime imports VirtualAlloc and IsDebuggerPresent).
  strings:
    $alloc1 = "VirtualAllocEx" ascii wide
    $alloc2 = "NtAllocateVirtualMemory" ascii wide
    $write1 = "WriteProcessMemory" ascii wide
    $write2 = "NtWriteVirtualMemory" ascii wide
    $exec1 = "CreateRemoteThread" ascii wide
    $exec2 = "NtCreateThreadEx" ascii wide
    $exec3 = "QueueUserAPC" ascii wide
    $exec4 = "RtlCreateUserThread" ascii wide
  condition:
    any of ($alloc*) and any of ($write*) and any of ($exec*)
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
