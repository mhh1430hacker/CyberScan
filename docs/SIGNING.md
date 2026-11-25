# Code signing (Windows app)

Unsigned installers trigger Microsoft Defender SmartScreen ("Windows protected your PC") and some
antivirus heuristics. Signing `CyberScan.exe` and `CyberScan-Setup.exe` with a code-signing
certificate removes the "Unknown publisher" label; SmartScreen reputation then builds up with
downloads (it is immediate only for EV certificates and Azure Trusted Signing).

## How the build signs

`build_windows.ps1` signs both files with `signtool` when one of these is set, and skips signing
(with a yellow note) when none is:

| method | environment variables |
|---|---|
| .pfx file | `CYBERSCAN_SIGN_PFX` (path), `CYBERSCAN_SIGN_PASSWORD` |
| certificate in the Windows store or on a USB token / HSM | `CYBERSCAN_SIGN_THUMBPRINT` (SHA-1 thumbprint) |
| Azure Trusted Signing | `CYBERSCAN_SIGN_DLIB` (path to `Azure.CodeSigning.Dlib.dll`), `CYBERSCAN_SIGN_METADATA` (path to `metadata.json`) |

Optional: `CYBERSCAN_SIGN_TIMESTAMP` (default `http://timestamp.digicert.com`) and
`CYBERSCAN_SIGNTOOL` (otherwise the newest Windows 10/11 SDK `signtool.exe` is used; install the
SDK's "Signing Tools" if it is missing). Every signature is RFC 3161 timestamped, so it stays valid
after the certificate expires, and is verified (`signtool verify /pa`) before the build continues.

Never commit a .pfx or a password; set them in the shell for the build only:

```powershell
$env:CYBERSCAN_SIGN_PFX = "D:\keys\cyberscan.pfx"
$env:CYBERSCAN_SIGN_PASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText  # PowerShell 7
powershell -ExecutionPolicy Bypass -File build_windows.ps1
```

## Getting a certificate

Since June 2023 all public code-signing keys must live on a hardware token or in a cloud HSM, so
an OV/EV certificate comes on a USB token or as a cloud signing service, not as a plain .pfx.

| option | cost (approx., 2026) | notes |
|---|---|---|
| **Azure Trusted Signing** (Microsoft "Artifact Signing") | about USD 10 / month | Cheapest commercial route and trusted by SmartScreen quickly. Needs an Azure subscription and identity validation (organisations, and individual developers in supported countries; check the current eligibility list for Saudi Arabia). Use the `CYBERSCAN_SIGN_DLIB` method. |
| **Certum Open Source Code Signing** | about EUR 25-60 / year + card reader | For open-source projects, issued to an individual. Comes on a smart card (or the SimplySign cloud); install Certum's middleware and use `CYBERSCAN_SIGN_THUMBPRINT`. The publisher shows as "Open Source Developer, <name>". |
| **SSL.com** OV code signing | about USD 130-250 / year | eSigner cloud signing (works with signtool via their CKA tool) or a YubiKey. EV variant costs more but gives instant SmartScreen reputation. |
| Sectigo / DigiCert resellers | USD 200-500 / year | Classic OV/EV on a token. |

Steps (any vendor):

1. Pick the publisher name. It must match a verifiable identity: a registered business (OV/EV) or
   your legal name (individual / open source).
2. Order, then complete validation (ID documents, sometimes a phone call; 1-10 days).
3. Receive the token or cloud credentials, install the vendor's driver/tool.
4. Find the thumbprint: `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Format-List Subject, Thumbprint`.
5. Set the matching variables above and run `build_windows.ps1`.
6. Check: right-click the installer > Properties > Digital Signatures.

The Microsoft Store does not need your own certificate: Microsoft signs MSIX packages it
distributes, and for a classic installer listed in the Store a signed installer is required (see
`docs/stores/microsoft-store.md`).
