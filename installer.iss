; CyberScan desktop installer (Inno Setup 6).
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer.iss
; Packs dist\CyberScan (built by build.spec) into dist\CyberScan-Setup.exe.
; build_windows.ps1 runs the whole chain (PyInstaller, self-test, optional signing, this script).
; Installs per user (no admin prompt); history and settings stay in %LOCALAPPDATA%\CyberScan.

#define AppName "CyberScan"
; keep AppVersion in step with ui/updater.py APP_VERSION
#define AppVersion "2.1.0"

[Setup]
AppId={{6F1C2B7E-4A9D-4C3B-9E5A-CB5CA2026D17}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=ONYX team
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=CyberScan-Setup
SetupIconFile=ui\assets\cyberscan.ico
UninstallDisplayIcon={app}\CyberScan.exe
; LZMA2 ultra64 (64 MB dictionary) + solid: the smallest installer Inno Setup can make.
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
LZMANumBlockThreads=4
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
AppPublisherURL=https://ainex-ai.xyz/
AppSupportURL=https://ainex-ai.xyz/
AppUpdatesURL=https://ainex-ai.xyz/
; an update closes a running CyberScan first (the in-app updater starts this installer)
CloseApplications=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "dist\CyberScan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\CyberScan.exe"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\CyberScan.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\CyberScan.exe"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent
