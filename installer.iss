; CyberScan desktop installer (Inno Setup 6).
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer.iss
; Packs dist\CyberScan (built by build.spec) into dist\CyberScan-Setup.exe.
; Installs per user (no admin prompt); history and settings stay in %LOCALAPPDATA%\CyberScan.

#define AppName "CyberScan"
#define AppVersion "2.0.0"

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
Compression=lzma2/max
SolidCompression=yes
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
