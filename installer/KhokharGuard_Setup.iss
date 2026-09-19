; ============================================================
; Khokhar & Son's Antivirus - Inno Setup installer script
; Build: 1) pyinstaller khokharguard.spec --noconfirm
;        2) iscc installer\KhokharGuard_Setup.iss
; ============================================================

#define MyAppName "Khokhar & Son's Antivirus"
#define MyAppVersion "1.1.1"
#define MyAppPublisher "Khokhar & Son's"
#define MyAppExeName "KhokharGuard.exe"

[Setup]
AppId={{84E1646A-48F8-467D-939C-3BD9A120208E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\KhokharGuard
DefaultGroupName={#MyAppName}
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=..\dist\installer
OutputBaseFilename=KhokharGuard_Setup_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
; Allow non-admin users to install per-user: KhokharGuard_Setup.exe /CURRENTUSER
; installs into %LOCALAPPDATA%\Programs with a per-user Start Menu entry.
PrivilegesRequiredOverridesAllowed=commandline
MinVersion=6.3
SetupIconFile=..\assets\icons\khokharantivirus.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start KhokharGuard when Windows starts"; \
    GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\dist\KhokharGuard\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{userappdata}\KhokharGuard"; Flags: uninsneveruninstall
Name: "{userappdata}\KhokharGuard\logs"
Name: "{userappdata}\KhokharGuard\quarantine"
Name: "{userappdata}\KhokharGuard\reports"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "KhokharGuard"; \
    ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; \
    Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: \
    "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Keep user data (quarantine, logs, reports) - only remove app files.
Type: filesandordirs; Name: "{app}"
