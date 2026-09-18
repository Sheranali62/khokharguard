; ============================================================
; LocalGuard Antivirus - Inno Setup installer script
; Build: 1) pyinstaller localguard.spec --noconfirm
;        2) iscc installer\LocalGuard_Setup.iss
; ============================================================

#define MyAppName "LocalGuard Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "LocalGuard"
#define MyAppExeName "LocalGuard.exe"

[Setup]
AppId={{8C6B2F1A-4E93-4B7D-9A51-LOCALGUARD100}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\LocalGuard
DefaultGroupName={#MyAppName}
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=..\dist\installer
OutputBaseFilename=LocalGuard_Setup_{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
; Allow non-admin users to install per-user: LocalGuard_Setup.exe /CURRENTUSER
; installs into %LOCALAPPDATA%\Programs with a per-user Start Menu entry.
PrivilegesRequiredOverridesAllowed=commandline
MinVersion=6.3
SetupIconFile=..\assets\icons\localguard.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start LocalGuard when Windows starts"; \
    GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\dist\LocalGuard\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{userappdata}\LocalGuard"; Flags: uninsneveruninstall
Name: "{userappdata}\LocalGuard\logs"
Name: "{userappdata}\LocalGuard\quarantine"
Name: "{userappdata}\LocalGuard\reports"

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "LocalGuard"; \
    ValueData: """{app}\{#MyAppExeName}"""; Tasks: autostart; \
    Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: \
    "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Keep user data (quarantine, logs, reports) - only remove app files.
Type: filesandordirs; Name: "{app}"
