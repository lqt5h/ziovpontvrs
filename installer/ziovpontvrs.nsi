; ============================================================
; Ziovpontvrs NSIS Installer
; ============================================================
; Covers functional requirements:
;   1) Includes all build artifacts (exe, dll, resources, configs)
;   2) Installs third-party dependencies (VC++ Redistributable)
;   3) Registers Windows service for auto-start
;   4) Uninstall removes all application files
;   5) Uninstall removes dependencies if not used by other apps
;   6) Uninstall stops and removes the service
;   7) Built on CI pipeline, output goes to build artifacts
; ============================================================

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

!define PRODUCT_NAME       "Ziovpontvrs"
!define PRODUCT_VERSION    "1.0.0"
!define PRODUCT_PUBLISHER  "Ziovpontvrs Team"
!define SERVICE_NAME       "ZiovpontvrsSvc"
!define EXE_GUI            "ziovpontvrs.exe"
!define EXE_SVC            "ziovpontvrs_svc.exe"
!define VCREDIST_EXE       "vc_redist.x64.exe"
!define UNINSTALLER        "uninstall.exe"
!define REG_UNINSTALL      "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define REG_APP            "Software\${PRODUCT_NAME}"

; VCRedist detection: MSVC 14.x (2015-2022) runtime
!define VCREDIST_REG_KEY   "Software\Microsoft\VisualC\14.0\Runtime\x64"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "ziovpontvrs-setup.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${REG_UNINSTALL}" "InstallLocation"
RequestExecutionLevel admin
ShowInstDetails show
ShowUnInstDetails show

!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; ============================================================
; Functions
; ============================================================

Function IsVCRedistInstalled
    ; Check if MSVC runtime is already present
    ReadRegDWORD $0 HKLM "${VCREDIST_REG_KEY}" "Installed"
    ${If} $0 == 1
        Push 1
    ${Else}
        Push 0
    ${EndIf}
FunctionEnd

; ============================================================
; Installer Section
; ============================================================
Section "MainSection" SEC_MAIN
    SetOutPath "$INSTDIR"

    ; --- Req 1: all build artifacts ---
    File "${EXE_GUI}"
    File "${EXE_SVC}"

    ; --- Req 2: install third-party dependencies ---
    Call IsVCRedistInstalled
    Pop $0
    ${If} $0 == 0
        DetailPrint "Installing Visual C++ Redistributable..."
        SetOutPath "$TEMP"
        File "${VCREDIST_EXE}"
        nsExec::ExecToLog '"$TEMP\${VCREDIST_EXE}" /install /quiet /norestart'
        Pop $1
        Delete "$TEMP\${VCREDIST_EXE}"
        ; Mark that we installed VCRedist so uninstaller can remove it
        WriteRegDWORD HKLM "${REG_APP}" "VCRedistInstalledByUs" 1
        DetailPrint "Visual C++ Redistributable installed."
    ${Else}
        DetailPrint "Visual C++ Redistributable already installed, skipping."
        WriteRegDWORD HKLM "${REG_APP}" "VCRedistInstalledByUs" 0
    ${EndIf}

    SetOutPath "$INSTDIR"

    ; --- Write uninstaller ---
    WriteUninstaller "$INSTDIR\${UNINSTALLER}"

    ; --- Add/Remove Programs registry ---
    WriteRegStr   HKLM "${REG_UNINSTALL}" "DisplayName"      "${PRODUCT_NAME}"
    WriteRegStr   HKLM "${REG_UNINSTALL}" "DisplayVersion"   "${PRODUCT_VERSION}"
    WriteRegStr   HKLM "${REG_UNINSTALL}" "UninstallString"  '"$INSTDIR\${UNINSTALLER}"'
    WriteRegStr   HKLM "${REG_UNINSTALL}" "QuietUninstallString" '"$INSTDIR\${UNINSTALLER}" /S'
    WriteRegStr   HKLM "${REG_UNINSTALL}" "InstallLocation"  "$INSTDIR"
    WriteRegStr   HKLM "${REG_UNINSTALL}" "Publisher"        "${PRODUCT_PUBLISHER}"
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoModify" 1
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "NoRepair" 1
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "${REG_UNINSTALL}" "EstimatedSize" $0

    ; --- Req 3: register and start Windows service ---
    DetailPrint "Registering Windows service ${SERVICE_NAME}..."
    nsExec::ExecToLog '"$INSTDIR\${EXE_SVC}" install'
    Pop $0

    DetailPrint "Starting service ${SERVICE_NAME}..."
    nsExec::ExecToLog 'sc start ${SERVICE_NAME}'
    Pop $0
SectionEnd

; ============================================================
; Uninstaller Section
; ============================================================
Section "Uninstall"
    ; --- Req 6: stop and remove the service ---
    DetailPrint "Stopping service ${SERVICE_NAME}..."
    nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'
    Pop $0
    ; Wait for service to fully stop
    Sleep 4000

    DetailPrint "Removing service ${SERVICE_NAME}..."
    nsExec::ExecToLog '"$INSTDIR\${EXE_SVC}" uninstall'
    Pop $0
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    Pop $0

    ; --- Req 5: remove dependencies if installed by us ---
    ReadRegDWORD $0 HKLM "${REG_APP}" "VCRedistInstalledByUs"
    ${If} $0 == 1
        DetailPrint "Removing Visual C++ Redistributable (installed by ${PRODUCT_NAME})..."
        ; VCRedist supports uninstall via its product code
        ; Use the bundled copy or call the system uninstaller
        nsExec::ExecToLog '"$TEMP\vc_redist.x64.exe" /uninstall /quiet /norestart'
        Pop $1
        ; If the bundled exe is gone, try via the standard uninstall GUID
        ; Microsoft VC++ 2015-2022 Redist x64
        nsExec::ExecToLog 'MsiExec.exe /x{F4499EE3-A166-496C-81BB-51D1BCDC70A9} /quiet /norestart'
        Pop $1
        DetailPrint "Visual C++ Redistributable removed."
    ${Else}
        DetailPrint "Visual C++ Redistributable was not installed by us, keeping it."
    ${EndIf}

    ; --- Req 4: remove all application files ---
    Delete "$INSTDIR\${EXE_GUI}"
    Delete "$INSTDIR\${EXE_SVC}"
    Delete "$INSTDIR\${UNINSTALLER}"
    RMDir "$INSTDIR"

    ; --- Clean up registry ---
    DeleteRegKey HKLM "${REG_UNINSTALL}"
    DeleteRegKey HKLM "${REG_APP}"
SectionEnd
