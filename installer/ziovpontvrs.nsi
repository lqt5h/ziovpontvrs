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

Function IsVCRedistInstalled
    ReadRegDWORD $0 HKLM "${VCREDIST_REG_KEY}" "Installed"
    ${If} $0 == 1
        Push 1
    ${Else}
        Push 0
    ${EndIf}
FunctionEnd

; ============================================================
; Req 1-3: install artifacts, dependencies, register service
; ============================================================
Section "Install"
    SetOutPath "$INSTDIR"

    ; --- Req 1: all build artifacts ---
    File "${EXE_GUI}"
    File "${EXE_SVC}"

    ; --- Default AV database files ---
    File "default_manifest.bin"
    File "default_data.bin"

    ; --- Req 2: third-party dependencies ---
    Call IsVCRedistInstalled
    Pop $0
    ${If} $0 == 0
        DetailPrint "Installing Visual C++ Redistributable..."
        SetOutPath "$TEMP"
        File "${VCREDIST_EXE}"
        nsExec::ExecToLog '"$TEMP\${VCREDIST_EXE}" /install /quiet /norestart'
        Pop $1
        Delete "$TEMP\${VCREDIST_EXE}"
        WriteRegDWORD HKLM "${REG_APP}" "VCRedistInstalledByUs" 1
    ${Else}
        DetailPrint "Visual C++ Redistributable already present."
        WriteRegDWORD HKLM "${REG_APP}" "VCRedistInstalledByUs" 0
    ${EndIf}

    SetOutPath "$INSTDIR"
    WriteUninstaller "$INSTDIR\${UNINSTALLER}"

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

    ; --- Req 3: register Windows service for auto-start ---
    ; Clean up any leftover service from previous install
    DetailPrint "Cleaning up previous service registration..."
    nsExec::ExecToLog 'taskkill /F /IM ${EXE_GUI}'
    Pop $0
    nsExec::ExecToLog 'taskkill /F /IM ${EXE_SVC}'
    Pop $0
    Sleep 1000
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    Pop $0
    Sleep 1000

    DetailPrint "Registering service ${SERVICE_NAME}..."
    nsExec::ExecToLog '"$INSTDIR\${EXE_SVC}" install'
    Pop $0

    ; Force auto-start in case CreateServiceW silently failed
    DetailPrint "Ensuring auto-start configuration..."
    nsExec::ExecToLog 'sc config ${SERVICE_NAME} start= auto'
    Pop $0

    DetailPrint "Starting service ${SERVICE_NAME}..."
    nsExec::ExecToLog 'sc start ${SERVICE_NAME}'
    Pop $0

    ; Verify service is running
    DetailPrint "Verifying service status..."
    nsExec::ExecToLog 'sc query ${SERVICE_NAME}'
    Pop $0
SectionEnd

; ============================================================
; Req 4-6: stop service, remove dependencies, delete files
; ============================================================
Section "Uninstall"
    ; --- Req 6: stop and remove the service ---
    DetailPrint "Killing GUI process..."
    nsExec::ExecToLog 'taskkill /F /IM ${EXE_GUI}'
    Pop $0

    DetailPrint "Killing service process..."
    nsExec::ExecToLog 'taskkill /F /IM ${EXE_SVC}'
    Pop $0
    Sleep 2000

    DetailPrint "Removing service ${SERVICE_NAME}..."
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    Pop $0
    Sleep 1000

    ; --- Req 5: remove dependencies if installed by us ---
    ReadRegDWORD $0 HKLM "${REG_APP}" "VCRedistInstalledByUs"
    ${If} $0 == 1
        DetailPrint "Removing Visual C++ Redistributable..."
        nsExec::ExecToLog '"$TEMP\vc_redist.x64.exe" /uninstall /quiet /norestart'
        Pop $1
        nsExec::ExecToLog 'MsiExec.exe /x{F4499EE3-A166-496C-81BB-51D1BCDC70A9} /quiet /norestart'
        Pop $1
    ${Else}
        DetailPrint "Visual C++ Redistributable was not installed by us, keeping it."
    ${EndIf}

    ; --- Req 4: remove all application files ---
    Delete "$INSTDIR\${EXE_GUI}"
    Delete "$INSTDIR\${EXE_SVC}"
    Delete "$INSTDIR\${UNINSTALLER}"
    Delete "$INSTDIR\default_manifest.bin"
    Delete "$INSTDIR\default_data.bin"
    Delete "$INSTDIR\manifest.bin"
    Delete "$INSTDIR\data.bin"
    Delete "$INSTDIR\manifest.bin.bak"
    Delete "$INSTDIR\data.bin.bak"
    RMDir "$INSTDIR"

    ; Clean up registry
    DeleteRegKey HKLM "${REG_UNINSTALL}"
    DeleteRegKey HKLM "${REG_APP}"
SectionEnd
