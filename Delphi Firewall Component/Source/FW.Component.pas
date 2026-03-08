unit FW.Component;

{******************************************************************************
  FW.Component - Minimal WFP-Only Firewall Component

  Goals:
  - Detect inbound/outbound network activity from WFP net events.
  - Allow/Block applications using WFP app-id filters.
******************************************************************************}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  FW.WFP.API,
  FW.Types,
  FW.Monitor;

type
  TFirewall = class;

  TFirewallMonitorThread = class(TThread)
  private
    FOwner: TFirewall;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TFirewall);
  end;

  TFirewallInstalledRule = class
  public
    Info: TFirewallRuleInfo;
    FilterIds: TList<UINT64>;
    constructor Create(const ARuleInfo: TFirewallRuleInfo);
    destructor Destroy; override;
  end;

  TFirewall = class(TComponent)
  private
    FEngineHandle: THandle;
    FEventHandle: THandle;
    FActive: Boolean;
    FDynamicSession: Boolean;

    FProviderName: string;
    FProviderGUID: string;
    FSublayerName: string;
    FSublayerGUID: string;

    FProviderKey: TGUID;
    FSublayerKey: TGUID;

    FRules: TObjectList<TFirewallInstalledRule>;
    FDefaultBlockFilterIds: TList<UINT64>;
    FKnownApps: TDictionary<string, Boolean>;
    FConnectionKeys: TDictionary<string, Boolean>;
    FLock: TCriticalSection;

    FMonitor: TNetworkMonitor;
    FMonitorThread: TFirewallMonitorThread;
    FMonitorIntervalMs: Cardinal;

    FOnNewAppDetected: TFirewallAppDetectedEvent;
    FOnBlock: TFirewallTrafficEvent;
    FOnAllow: TFirewallTrafficEvent;
    FOnNewRule: TFirewallRuleEvent;
    FOnDeleteRule: TFirewallRuleEvent;
    FOnError: TFirewallErrorEvent;

    procedure SetActive(const Value: Boolean);

    class procedure WFPNetEventCallback(context: Pointer;
      const event: PFWPM_NET_EVENT1); stdcall; static;

    procedure HandleNetEvent(const event: PFWPM_NET_EVENT1);
    function ParseNetEvent(const event: PFWPM_NET_EVENT1): TFirewallEvent;
    function ExtractAppPath(const appId: FWP_BYTE_BLOB_REC): string;
    function DevicePathToDosPath(const ADevicePath: string): string;

    procedure RaiseError(ACode: DWORD; const AMsg: string);
    procedure CheckResult(AStatus: DWORD; const AContext: string);
    procedure CheckElevation;

    function ParseGuidOrDefault(const AValue, ADefault: string): TGUID;
    function NormalizeManagedAppPath(const APath: string): string;

    procedure OpenEngine;
    procedure CloseEngine;
    procedure InstallProviderAndSublayer;
    procedure RemoveProviderAndSublayer;
    procedure EnableNetEventCollection;
    procedure SubscribeEvents;
    procedure UnsubscribeEvents;

    function IsNewApp(const APath: string): Boolean;
    procedure DispatchNetEvent(const AEvent: TFirewallEvent; ANewApp: Boolean);

    function FindRuleIndex(const ARuleID: TGUID): Integer;
    function AddRuleInternal(const AFilePath: string;
      AAction: TFirewallAction): TGUID;
    procedure InstallRuleFilters(ARule: TFirewallInstalledRule);
    procedure RemoveRuleFilters(ARule: TFirewallInstalledRule);
    procedure InstallDefaultBlockFilters;
    procedure RemoveDefaultBlockFilters;
    procedure PurgeManagedFilters;
    procedure ClearTrackedFilterIds;

    procedure StartMonitor;
    procedure StopMonitor;
    procedure MonitorTick;
    function ConnectionKey(const Conn: TNetworkConnection): string;
    function InferDirection(const Conn: TNetworkConnection): TFirewallDirection;
    function ConnectionToEvent(const Conn: TNetworkConnection): TFirewallEvent;

  protected
    procedure Loaded; override;

  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function AllowApplication(const AFilePath: string): TGUID;
    function BlockApplication(const AFilePath: string): TGUID;
    function DeleteRule(const ARuleID: TGUID): Boolean;
    procedure ClearRules;
    function GetRuleCount: Integer;

    function GetFileDetails(const AFilePath: string): TFirewallFileDetails;

  published
    property Active: Boolean read FActive write SetActive default False;
    property DynamicSession: Boolean read FDynamicSession write FDynamicSession
      default False;
    property MonitorIntervalMs: Cardinal read FMonitorIntervalMs
      write FMonitorIntervalMs default 200;

    property ProviderName: string read FProviderName write FProviderName;
    property ProviderGUID: string read FProviderGUID write FProviderGUID;
    property SublayerName: string read FSublayerName write FSublayerName;
    property SublayerGUID: string read FSublayerGUID write FSublayerGUID;

    property OnNewAppDetected: TFirewallAppDetectedEvent
      read FOnNewAppDetected write FOnNewAppDetected;
    property OnBlock: TFirewallTrafficEvent read FOnBlock write FOnBlock;
    property OnAllow: TFirewallTrafficEvent read FOnAllow write FOnAllow;
    property OnNewRule: TFirewallRuleEvent read FOnNewRule write FOnNewRule;
    property OnDeleteRule: TFirewallRuleEvent
      read FOnDeleteRule write FOnDeleteRule;
    property OnError: TFirewallErrorEvent read FOnError write FOnError;
  end;

implementation

uses
  System.Math,
  System.IOUtils,
  FW.IpHelper.API;

type
  PWinTrustFileInfo = ^TWinTrustFileInfo;
  TWinTrustFileInfo = record
    cbStruct: DWORD;
    pcwszFilePath: LPCWSTR;
    hFile: THandle;
    pgKnownSubject: PGUID;
  end;

  PWinTrustData = ^TWinTrustData;
  TWinTrustData = record
    cbStruct: DWORD;
    pPolicyCallbackData: Pointer;
    pSIPClientData: Pointer;
    dwUIChoice: DWORD;
    fdwRevocationChecks: DWORD;
    dwUnionChoice: DWORD;
    pFile: PWinTrustFileInfo;
    dwStateAction: DWORD;
    hWVTStateData: THandle;
    pwszURLReference: LPCWSTR;
    dwProvFlags: DWORD;
    dwUIContext: DWORD;
    pSignatureSettings: Pointer;
  end;

  HCERTSTORE = Pointer;
  PHCERTSTORE = ^HCERTSTORE;
  HCRYPTMSG = Pointer;
  PHCRYPTMSG = ^HCRYPTMSG;

  TCryptoApiBlob = record
    cbData: DWORD;
    pbData: PByte;
  end;

  PFWPMFilterPtrArray = ^TFWPMFilterPtrArray;
  TFWPMFilterPtrArray = array[0..0] of PFWPM_FILTER0;

  PCertInfo = ^TCertInfo;
  TCertInfo = record
    dwVersion: DWORD;
    SerialNumber: TCryptoApiBlob;
  end;

  PCertContext = ^TCertContext;
  TCertContext = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: PCertInfo;
    hCertStore: HCERTSTORE;
  end;

const
  WTD_UI_NONE = 2;
  WTD_REVOKE_NONE = 0;
  WTD_CHOICE_FILE = 1;
  WTD_STATEACTION_VERIFY = 1;
  WTD_STATEACTION_CLOSE = 2;
  WTD_CACHE_ONLY_URL_RETRIEVAL = $00000004;

  CERT_QUERY_OBJECT_FILE = 1;
  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = $00000002;
  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = $00000080;
  CERT_QUERY_FORMAT_FLAG_BINARY = $00000001;

  CERT_NAME_ISSUER_FLAG = 1;
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

  WINTRUST_ACTION_GENERIC_VERIFY_V2: TGUID =
    '{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}';

function WinVerifyTrust(hwnd: HWND; const ActionID: TGUID;
  ActionData: Pointer): Longint; stdcall; external 'wintrust.dll';

function CryptQueryObject(
  dwObjectType: DWORD;
  pvObject: Pointer;
  dwExpectedContentTypeFlags: DWORD;
  dwExpectedFormatTypeFlags: DWORD;
  dwFlags: DWORD;
  pdwMsgAndCertEncodingType: PDWORD;
  pdwContentType: PDWORD;
  pdwFormatType: PDWORD;
  phCertStore: PHCERTSTORE;
  phMsg: PHCRYPTMSG;
  ppvContext: Pointer
): BOOL; stdcall; external 'crypt32.dll';

function CertEnumCertificatesInStore(hCertStore: HCERTSTORE;
  pPrevCertContext: PCertContext): PCertContext; stdcall;
  external 'crypt32.dll';

function CertGetNameStringW(pCertContext: PCertContext; dwType, dwFlags: DWORD;
  pvTypePara: Pointer; pszNameString: PWideChar;
  cchNameString: DWORD): DWORD; stdcall; external 'crypt32.dll';

function CertFreeCertificateContext(pCertContext: PCertContext): BOOL; stdcall;
  external 'crypt32.dll';

function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall;
  external 'crypt32.dll';

function CryptMsgClose(hCryptMsg: HCRYPTMSG): BOOL; stdcall;
  external 'crypt32.dll';

function Swap32(Value: UINT32): DWORD; inline;
begin
  Result := ((Value and $FF) shl 24) or
            ((Value and $FF00) shl 8) or
            ((Value and $FF0000) shr 8) or
            ((Value and $FF000000) shr 24);
end;

{ TFirewallInstalledRule }

constructor TFirewallInstalledRule.Create(const ARuleInfo: TFirewallRuleInfo);
begin
  inherited Create;
  Info := ARuleInfo;
  FilterIds := TList<UINT64>.Create;
end;

destructor TFirewallInstalledRule.Destroy;
begin
  FilterIds.Free;
  inherited Destroy;
end;

{ TFirewallMonitorThread }

constructor TFirewallMonitorThread.Create(AOwner: TFirewall);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FOwner := AOwner;
end;

procedure TFirewallMonitorThread.Execute;
var
  Remaining: Cardinal;
  SleepChunk: Cardinal;
begin
  while not Terminated do
  begin
    if Assigned(FOwner) then
      FOwner.MonitorTick;

    if Assigned(FOwner) and (FOwner.FMonitorIntervalMs > 0) then
      Remaining := FOwner.FMonitorIntervalMs
    else
      Remaining := 500;

    while (Remaining > 0) and not Terminated do
    begin
      if Remaining > 100 then
        SleepChunk := 100
      else
        SleepChunk := Remaining;
      Sleep(SleepChunk);
      Dec(Remaining, SleepChunk);
    end;
  end;
end;

{ TFirewall }
constructor TFirewall.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FEngineHandle := 0;
  FEventHandle := 0;
  FActive := False;
  FDynamicSession := False;

  FProviderName := 'DelphiFirewall';
  FSublayerName := 'DelphiFirewall Sublayer';
  FProviderGUID := '{B0D553E2-C6A0-4A9A-AEB8-C7524838D62F}';
  FSublayerGUID := '{9FEE6F59-B951-4F9A-B52F-133DCF7A4279}';

  FProviderKey := TGUID.Empty;
  FSublayerKey := TGUID.Empty;

  FRules := TObjectList<TFirewallInstalledRule>.Create(True);
  FDefaultBlockFilterIds := TList<UINT64>.Create;
  FKnownApps := TDictionary<string, Boolean>.Create;
  FConnectionKeys := TDictionary<string, Boolean>.Create;
  FLock := TCriticalSection.Create;

  FMonitor := TNetworkMonitor.Create;
  FMonitorThread := nil;
  FMonitorIntervalMs := 200;
end;

destructor TFirewall.Destroy;
begin
  try
    if FActive then
      SetActive(False);
  except
    // Never raise from component destruction.
  end;

  StopMonitor;
  FMonitor.Free;

  FLock.Free;
  FConnectionKeys.Free;
  FKnownApps.Free;
  FDefaultBlockFilterIds.Free;
  FRules.Free;
  inherited Destroy;
end;

procedure TFirewall.Loaded;
begin
  inherited Loaded;
  if not (csDesigning in ComponentState) and FActive then
  begin
    FActive := False;
    SetActive(True);
  end;
end;

procedure TFirewall.RaiseError(ACode: DWORD; const AMsg: string);
begin
  if Assigned(FOnError) then
    TThread.Queue(nil,
      procedure
      begin
        if Assigned(FOnError) then
          FOnError(Self, ACode, AMsg);
      end);
end;

procedure TFirewall.CheckResult(AStatus: DWORD; const AContext: string);
begin
  if AStatus <> ERROR_SUCCESS then
    raise EFirewallWFPError.Create(AStatus, AContext);
end;

procedure TFirewall.CheckElevation;
var
  Token: THandle;
  Elevation: TOKEN_ELEVATION;
  ReturnLength: DWORD;
begin
  if not OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, Token) then
    raise EFirewallError.Create('Failed to open process token');
  try
    if not GetTokenInformation(Token, TokenElevation, @Elevation,
      SizeOf(Elevation), ReturnLength) then
      raise EFirewallError.Create('Failed to query token elevation');

    if Elevation.TokenIsElevated = 0 then
      raise EFirewallElevationRequired.Create;
  finally
    CloseHandle(Token);
  end;
end;

function TFirewall.ParseGuidOrDefault(const AValue, ADefault: string): TGUID;
begin
  try
    if Trim(AValue) <> '' then
      Result := StringToGUID(AValue)
    else
      Result := StringToGUID(ADefault);
  except
    Result := StringToGUID(ADefault);
  end;
end;

function TFirewall.NormalizeManagedAppPath(const APath: string): string;
var
  WinDir: string;
  SysNativePath: string;
begin
  Result := Trim(APath);
  if Result = '' then
    Exit;

  if SameText(Result, 'System') or SameText(Result, 'System Idle Process') then
  begin
    WinDir := GetEnvironmentVariable('SystemRoot');
    if WinDir = '' then
      WinDir := GetEnvironmentVariable('windir');
    if WinDir = '' then
      WinDir := 'C:\Windows';
    Result := TPath.Combine(WinDir, 'System32\ntoskrnl.exe');
  end;

  // Convert NT device/system-root style paths into a normal path.
  if (Pos('\Device\', Result) = 1) or (Pos('\SystemRoot\', Result) = 1) then
    Result := DevicePathToDosPath(Result);

  try
    if (Pos(':\', Result) > 0) or (Pos('\\', Result) = 1) then
      Result := ExpandFileName(Result);
  except
    // Keep original string if expansion fails.
  end;

  if FileExists(Result) then
    Exit;

  // On 32-bit apps running on 64-bit Windows, System32 checks can be
  // redirected to SysWOW64 and fail. Try Sysnative alias.
  if Pos('\SYSTEM32\', UpperCase(Result)) > 0 then
  begin
    SysNativePath := StringReplace(Result, '\System32\', '\Sysnative\',
      [rfIgnoreCase]);
    if FileExists(SysNativePath) then
      Exit(SysNativePath);

    // Keep canonical kernel identity even if current process cannot stat it.
    if SameText(ExtractFileName(Result), 'ntoskrnl.exe') then
      Exit(Result);
  end;

  Result := '';
end;

procedure TFirewall.OpenEngine;
var
  Session: FWPM_SESSION0_REC;
  NameW: array[0..255] of WideChar;
  Status: DWORD;
begin
  if FEngineHandle <> 0 then
    Exit;

  CheckElevation;

  FillChar(Session, SizeOf(Session), 0);
  StringToWideChar(FProviderName, NameW, Length(NameW));
  Session.displayData.name := @NameW[0];
  Session.displayData.description := @NameW[0];
  Session.txnWaitTimeoutInMSec := WFP_TRANSACTION_TIMEOUT;

  if FDynamicSession then
    Session.flags := FWPM_SESSION_FLAG_DYNAMIC
  else
    Session.flags := 0;

  Status := FwpmEngineOpen0(nil, RPC_C_AUTHN_WINNT, nil, @Session, @FEngineHandle);
  CheckResult(Status, 'FwpmEngineOpen0');
end;

procedure TFirewall.CloseEngine;
begin
  if FEngineHandle <> 0 then
  begin
    FwpmEngineClose0(FEngineHandle);
    FEngineHandle := 0;
  end;
end;

procedure TFirewall.InstallProviderAndSublayer;
var
  Provider: FWPM_PROVIDER0_REC;
  Sublayer: FWPM_SUBLAYER0_REC;
  NameW, DescW: array[0..255] of WideChar;
  Status: DWORD;
begin
  if FEngineHandle = 0 then
    Exit;

  FProviderKey := ParseGuidOrDefault(FProviderGUID,
    '{B0D553E2-C6A0-4A9A-AEB8-C7524838D62F}');
  FSublayerKey := ParseGuidOrDefault(FSublayerGUID,
    '{9FEE6F59-B951-4F9A-B52F-133DCF7A4279}');

  FillChar(Provider, SizeOf(Provider), 0);
  Provider.providerKey := FProviderKey;
  StringToWideChar(FProviderName, NameW, Length(NameW));
  StringToWideChar(FProviderName + ' Provider', DescW, Length(DescW));
  Provider.displayData.name := @NameW[0];
  Provider.displayData.description := @DescW[0];
  if not FDynamicSession then
    Provider.flags := FWPM_PROVIDER_FLAG_PERSISTENT;

  Status := FwpmProviderAdd0(FEngineHandle, @Provider, nil);
  if (Status <> ERROR_SUCCESS) and (Status <> $80320009) then
    CheckResult(Status, 'FwpmProviderAdd0');

  FillChar(Sublayer, SizeOf(Sublayer), 0);
  Sublayer.subLayerKey := FSublayerKey;
  Sublayer.providerKey := @FProviderKey;
  Sublayer.weight := $FFFF;

  StringToWideChar(FSublayerName, NameW, Length(NameW));
  StringToWideChar(FSublayerName + ' Sublayer', DescW, Length(DescW));
  Sublayer.displayData.name := @NameW[0];
  Sublayer.displayData.description := @DescW[0];
  if not FDynamicSession then
    Sublayer.flags := FWPM_SUBLAYER_FLAG_PERSISTENT;

  Status := FwpmSubLayerAdd0(FEngineHandle, @Sublayer, nil);
  if (Status <> ERROR_SUCCESS) and (Status <> $80320009) then
    CheckResult(Status, 'FwpmSubLayerAdd0');
end;

procedure TFirewall.RemoveProviderAndSublayer;
begin
  if FEngineHandle = 0 then
    Exit;

  if FSublayerKey <> TGUID.Empty then
    FwpmSubLayerDeleteByKey0(FEngineHandle, FSublayerKey);

  if FProviderKey <> TGUID.Empty then
    FwpmProviderDeleteByKey0(FEngineHandle, FProviderKey);
end;

procedure TFirewall.PurgeManagedFilters;
const
  // Returned by filter enum handle creation when the template can never match.
  // In that case there is nothing to purge, so treat it as a no-op.
  FWP_E_ENUM_TEMPLATE_NO_MATCH = DWORD($80320033);
var
  EnumTemplate: FWPM_FILTER_ENUM_TEMPLATE0_REC;
  EnumHandle: THandle;
  Entries: Pointer;
  EntryArray: PFWPMFilterPtrArray;
  Returned: UINT32;
  Status: DWORD;
  I: Integer;
  FilterObj: PFWPM_FILTER0;
  FilterIds: TList<UINT64>;
begin
  if (FEngineHandle = 0) or
     (FProviderKey = TGUID.Empty) or
     (FSublayerKey = TGUID.Empty) then
    Exit;

  FillChar(EnumTemplate, SizeOf(EnumTemplate), 0);
  EnumTemplate.providerKey := @FProviderKey;

  EnumHandle := 0;
  Status := FwpmFilterCreateEnumHandle0(FEngineHandle, @EnumTemplate, @EnumHandle);
  if Status = FWP_E_ENUM_TEMPLATE_NO_MATCH then
    Exit;
  CheckResult(Status, 'FwpmFilterCreateEnumHandle0');

  FilterIds := TList<UINT64>.Create;
  try
    try
      repeat
        Entries := nil;
        Returned := 0;
        Status := FwpmFilterEnum0(FEngineHandle, EnumHandle, 256, @Entries, @Returned);
        CheckResult(Status, 'FwpmFilterEnum0');

        try
          if (Returned > 0) and (Entries <> nil) then
          begin
            EntryArray := PFWPMFilterPtrArray(Entries);
            for I := 0 to Integer(Returned) - 1 do
            begin
              FilterObj := EntryArray^[I];
              if Assigned(FilterObj) and
                 IsEqualGUID(FilterObj^.subLayerKey, FSublayerKey) then
                FilterIds.Add(FilterObj^.filterId);
            end;
          end;
        finally
          if Entries <> nil then
            FwpmFreeMemory0(@Entries);
        end;
      until Returned = 0;
    finally
      if EnumHandle <> 0 then
        FwpmFilterDestroyEnumHandle0(FEngineHandle, EnumHandle);
    end;

    for I := 0 to FilterIds.Count - 1 do
      FwpmFilterDeleteById0(FEngineHandle, FilterIds[I]);
  finally
    FilterIds.Free;
  end;
end;

procedure TFirewall.ClearTrackedFilterIds;
var
  I: Integer;
begin
  FLock.Enter;
  try
    FDefaultBlockFilterIds.Clear;
    for I := 0 to FRules.Count - 1 do
      FRules[I].FilterIds.Clear;
  finally
    FLock.Leave;
  end;
end;

procedure TFirewall.EnableNetEventCollection;
const
  FWP_E_DYNAMIC_SESSION_IN_PROGRESS = DWORD($8032000B);
  FWP_E_INVALID_FLAGS = DWORD($8032001E);
var
  Value: FWP_VALUE0_REC;
  Status: DWORD;
begin
  if FEngineHandle = 0 then
    Exit;

  // WFP engine options cannot be set from dynamic sessions.
  if FDynamicSession then
    Exit;

  FillChar(Value, SizeOf(Value), 0);
  Value._type := FW.WFP.API.FWP_UINT32;

  Value.uint32 := 1;
  Status := FwpmEngineSetOption0(FEngineHandle,
    FWPM_ENGINE_COLLECT_NET_EVENTS, @Value);
  if (Status <> ERROR_SUCCESS) and
     (Status <> FWP_E_DYNAMIC_SESSION_IN_PROGRESS) then
  begin
    RaiseError(Status,
      'FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS) failed');
    Exit;
  end;

  // Use a valid keyword mask (not $FFFFFFFF).
  Value.uint32 := FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW or
                  FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST or
                  FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST or
                  FWPM_NET_EVENT_KEYWORD_PORT_SCANNING_DROP;
  Status := FwpmEngineSetOption0(FEngineHandle,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, @Value);
  if (Status <> ERROR_SUCCESS) and
     (Status <> FWP_E_DYNAMIC_SESSION_IN_PROGRESS) and
     (Status <> FWP_E_INVALID_FLAGS) then
    RaiseError(Status,
      'FwpmEngineSetOption0(FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS) failed');
end;

procedure TFirewall.SubscribeEvents;
var
  Subscription: FWPM_NET_EVENT_SUBSCRIPTION0_REC;
  EnumTemplate: FWPM_NET_EVENT_ENUM_TEMPLATE0_REC;
  Status: DWORD;
begin
  if (FEngineHandle = 0) or (FEventHandle <> 0) then
    Exit;

  FillChar(EnumTemplate, SizeOf(EnumTemplate), 0);
  FillChar(Subscription, SizeOf(Subscription), 0);
  Subscription.enumTemplate := @EnumTemplate;

  Status := FwpmNetEventSubscribe0(FEngineHandle, @Subscription,
    @WFPNetEventCallback, Self, @FEventHandle);
  CheckResult(Status, 'FwpmNetEventSubscribe0');
end;

procedure TFirewall.UnsubscribeEvents;
begin
  if (FEngineHandle <> 0) and (FEventHandle <> 0) then
  begin
    FwpmNetEventUnsubscribe0(FEngineHandle, FEventHandle);
    FEventHandle := 0;
  end;
end;

procedure TFirewall.SetActive(const Value: Boolean);
var
  I: Integer;
begin
  if FActive = Value then
    Exit;

  if csDesigning in ComponentState then
  begin
    FActive := Value;
    Exit;
  end;

  if csLoading in ComponentState then
  begin
    FActive := Value;
    Exit;
  end;

  if Value then
  begin
    try
      OpenEngine;
      InstallProviderAndSublayer;
      PurgeManagedFilters;
      ClearTrackedFilterIds;

      FLock.Enter;
      try
        for I := 0 to FRules.Count - 1 do
          InstallRuleFilters(FRules[I]);
      finally
        FLock.Leave;
      end;

      // Apply explicit app rules first so there is no block-all window
      // before allow rules are in place.
      InstallDefaultBlockFilters;
      EnableNetEventCollection;
      SubscribeEvents;

      StartMonitor;
      FActive := True;
    except
      on E: Exception do
      begin
        RaiseError(ERROR_GEN_FAILURE, E.Message);
        try
          StopMonitor;
          UnsubscribeEvents;

          FLock.Enter;
          try
            for I := 0 to FRules.Count - 1 do
              RemoveRuleFilters(FRules[I]);
          finally
            FLock.Leave;
          end;

          RemoveDefaultBlockFilters;
          PurgeManagedFilters;
          ClearTrackedFilterIds;
          RemoveProviderAndSublayer;
          CloseEngine;
        except
          // Best effort cleanup
        end;
        FActive := False;
        raise;
      end;
    end;
  end
  else
  begin
    try
      StopMonitor;

      FLock.Enter;
      try
        for I := 0 to FRules.Count - 1 do
          RemoveRuleFilters(FRules[I]);
      finally
        FLock.Leave;
      end;

      RemoveDefaultBlockFilters;
      PurgeManagedFilters;
      ClearTrackedFilterIds;
      UnsubscribeEvents;
      RemoveProviderAndSublayer;
      CloseEngine;
    finally
      FConnectionKeys.Clear;
      FKnownApps.Clear;
      FActive := False;
    end;
  end;
end;

procedure TFirewall.StartMonitor;
begin
  if Assigned(FMonitorThread) then
    Exit;

  FMonitorThread := TFirewallMonitorThread.Create(Self);
end;

procedure TFirewall.StopMonitor;
begin
  if not Assigned(FMonitorThread) then
    Exit;

  FMonitorThread.Terminate;
  FMonitorThread.WaitFor;
  FreeAndNil(FMonitorThread);
end;

procedure TFirewall.MonitorTick;
var
  Snapshot: TNetworkConnectionArray;
  CurrentMap: TDictionary<string, TFirewallEvent>;
  NewEvents: TList<TFirewallEvent>;
  Key: string;
  I: Integer;
  EventCopy: TFirewallEvent;
  NewAppCopy: Boolean;
begin
  if not FActive then
    Exit;

  if not Assigned(FMonitor) then
    Exit;

  try
    FMonitor.Refresh;
    Snapshot := FMonitor.GetSnapshot;
  except
    on E: Exception do
    begin
      RaiseError(ERROR_GEN_FAILURE, 'Connection monitor failed: ' + E.Message);
      Exit;
    end;
  end;

  CurrentMap := TDictionary<string, TFirewallEvent>.Create;
  NewEvents := TList<TFirewallEvent>.Create;
  try
    for I := 0 to Length(Snapshot) - 1 do
    begin
      Key := ConnectionKey(Snapshot[I]);
      if Key = '' then
        Continue;

      if not CurrentMap.ContainsKey(Key) then
        CurrentMap.Add(Key, ConnectionToEvent(Snapshot[I]));
    end;

    FLock.Enter;
    try
      for Key in CurrentMap.Keys do
      begin
        if not FConnectionKeys.ContainsKey(Key) then
          NewEvents.Add(CurrentMap[Key]);
      end;

      FConnectionKeys.Clear;
      for Key in CurrentMap.Keys do
        FConnectionKeys.Add(Key, True);
    finally
      FLock.Leave;
    end;

    for I := 0 to NewEvents.Count - 1 do
    begin
      EventCopy := NewEvents[I];
      NewAppCopy := IsNewApp(EventCopy.ApplicationPath);

      TThread.Queue(nil,
        procedure
        begin
          DispatchNetEvent(EventCopy, NewAppCopy);
        end);
    end;
  finally
    NewEvents.Free;
    CurrentMap.Free;
  end;
end;

function TFirewall.ConnectionKey(const Conn: TNetworkConnection): string;
var
  AppKey: string;
begin
  AppKey := Conn.ProcessPath;
  if AppKey = '' then
    AppKey := Conn.ProcessName;

  Result := UpperCase(AppKey) + '|' +
    IntToStr(Ord(Conn.Protocol)) + '|' +
    IntToStr(Ord(Conn.IPVersion)) + '|' +
    Conn.LocalAddress + ':' + IntToStr(Conn.LocalPort) + '|' +
    Conn.RemoteAddress + ':' + IntToStr(Conn.RemotePort) + '|' +
    Conn.State;
end;

function TFirewall.InferDirection(const Conn: TNetworkConnection): TFirewallDirection;
begin
  if Conn.Protocol = fpTCP then
  begin
    if SameText(Conn.State, 'LISTEN') or SameText(Conn.State, 'LISTENING') then
      Exit(fdInbound);

    if (Conn.RemotePort = 0) or (Conn.RemoteAddress = '*') then
      Exit(fdBoth);

    Exit(fdOutbound);
  end;

  if (Conn.RemotePort = 0) or (Conn.RemoteAddress = '*') then
    Exit(fdBoth);

  Result := fdOutbound;
end;

function TFirewall.ConnectionToEvent(const Conn: TNetworkConnection): TFirewallEvent;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.TimeStamp := Now;
  Result.Direction := InferDirection(Conn);
  Result.Action := faAllow;
  Result.Protocol := Conn.Protocol;
  Result.IPVersion := Conn.IPVersion;
  Result.LocalAddress := Conn.LocalAddress;
  Result.LocalPort := Conn.LocalPort;
  Result.RemoteAddress := Conn.RemoteAddress;
  Result.RemotePort := Conn.RemotePort;
  Result.ApplicationPath := NormalizeManagedAppPath(Conn.ProcessPath);
  if Result.ApplicationPath = '' then
    Result.ApplicationPath := NormalizeManagedAppPath(Conn.ProcessName);
  Result.FilterId := 0;
  Result.LayerId := 0;

  Result.IsLoopback :=
    SameText(Result.LocalAddress, '127.0.0.1') or
    SameText(Result.LocalAddress, '::1') or
    SameText(Result.RemoteAddress, '127.0.0.1') or
    SameText(Result.RemoteAddress, '::1');
end;

function TFirewall.FindRuleIndex(const ARuleID: TGUID): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to FRules.Count - 1 do
    if IsEqualGUID(FRules[I].Info.RuleID, ARuleID) then
      Exit(I);
end;

function TFirewall.AddRuleInternal(const AFilePath: string;
  AAction: TFirewallAction): TGUID;
var
  RuleInfo: TFirewallRuleInfo;
  RuleObj: TFirewallInstalledRule;
  RulePath: string;
begin
  RulePath := NormalizeManagedAppPath(AFilePath);
  if RulePath = '' then
    raise EFirewallError.CreateFmt('File not found: %s', [AFilePath]);

  RuleInfo.RuleID := TGUID.NewGuid;
  RuleInfo.ApplicationPath := RulePath;
  RuleInfo.Action := AAction;
  RuleInfo.Enabled := True;

  RuleObj := TFirewallInstalledRule.Create(RuleInfo);

  FLock.Enter;
  try
    FRules.Add(RuleObj);
    if FActive then
      InstallRuleFilters(RuleObj);
  finally
    FLock.Leave;
  end;

  Result := RuleInfo.RuleID;

  if Assigned(FOnNewRule) then
    FOnNewRule(Self, RuleInfo);
end;

function TFirewall.AllowApplication(const AFilePath: string): TGUID;
begin
  Result := AddRuleInternal(AFilePath, faAllow);
end;

function TFirewall.BlockApplication(const AFilePath: string): TGUID;
begin
  Result := AddRuleInternal(AFilePath, faBlock);
end;

function TFirewall.DeleteRule(const ARuleID: TGUID): Boolean;
var
  Index: Integer;
  RuleCopy: TFirewallRuleInfo;
begin
  Result := False;

  FLock.Enter;
  try
    Index := FindRuleIndex(ARuleID);
    if Index < 0 then
      Exit;

    if FActive then
      RemoveRuleFilters(FRules[Index]);

    RuleCopy := FRules[Index].Info;
    FRules.Delete(Index);
    Result := True;
  finally
    FLock.Leave;
  end;

  if Result and Assigned(FOnDeleteRule) then
    FOnDeleteRule(Self, RuleCopy);
end;

procedure TFirewall.ClearRules;
var
  I: Integer;
begin
  FLock.Enter;
  try
    if FActive then
      for I := 0 to FRules.Count - 1 do
        RemoveRuleFilters(FRules[I]);
    FRules.Clear;
  finally
    FLock.Leave;
  end;
end;

function TFirewall.GetRuleCount: Integer;
begin
  FLock.Enter;
  try
    Result := FRules.Count;
  finally
    FLock.Leave;
  end;
end;

procedure TFirewall.InstallRuleFilters(ARule: TFirewallInstalledRule);
var
  AppBlob: PFWP_BYTE_BLOB;
  Layers: array[0..3] of TGUID;
  I: Integer;
  Condition: FWPM_FILTER_CONDITION0_REC;
  Filter: FWPM_FILTER0_REC;
  FilterId: UINT64;
  FilterName: string;
  NameW: array[0..255] of WideChar;
  Status: DWORD;

  function AddFilter(const ALayer: TGUID): UINT64;
  begin
    FillChar(Condition, SizeOf(Condition), 0);
    Condition.fieldKey := FWPM_CONDITION_ALE_APP_ID;
    Condition.matchType := FWP_MATCH_EQUAL;
    Condition.conditionValue._type := FW.WFP.API.FWP_BYTE_BLOB_TYPE;
    Condition.conditionValue.byteBlob := AppBlob;

    FillChar(Filter, SizeOf(Filter), 0);
    CreateGUID(Filter.filterKey);

    if ARule.Info.Action = faAllow then
      FilterName := 'Allow ' + ExtractFileName(ARule.Info.ApplicationPath)
    else
      FilterName := 'Block ' + ExtractFileName(ARule.Info.ApplicationPath);

    StringToWideChar(FilterName, NameW, Length(NameW));
    Filter.displayData.name := @NameW[0];
    Filter.displayData.description := @NameW[0];

    Filter.providerKey := @FProviderKey;
    Filter.layerKey := ALayer;
    Filter.subLayerKey := FSublayerKey;

    Filter.weight._type := FW.WFP.API.FWP_UINT8;
    if ARule.Info.Action = faAllow then
      Filter.weight.uint8 := FW_WEIGHT_HIGHEST_IMPORTANT
    else
      Filter.weight.uint8 := FW_WEIGHT_RULE_USER_BLOCK;

    if ARule.Info.Action = faAllow then
      Filter.action._type := FWP_ACTION_PERMIT
    else
      Filter.action._type := FWP_ACTION_BLOCK;

    Filter.numFilterConditions := 1;
    Filter.filterCondition := @Condition;

    FilterId := 0;
    Status := FwpmFilterAdd0(FEngineHandle, @Filter, nil, @FilterId);
    CheckResult(Status, 'FwpmFilterAdd0');
    Result := FilterId;
  end;

begin
  if (FEngineHandle = 0) or not ARule.Info.Enabled then
    Exit;

  if ARule.FilterIds.Count > 0 then
    RemoveRuleFilters(ARule);

  Status := FwpmGetAppIdFromFileName0(PWideChar(ARule.Info.ApplicationPath), AppBlob);
  CheckResult(Status, 'FwpmGetAppIdFromFileName0');

  try
    Layers[0] := FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    Layers[1] := FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    Layers[2] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    Layers[3] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

    CheckResult(FwpmTransactionBegin0(FEngineHandle, 0), 'FwpmTransactionBegin0');
    try
      for I := 0 to 3 do
        ARule.FilterIds.Add(AddFilter(Layers[I]));
      CheckResult(FwpmTransactionCommit0(FEngineHandle), 'FwpmTransactionCommit0');
    except
      FwpmTransactionAbort0(FEngineHandle);
      ARule.FilterIds.Clear;
      raise;
    end;
  finally
    FwpmFreeMemory0(PPointer(@AppBlob));
  end;
end;

procedure TFirewall.InstallDefaultBlockFilters;
var
  Layers: array[0..3] of TGUID;
  I: Integer;
  Filter: FWPM_FILTER0_REC;
  FilterId: UINT64;
  NameW: array[0..255] of WideChar;
  Status: DWORD;

  function AddDefaultBlock(const ALayer: TGUID): UINT64;
  begin
    FillChar(Filter, SizeOf(Filter), 0);
    CreateGUID(Filter.filterKey);

    StringToWideChar('Default Block All', NameW, Length(NameW));
    Filter.displayData.name := @NameW[0];
    Filter.displayData.description := @NameW[0];

    Filter.providerKey := @FProviderKey;
    Filter.layerKey := ALayer;
    Filter.subLayerKey := FSublayerKey;

    // Keep default-block low enough so explicit allow rules can override.
    Filter.weight._type := FW.WFP.API.FWP_UINT8;
    Filter.weight.uint8 := FW_WEIGHT_LOWEST;

    Filter.action._type := FWP_ACTION_BLOCK;
    Filter.numFilterConditions := 0;
    Filter.filterCondition := nil;

    FilterId := 0;
    Status := FwpmFilterAdd0(FEngineHandle, @Filter, nil, @FilterId);
    CheckResult(Status, 'FwpmFilterAdd0(DefaultBlock)');
    Result := FilterId;
  end;

begin
  if FEngineHandle = 0 then
    Exit;

  if FDefaultBlockFilterIds.Count > 0 then
    Exit;

  Layers[0] := FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  Layers[1] := FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  Layers[2] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  Layers[3] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

  CheckResult(FwpmTransactionBegin0(FEngineHandle, 0),
    'FwpmTransactionBegin0(DefaultBlock)');
  try
    for I := 0 to 3 do
      FDefaultBlockFilterIds.Add(AddDefaultBlock(Layers[I]));

    CheckResult(FwpmTransactionCommit0(FEngineHandle),
      'FwpmTransactionCommit0(DefaultBlock)');
  except
    FwpmTransactionAbort0(FEngineHandle);
    FDefaultBlockFilterIds.Clear;
    raise;
  end;
end;

procedure TFirewall.RemoveDefaultBlockFilters;
var
  I: Integer;
begin
  if FDefaultBlockFilterIds.Count = 0 then
    Exit;

  if FEngineHandle = 0 then
  begin
    FDefaultBlockFilterIds.Clear;
    Exit;
  end;

  for I := FDefaultBlockFilterIds.Count - 1 downto 0 do
    FwpmFilterDeleteById0(FEngineHandle, FDefaultBlockFilterIds[I]);

  FDefaultBlockFilterIds.Clear;
end;
procedure TFirewall.RemoveRuleFilters(ARule: TFirewallInstalledRule);
var
  I: Integer;
begin
  if FEngineHandle = 0 then
  begin
    ARule.FilterIds.Clear;
    Exit;
  end;

  for I := ARule.FilterIds.Count - 1 downto 0 do
    FwpmFilterDeleteById0(FEngineHandle, ARule.FilterIds[I]);

  ARule.FilterIds.Clear;
end;

class procedure TFirewall.WFPNetEventCallback(context: Pointer;
  const event: PFWPM_NET_EVENT1);
var
  SelfObj: TFirewall;
begin
  SelfObj := TFirewall(context);
  if Assigned(SelfObj) and Assigned(event) then
    SelfObj.HandleNetEvent(event);
end;

procedure TFirewall.HandleNetEvent(const event: PFWPM_NET_EVENT1);
var
  LEvent: TFirewallEvent;
  LNewApp: Boolean;
begin
  try
    LEvent := ParseNetEvent(event);
    LNewApp := IsNewApp(LEvent.ApplicationPath);

    TThread.Queue(nil,
      procedure
      begin
        DispatchNetEvent(LEvent, LNewApp);
      end);
  except
    on E: Exception do
      RaiseError(ERROR_GEN_FAILURE, 'WFP event parse failed: ' + E.Message);
  end;
end;

function TFirewall.ParseNetEvent(const event: PFWPM_NET_EVENT1): TFirewallEvent;
var
  Header: FWPM_NET_EVENT_HEADER1_REC;
  SysTime: TSystemTime;

  procedure ApplyFallbackDirection;
  begin
    if Result.Direction <> fdBoth then
      Exit;

    if (Result.RemotePort <> 0) or (Result.RemoteAddress <> '') then
      Result.Direction := fdOutbound
    else
      Result.Direction := fdInbound;
  end;

begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Action := faAllow;
  Result.Direction := fdBoth;
  Result.Protocol := fpAny;
  Result.IPVersion := fipBoth;

  Header := event^.header;

  if (Header.timeStamp.dwLowDateTime <> 0) or
     (Header.timeStamp.dwHighDateTime <> 0) then
  begin
    FileTimeToSystemTime(Header.timeStamp, SysTime);
    Result.TimeStamp := SystemTimeToDateTime(SysTime);
  end
  else
    Result.TimeStamp := Now;

  if (Header.flags and FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) <> 0 then
  begin
    case Header.ipProtocol of
      IPPROTO_TCP:  Result.Protocol := fpTCP;
      IPPROTO_UDP:  Result.Protocol := fpUDP;
      IPPROTO_ICMP,
      IPPROTO_ICMPV6: Result.Protocol := fpICMP;
    else
      Result.Protocol := fpAny;
    end;
  end;

  if (Header.flags and FWPM_NET_EVENT_FLAG_IP_VERSION_SET) <> 0 then
  begin
    case Header.ipVersion of
      FWP_IP_VERSION_V4: Result.IPVersion := fipV4;
      FWP_IP_VERSION_V6: Result.IPVersion := fipV6;
    else
      Result.IPVersion := fipBoth;
    end;
  end;

  if (Header.flags and FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) <> 0 then
  begin
    if Result.IPVersion = fipV6 then
      Result.LocalAddress := FW.IpHelper.API.IPv6ToStr(Header.localAddr.V6)
    else
      Result.LocalAddress := FW.IpHelper.API.IPv4ToStr(Swap32(Header.localAddr.V4));
  end;

  if (Header.flags and FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) <> 0 then
  begin
    if Result.IPVersion = fipV6 then
      Result.RemoteAddress := FW.IpHelper.API.IPv6ToStr(Header.remoteAddr.V6)
    else
      Result.RemoteAddress := FW.IpHelper.API.IPv4ToStr(Swap32(Header.remoteAddr.V4));
  end;

  if (Header.flags and FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) <> 0 then
    Result.LocalPort := Header.localPort;

  if (Header.flags and FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) <> 0 then
    Result.RemotePort := Header.remotePort;

  if (Header.flags and FWPM_NET_EVENT_FLAG_APP_ID_SET) <> 0 then
    Result.ApplicationPath := ExtractAppPath(Header.appId);

  case event^._type of
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
    FWPM_NET_EVENT_TYPE_CAPABILITY_DROP,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
      begin
        Result.Action := faBlock;
        if Assigned(event^.classifyDrop) then
        begin
          Result.FilterId := event^.classifyDrop^.filterId;
          Result.LayerId := event^.classifyDrop^.layerId;
          Result.IsLoopback := Boolean(event^.classifyDrop^.isLoopback);
          if event^.classifyDrop^.msFwpDirection = UINT32(FWP_DIRECTION_OUTBOUND) then
            Result.Direction := fdOutbound
          else
            Result.Direction := fdInbound;
        end;
      end;

    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW,
    FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
      begin
        Result.Action := faAllow;
        if Assigned(event^.classifyAllow) then
        begin
          Result.FilterId := event^.classifyAllow^.filterId;
          Result.LayerId := event^.classifyAllow^.layerId;
          Result.IsLoopback := Boolean(event^.classifyAllow^.isLoopback);
          if event^.classifyAllow^.msFwpDirection = UINT32(FWP_DIRECTION_OUTBOUND) then
            Result.Direction := fdOutbound
          else
            Result.Direction := fdInbound;
        end;
      end;
  else
    Result.Action := faAllow;
  end;

  ApplyFallbackDirection;
end;

function TFirewall.ExtractAppPath(const appId: FWP_BYTE_BLOB_REC): string;
var
  DevicePath: string;
begin
  Result := '';
  if (appId.size = 0) or (appId.data = nil) then
    Exit;

  SetString(DevicePath, PWideChar(appId.data),
    (appId.size div SizeOf(WideChar)) - 1);

  Result := DevicePathToDosPath(DevicePath);
end;

function TFirewall.DevicePathToDosPath(const ADevicePath: string): string;
var
  Drive: Char;
  DevName: array[0..MAX_PATH - 1] of WideChar;
  DevStr: string;
  WinDir: string;
  Ret: DWORD;
begin
  Result := ADevicePath;

  if Pos('\SystemRoot\', ADevicePath) = 1 then
  begin
    WinDir := GetEnvironmentVariable('SystemRoot');
    if WinDir = '' then
      WinDir := GetEnvironmentVariable('windir');
    if WinDir = '' then
      WinDir := 'C:\Windows';
    Result := IncludeTrailingPathDelimiter(WinDir) +
      Copy(ADevicePath, Length('\SystemRoot\') + 1, MaxInt);
    Exit;
  end;

  for Drive := 'A' to 'Z' do
  begin
    Ret := QueryDosDeviceW(PWideChar(string(Drive) + ':'),
      @DevName[0], MAX_PATH);
    if Ret > 0 then
    begin
      DevStr := DevName;
      if (DevStr <> '') and
         SameText(Copy(ADevicePath, 1, Length(DevStr)), DevStr) then
      begin
        Result := Drive + ':' + Copy(ADevicePath, Length(DevStr) + 1, MaxInt);
        Exit;
      end;
    end;
  end;
end;

function TFirewall.IsNewApp(const APath: string): Boolean;
var
  Key: string;
begin
  Result := False;
  if APath = '' then
    Exit;

  Key := UpperCase(APath);

  FLock.Enter;
  try
    if not FKnownApps.ContainsKey(Key) then
    begin
      FKnownApps.Add(Key, True);
      Result := True;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TFirewall.DispatchNetEvent(const AEvent: TFirewallEvent;
  ANewApp: Boolean);
var
  Details: TFirewallFileDetails;
begin
  if ANewApp and Assigned(FOnNewAppDetected) then
  begin
    Details := GetFileDetails(AEvent.ApplicationPath);
    FOnNewAppDetected(Self, AEvent, Details);
  end;

  case AEvent.Action of
    faBlock:
      if Assigned(FOnBlock) then
        FOnBlock(Self, AEvent);

    faAllow:
      if Assigned(FOnAllow) then
        FOnAllow(Self, AEvent);
  end;
end;

function TFirewall.GetFileDetails(const AFilePath: string): TFirewallFileDetails;
var
  Attr: WIN32_FILE_ATTRIBUTE_DATA;

  function FileTimeToDateTimeSafe(const FT: TFileTime): TDateTime;
  var
    LFT: TFileTime;
    LST: TSystemTime;
  begin
    Result := 0;
    if (FT.dwLowDateTime = 0) and (FT.dwHighDateTime = 0) then
      Exit;

    if not FileTimeToLocalFileTime(FT, LFT) then
      Exit;
    if not FileTimeToSystemTime(LFT, LST) then
      Exit;

    Result := SystemTimeToDateTime(LST);
  end;

  procedure LoadVersionInfo;
  var
    InfoSize, Handle: DWORD;
    InfoBuf: TBytes;
    LangPtr: Pointer;
    LangLen: UINT;
    LangCode: string;
    ValuePtr: Pointer;
    ValueLen: UINT;

    function QueryStr(const AKey: string): string;
    var
      SubBlock: string;
    begin
      Result := '';
      SubBlock := Format('\\StringFileInfo\\%s\\%s', [LangCode, AKey]);
      if VerQueryValueW(Pointer(InfoBuf), PWideChar(SubBlock), ValuePtr, ValueLen) and
         (ValueLen > 0) then
        Result := Trim(PWideChar(ValuePtr));
    end;

  begin
    InfoSize := Winapi.Windows.GetFileVersionInfoSizeW(PWideChar(Result.FilePath), Handle);
    if InfoSize = 0 then
      Exit;

    SetLength(InfoBuf, InfoSize);
    if not Winapi.Windows.GetFileVersionInfoW(PWideChar(Result.FilePath),
      Handle, InfoSize, Pointer(InfoBuf)) then
      Exit;

    if not VerQueryValueW(Pointer(InfoBuf), '\\VarFileInfo\\Translation',
      LangPtr, LangLen) or (LangLen < 4) then
      Exit;

    LangCode := Format('%.4x%.4x', [
      PWord(LangPtr)^,
      PWord(PByte(LangPtr) + 2)^
    ]);

    Result.Publisher := QueryStr('CompanyName');
    Result.FileDescription := QueryStr('FileDescription');
    Result.FileVersion := QueryStr('FileVersion');
    Result.ProductName := QueryStr('ProductName');
  end;

  procedure LoadSignatureInfo;
  var
    FileInfo: TWinTrustFileInfo;
    TrustData: TWinTrustData;
    PolicyGUID: TGUID;
    Encoding, ContentType, FormatType: DWORD;
    CertStore: HCERTSTORE;
    CryptMsg: HCRYPTMSG;
    CertContext: PCertContext;
    NameBuf: array[0..511] of WideChar;
    I: Integer;
  begin
    Result.IsSigned := False;
    Result.CertificateSubject := '';
    Result.CertificateIssuer := '';
    Result.CertificateSerial := '';

    FillChar(FileInfo, SizeOf(FileInfo), 0);
    FileInfo.cbStruct := SizeOf(FileInfo);
    FileInfo.pcwszFilePath := PWideChar(Result.FilePath);

    FillChar(TrustData, SizeOf(TrustData), 0);
    TrustData.cbStruct := SizeOf(TrustData);
    TrustData.dwUIChoice := WTD_UI_NONE;
    TrustData.fdwRevocationChecks := WTD_REVOKE_NONE;
    TrustData.dwUnionChoice := WTD_CHOICE_FILE;
    TrustData.pFile := @FileInfo;
    TrustData.dwStateAction := WTD_STATEACTION_VERIFY;
    TrustData.dwProvFlags := WTD_CACHE_ONLY_URL_RETRIEVAL;

    PolicyGUID := WINTRUST_ACTION_GENERIC_VERIFY_V2;
    Result.IsSigned := WinVerifyTrust(INVALID_HANDLE_VALUE, PolicyGUID,
      @TrustData) = ERROR_SUCCESS;

    TrustData.dwStateAction := WTD_STATEACTION_CLOSE;
    WinVerifyTrust(INVALID_HANDLE_VALUE, PolicyGUID, @TrustData);

    if not Result.IsSigned then
      Exit;

    CertStore := nil;
    CryptMsg := nil;

    if not CryptQueryObject(CERT_QUERY_OBJECT_FILE, PWideChar(Result.FilePath),
      CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED or
      CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
      CERT_QUERY_FORMAT_FLAG_BINARY, 0,
      @Encoding, @ContentType, @FormatType, @CertStore, @CryptMsg, nil) then
      Exit;

    try
      CertContext := CertEnumCertificatesInStore(CertStore, nil);
      if Assigned(CertContext) then
      begin
        try
          if CertGetNameStringW(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0, nil, @NameBuf[0], Length(NameBuf)) > 0 then
            Result.CertificateSubject := NameBuf;

          if CertGetNameStringW(CertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG, nil, @NameBuf[0], Length(NameBuf)) > 0 then
            Result.CertificateIssuer := NameBuf;

          if Assigned(CertContext.pCertInfo) then
          begin
            Result.CertificateSerial := '';
            for I := Integer(CertContext.pCertInfo.SerialNumber.cbData) - 1
              downto 0 do
              Result.CertificateSerial := Result.CertificateSerial +
                IntToHex(CertContext.pCertInfo.SerialNumber.pbData[I], 2);
          end;
        finally
          CertFreeCertificateContext(CertContext);
        end;
      end;
    finally
      if CryptMsg <> nil then
        CryptMsgClose(CryptMsg);
      if CertStore <> nil then
        CertCloseStore(CertStore, 0);
    end;
  end;

begin
  FillChar(Result, SizeOf(Result), 0);

  if Trim(AFilePath) = '' then
    Exit;

  Result.FilePath := ExpandFileName(AFilePath);
  Result.FileName := ExtractFileName(Result.FilePath);
  Result.Exists := FileExists(Result.FilePath);

  if not Result.Exists then
    Exit;

  if GetFileAttributesExW(PWideChar(Result.FilePath), GetFileExInfoStandard,
    @Attr) then
  begin
    Result.FileSize := (Int64(Attr.nFileSizeHigh) shl 32) or Attr.nFileSizeLow;
    Result.DateCreated := FileTimeToDateTimeSafe(Attr.ftCreationTime);
    Result.DateModified := FileTimeToDateTimeSafe(Attr.ftLastWriteTime);
  end;

  LoadVersionInfo;
  LoadSignatureInfo;
end;

end.
