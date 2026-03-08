unit FW.Engine;

{******************************************************************************
  FW.Engine - WFP Engine Wrapper

  Encapsulates all direct Windows Filtering Platform API interaction including
  engine lifecycle, provider/sublayer management, filter installation/removal,
  transactions, and net event subscription. NOT thread-safe by itself; the
  caller (worker thread) must serialize access.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.Generics.Collections,
  FW.WFP.API, FW.Types, FW.Rules;

type
  TWFPEngine = class
  private
    FEngineHandle: THandle;
    FProviderKey: TGUID;
    FSublayerKey: TGUID;
    FProviderName: string;
    FSublayerName: string;
    FDynamicSession: Boolean;
    FIsOpen: Boolean;
    FProviderInstalled: Boolean;
    FSublayerInstalled: Boolean;

    procedure CheckOpen;
    procedure CheckResult(AResult: DWORD; const AContext: string);
    procedure CheckElevation;

    function GetAppIdBlob(const APath: string): PFWP_BYTE_BLOB;
    procedure FreeAppIdBlob(ABlob: PFWP_BYTE_BLOB);

    function ProtocolToIPPROTO(AProt: TFirewallProtocol): UINT8;
    function GetLayerGUIDs(ADir: TFirewallDirection;
      AIPVer: TFirewallIPVersion): TArray<TGUID>;
    function ActionToWFP(AAction: TFirewallAction): UINT32;
    function WeightToWFP(AWeight: Byte): UINT8;

    function CreateSingleFilter(
      const ALayerKey: TGUID;
      const AName: string;
      AConditions: PFWPM_FILTER_CONDITION0;
      AConditionCount: UINT32;
      AAction: UINT32;
      AWeight: UINT8
    ): UINT64;

    function ParseIPv4(const AAddr: string; out AIP: UINT32;
      out AMask: UINT32): Boolean;
  public
    constructor Create(const AProviderKey, ASublayerKey: TGUID;
      const AProviderName, ASublayerName: string);
    destructor Destroy; override;

    // Engine lifecycle
    procedure Open(ADynamic: Boolean = True);
    procedure Close;

    // Provider and sublayer
    procedure InstallProvider;
    procedure UninstallProvider;
    procedure InstallSublayer(AWeight: UINT16 = $FFFF);
    procedure UninstallSublayer;

    // Transactions
    procedure BeginTransaction;
    procedure CommitTransaction;
    procedure AbortTransaction;

    // Filter management
    function InstallRule(ARule: TFirewallRule): TArray<UINT64>;
    procedure UninstallRule(ARule: TFirewallRule);
    procedure UninstallFilterById(AId: UINT64);

    // Convenience: install default block-all filters (lowest weight)
    function InstallDefaultBlockAll: TArray<UINT64>;

    // Net event subscription
    procedure SubscribeNetEvents(ACallback: FWPM_NET_EVENT_CALLBACK0;
      AContext: Pointer; out AEventsHandle: THandle);
    procedure UnsubscribeNetEvents(var AEventsHandle: THandle);

    // Enable net event collection
    procedure EnableNetEventCollection;

    property EngineHandle: THandle read FEngineHandle;
    property IsOpen: Boolean read FIsOpen;
    property ProviderKey: TGUID read FProviderKey;
    property SublayerKey: TGUID read FSublayerKey;
  end;

implementation

uses
  System.Math;

{ TWFPEngine }

constructor TWFPEngine.Create(const AProviderKey, ASublayerKey: TGUID;
  const AProviderName, ASublayerName: string);
begin
  inherited Create;
  FProviderKey := AProviderKey;
  FSublayerKey := ASublayerKey;
  FProviderName := AProviderName;
  FSublayerName := ASublayerName;
  FEngineHandle := 0;
  FIsOpen := False;
  FDynamicSession := True;
  FProviderInstalled := False;
  FSublayerInstalled := False;
end;

destructor TWFPEngine.Destroy;
begin
  if FIsOpen then
    Close;
  inherited Destroy;
end;

procedure TWFPEngine.CheckOpen;
begin
  if not FIsOpen then
    raise EFirewallError.Create('WFP engine is not open');
end;

procedure TWFPEngine.CheckResult(AResult: DWORD; const AContext: string);
begin
  if AResult <> ERROR_SUCCESS then
    raise EFirewallWFPError.Create(AResult, AContext);
end;

procedure TWFPEngine.CheckElevation;
var
  Token: THandle;
  Elevation: TOKEN_ELEVATION;
  ReturnLength: DWORD;
begin
  if not OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, Token) then
    raise EFirewallError.Create('Failed to open process token for elevation check');
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

procedure TWFPEngine.Open(ADynamic: Boolean);
var
  Session: FWPM_SESSION0_REC;
  Status: DWORD;
  Retries: Integer;
  NameW: array[0..255] of WideChar;
begin
  if FIsOpen then
    Exit;

  CheckElevation;

  FDynamicSession := ADynamic;

  FillChar(Session, SizeOf(Session), 0);
  StringToWideChar(FProviderName, NameW, Length(NameW));
  Session.displayData.name := @NameW[0];
  Session.displayData.description := @NameW[0];
  Session.txnWaitTimeoutInMSec := WFP_TRANSACTION_TIMEOUT;

  if ADynamic then
    Session.flags := FWPM_SESSION_FLAG_DYNAMIC
  else
    Session.flags := 0;

  // Retry in case BFE service is starting up
  for Retries := 0 to 5 do
  begin
    Status := FwpmEngineOpen0(nil, RPC_C_AUTHN_WINNT, nil, @Session,
      @FEngineHandle);
    if Status = ERROR_SUCCESS then
      Break;
    if Retries < 5 then
      Sleep(500);
  end;

  CheckResult(Status, 'FwpmEngineOpen0');
  FIsOpen := True;
end;

procedure TWFPEngine.Close;
begin
  if not FIsOpen then
    Exit;

  // Sublayer and provider are auto-cleaned in dynamic sessions
  if FIsOpen and (FEngineHandle <> 0) then
  begin
    FwpmEngineClose0(FEngineHandle);
    FEngineHandle := 0;
  end;

  FIsOpen := False;
  FProviderInstalled := False;
  FSublayerInstalled := False;
end;

procedure TWFPEngine.InstallProvider;
var
  Provider: FWPM_PROVIDER0_REC;
  NameW, DescW: array[0..255] of WideChar;
  Status: DWORD;
begin
  CheckOpen;

  FillChar(Provider, SizeOf(Provider), 0);
  Provider.providerKey := FProviderKey;
  StringToWideChar(FProviderName, NameW, Length(NameW));
  StringToWideChar(FProviderName + ' Provider', DescW, Length(DescW));
  Provider.displayData.name := @NameW[0];
  Provider.displayData.description := @DescW[0];

  if not FDynamicSession then
    Provider.flags := FWPM_PROVIDER_FLAG_PERSISTENT;

  Status := FwpmProviderAdd0(FEngineHandle, @Provider, nil);

  // FWP_E_ALREADY_EXISTS = 0x80320009
  if (Status <> ERROR_SUCCESS) and (Status <> $80320009) then
    CheckResult(Status, 'FwpmProviderAdd0');

  FProviderInstalled := True;
end;

procedure TWFPEngine.UninstallProvider;
begin
  CheckOpen;
  FwpmProviderDeleteByKey0(FEngineHandle, FProviderKey);
  FProviderInstalled := False;
end;

procedure TWFPEngine.InstallSublayer(AWeight: UINT16);
var
  Sublayer: FWPM_SUBLAYER0_REC;
  NameW, DescW: array[0..255] of WideChar;
  Status: DWORD;
begin
  CheckOpen;

  FillChar(Sublayer, SizeOf(Sublayer), 0);
  Sublayer.subLayerKey := FSublayerKey;
  Sublayer.providerKey := @FProviderKey;
  Sublayer.weight := AWeight;

  StringToWideChar(FSublayerName, NameW, Length(NameW));
  StringToWideChar(FSublayerName + ' Sublayer', DescW, Length(DescW));
  Sublayer.displayData.name := @NameW[0];
  Sublayer.displayData.description := @DescW[0];

  if not FDynamicSession then
    Sublayer.flags := FWPM_SUBLAYER_FLAG_PERSISTENT;

  Status := FwpmSubLayerAdd0(FEngineHandle, @Sublayer, nil);

  // FWP_E_ALREADY_EXISTS
  if (Status <> ERROR_SUCCESS) and (Status <> $80320009) then
    CheckResult(Status, 'FwpmSubLayerAdd0');

  FSublayerInstalled := True;
end;

procedure TWFPEngine.UninstallSublayer;
begin
  CheckOpen;
  FwpmSubLayerDeleteByKey0(FEngineHandle, FSublayerKey);
  FSublayerInstalled := False;
end;

procedure TWFPEngine.BeginTransaction;
begin
  CheckOpen;
  CheckResult(FwpmTransactionBegin0(FEngineHandle, 0), 'FwpmTransactionBegin0');
end;

procedure TWFPEngine.CommitTransaction;
begin
  CheckOpen;
  CheckResult(FwpmTransactionCommit0(FEngineHandle), 'FwpmTransactionCommit0');
end;

procedure TWFPEngine.AbortTransaction;
begin
  CheckOpen;
  FwpmTransactionAbort0(FEngineHandle);
end;

function TWFPEngine.GetAppIdBlob(const APath: string): PFWP_BYTE_BLOB;
var
  Status: DWORD;
begin
  Result := nil;
  Status := FwpmGetAppIdFromFileName0(PWideChar(APath), Result);
  CheckResult(Status, 'FwpmGetAppIdFromFileName0 for "' + APath + '"');
end;

procedure TWFPEngine.FreeAppIdBlob(ABlob: PFWP_BYTE_BLOB);
var
  P: Pointer;
begin
  P := ABlob;
  FwpmFreeMemory0(@P);
end;

function TWFPEngine.ProtocolToIPPROTO(AProt: TFirewallProtocol): UINT8;
begin
  case AProt of
    fpTCP:  Result := IPPROTO_TCP;
    fpUDP:  Result := IPPROTO_UDP;
    fpICMP: Result := IPPROTO_ICMP;
  else
    Result := 0;
  end;
end;

function TWFPEngine.GetLayerGUIDs(ADir: TFirewallDirection;
  AIPVer: TFirewallIPVersion): TArray<TGUID>;
var
  LList: TList<TGUID>;
begin
  LList := TList<TGUID>.Create;
  try
    // Outbound layers
    if ADir in [fdOutbound, fdBoth] then
    begin
      if AIPVer in [fipV4, fipBoth] then
        LList.Add(FWPM_LAYER_ALE_AUTH_CONNECT_V4);
      if AIPVer in [fipV6, fipBoth] then
        LList.Add(FWPM_LAYER_ALE_AUTH_CONNECT_V6);
    end;

    // Inbound layers
    if ADir in [fdInbound, fdBoth] then
    begin
      if AIPVer in [fipV4, fipBoth] then
        LList.Add(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
      if AIPVer in [fipV6, fipBoth] then
        LList.Add(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    end;

    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TWFPEngine.ActionToWFP(AAction: TFirewallAction): UINT32;
begin
  case AAction of
    faBlock: Result := FWP_ACTION_BLOCK;
    faAllow: Result := FWP_ACTION_PERMIT;
  else
    Result := FWP_ACTION_BLOCK;
  end;
end;

function TWFPEngine.WeightToWFP(AWeight: Byte): UINT8;
begin
  // Map user weight 0..7 to WFP weights $08..$0F
  Result := FW_WEIGHT_LOWEST + Min(AWeight, 7);
end;

function TWFPEngine.ParseIPv4(const AAddr: string; out AIP: UINT32;
  out AMask: UINT32): Boolean;
var
  Parts: TArray<string>;
  AddrPart: string;
  PrefixLen: Integer;
  Octets: TArray<string>;
  B: array[0..3] of Byte;
  I: Integer;
begin
  Result := False;
  AIP := 0;
  AMask := $FFFFFFFF;

  if AAddr = '' then
    Exit;

  // Check for CIDR notation (e.g., 192.168.1.0/24)
  Parts := AAddr.Split(['/']);
  AddrPart := Parts[0];
  if Length(Parts) > 1 then
  begin
    PrefixLen := StrToIntDef(Parts[1], 32);
    if PrefixLen < 0 then PrefixLen := 0;
    if PrefixLen > 32 then PrefixLen := 32;
    if PrefixLen = 0 then
      AMask := 0
    else
      AMask := UINT32($FFFFFFFF shl (32 - PrefixLen));
  end;

  Octets := AddrPart.Split(['.']);
  if Length(Octets) <> 4 then
    Exit;

  for I := 0 to 3 do
  begin
    B[I] := Byte(StrToIntDef(Octets[I], 0));
  end;

  // Network byte order (big-endian)
  AIP := UINT32(B[0]) shl 24 or UINT32(B[1]) shl 16 or
         UINT32(B[2]) shl 8 or UINT32(B[3]);

  Result := True;
end;

function TWFPEngine.CreateSingleFilter(
  const ALayerKey: TGUID;
  const AName: string;
  AConditions: PFWPM_FILTER_CONDITION0;
  AConditionCount: UINT32;
  AAction: UINT32;
  AWeight: UINT8
): UINT64;
var
  Filter: FWPM_FILTER0_REC;
  NameW, DescW: array[0..511] of WideChar;
  FilterId: UINT64;
  Status: DWORD;
begin
  FillChar(Filter, SizeOf(Filter), 0);
  CreateGUID(Filter.filterKey);

  StringToWideChar(AName, NameW, Length(NameW));
  StringToWideChar(AName, DescW, Length(DescW));
  Filter.displayData.name := @NameW[0];
  Filter.displayData.description := @DescW[0];

  Filter.providerKey := @FProviderKey;
  Filter.layerKey := ALayerKey;
  Filter.subLayerKey := FSublayerKey;

  Filter.weight._type := FW.WFP.API.FWP_UINT8;
  Filter.weight.uint8 := AWeight;

  Filter.action._type := AAction;

  Filter.numFilterConditions := AConditionCount;
  Filter.filterCondition := AConditions;

  if not FDynamicSession then
    Filter.flags := FWPM_FILTER_FLAG_PERSISTENT;

  FilterId := 0;
  Status := FwpmFilterAdd0(FEngineHandle, @Filter, nil, @FilterId);
  CheckResult(Status, 'FwpmFilterAdd0 for "' + AName + '"');
  Result := FilterId;
end;

function TWFPEngine.InstallRule(ARule: TFirewallRule): TArray<UINT64>;
var
  Conditions: array[0..7] of FWPM_FILTER_CONDITION0_REC;
  CondCount: Integer;
  Layers: TArray<TGUID>;
  AppBlob: PFWP_BYTE_BLOB;
  I: Integer;
  FilterId: UINT64;
  FilterIds: TList<UINT64>;
  V4Addr, V4Mask: UINT32;
  V4AddrMask: FWP_V4_ADDR_AND_MASK_REC;
  WfpAction: UINT32;
  WfpWeight: UINT8;
  RemoteV4AddrMask: FWP_V4_ADDR_AND_MASK_REC;
begin
  CheckOpen;
  Result := nil;

  if not ARule.Data.Enabled then
    Exit;

  // Build filter conditions
  CondCount := 0;
  FillChar(Conditions, SizeOf(Conditions), 0);
  AppBlob := nil;

  try
    // Condition: Application path
    if ARule.Data.ApplicationPath <> '' then
    begin
      AppBlob := GetAppIdBlob(ARule.Data.ApplicationPath);
      Conditions[CondCount].fieldKey := FWPM_CONDITION_ALE_APP_ID;
      Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
      Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_BYTE_BLOB_TYPE;
      Conditions[CondCount].conditionValue.byteBlob := AppBlob;
      Inc(CondCount);
    end;

    // Condition: Protocol
    if ARule.Data.Protocol <> fpAny then
    begin
      Conditions[CondCount].fieldKey := FWPM_CONDITION_IP_PROTOCOL;
      Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
      Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_UINT8;
      Conditions[CondCount].conditionValue.uint8 := ProtocolToIPPROTO(ARule.Data.Protocol);
      Inc(CondCount);
    end;

    // Condition: Remote Address (IPv4 only for now)
    if ARule.Data.RemoteAddress <> '' then
    begin
      if ParseIPv4(ARule.Data.RemoteAddress, V4Addr, V4Mask) then
      begin
        RemoteV4AddrMask.addr := V4Addr;
        RemoteV4AddrMask.mask := V4Mask;
        Conditions[CondCount].fieldKey := FWPM_CONDITION_IP_REMOTE_ADDRESS;
        Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
        Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_V4_ADDR_MASK;
        Conditions[CondCount].conditionValue.v4AddrMask := @RemoteV4AddrMask;
        Inc(CondCount);
      end;
    end;

    // Condition: Local Address (IPv4 only for now)
    if ARule.Data.LocalAddress <> '' then
    begin
      if ParseIPv4(ARule.Data.LocalAddress, V4Addr, V4Mask) then
      begin
        V4AddrMask.addr := V4Addr;
        V4AddrMask.mask := V4Mask;
        Conditions[CondCount].fieldKey := FWPM_CONDITION_IP_LOCAL_ADDRESS;
        Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
        Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_V4_ADDR_MASK;
        Conditions[CondCount].conditionValue.v4AddrMask := @V4AddrMask;
        Inc(CondCount);
      end;
    end;

    // Condition: Remote Port
    if ARule.Data.RemotePort > 0 then
    begin
      Conditions[CondCount].fieldKey := FWPM_CONDITION_IP_REMOTE_PORT;
      Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
      Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_UINT16;
      Conditions[CondCount].conditionValue.uint16 := ARule.Data.RemotePort;
      Inc(CondCount);
    end;

    // Condition: Local Port
    if ARule.Data.LocalPort > 0 then
    begin
      Conditions[CondCount].fieldKey := FWPM_CONDITION_IP_LOCAL_PORT;
      Conditions[CondCount].matchType := FWP_MATCH_EQUAL;
      Conditions[CondCount].conditionValue._type := FW.WFP.API.FWP_UINT16;
      Conditions[CondCount].conditionValue.uint16 := ARule.Data.LocalPort;
      Inc(CondCount);
    end;

    // Determine WFP action and weight
    WfpAction := ActionToWFP(ARule.Data.Action);
    WfpWeight := WeightToWFP(ARule.Data.Weight);

    // Get target layers based on direction and IP version
    Layers := GetLayerGUIDs(ARule.Data.Direction, ARule.Data.IPVersion);

    // Create a filter on each target layer
    FilterIds := TList<UINT64>.Create;
    try
      for I := 0 to Length(Layers) - 1 do
      begin
        FilterId := CreateSingleFilter(
          Layers[I],
          ARule.Data.Name,
          @Conditions[0],
          UINT32(CondCount),
          WfpAction,
          WfpWeight
        );
        FilterIds.Add(FilterId);
      end;

      // Store filter IDs in the rule
      ARule.WFPFilterIds.Clear;
      ARule.WFPFilterIds.AddRange(FilterIds);
      ARule.Installed := True;

      Result := FilterIds.ToArray;
    finally
      FilterIds.Free;
    end;
  finally
    if AppBlob <> nil then
      FreeAppIdBlob(AppBlob);
  end;
end;

procedure TWFPEngine.UninstallRule(ARule: TFirewallRule);
var
  I: Integer;
begin
  CheckOpen;
  for I := ARule.WFPFilterIds.Count - 1 downto 0 do
  begin
    FwpmFilterDeleteById0(FEngineHandle, ARule.WFPFilterIds[I]);
  end;
  ARule.WFPFilterIds.Clear;
  ARule.Installed := False;
end;

procedure TWFPEngine.UninstallFilterById(AId: UINT64);
begin
  CheckOpen;
  FwpmFilterDeleteById0(FEngineHandle, AId);
end;

function TWFPEngine.InstallDefaultBlockAll: TArray<UINT64>;
var
  FilterIds: TList<UINT64>;
  Layers: array[0..3] of TGUID;
  I: Integer;
  FilterId: UINT64;
begin
  CheckOpen;

  // Default block filters on all four ALE auth layers (inbound + outbound,
  // IPv4 + IPv6). These block everything at the lowest weight; per-app
  // Allow rules use a higher weight and take priority.
  //
  // BLOCKED events for allowed apps (from these or external WFP providers)
  // are suppressed in HandleWFPEvent via HasAllowRuleForApp.
  Layers[0] := FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  Layers[1] := FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  Layers[2] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  Layers[3] := FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

  FilterIds := TList<UINT64>.Create;
  try
    for I := 0 to 3 do
    begin
      FilterId := CreateSingleFilter(
        Layers[I],
        'Default Block All',
        nil,  // no conditions = match everything
        0,
        FWP_ACTION_BLOCK,
        FW_WEIGHT_LOWEST
      );
      FilterIds.Add(FilterId);
    end;
    Result := FilterIds.ToArray;
  finally
    FilterIds.Free;
  end;
end;

procedure TWFPEngine.SubscribeNetEvents(ACallback: FWPM_NET_EVENT_CALLBACK0;
  AContext: Pointer; out AEventsHandle: THandle);
var
  Subscription: FWPM_NET_EVENT_SUBSCRIPTION0_REC;
  EnumTemplate: FWPM_NET_EVENT_ENUM_TEMPLATE0_REC;
  Status: DWORD;
begin
  CheckOpen;

  FillChar(EnumTemplate, SizeOf(EnumTemplate), 0);
  FillChar(Subscription, SizeOf(Subscription), 0);
  Subscription.enumTemplate := @EnumTemplate;

  AEventsHandle := 0;
  Status := FwpmNetEventSubscribe0(FEngineHandle, @Subscription,
    ACallback, AContext, @AEventsHandle);
  CheckResult(Status, 'FwpmNetEventSubscribe0');
end;

procedure TWFPEngine.UnsubscribeNetEvents(var AEventsHandle: THandle);
begin
  if (AEventsHandle <> 0) and FIsOpen then
  begin
    FwpmNetEventUnsubscribe0(FEngineHandle, AEventsHandle);
    AEventsHandle := 0;
  end;
end;

procedure TWFPEngine.EnableNetEventCollection;
var
  Value: FWP_VALUE0_REC;
begin
  CheckOpen;

  // Enable collection of net events (dropped packets)
  FillChar(Value, SizeOf(Value), 0);
  Value._type := FW.WFP.API.FWP_UINT32;
  Value.uint32 := 1;
  FwpmEngineSetOption0(FEngineHandle, FWPM_ENGINE_COLLECT_NET_EVENTS, @Value);

  // Set keywords to capture classify-allow events too
  Value.uint32 := FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW or
                  FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST or
                  FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST;
  FwpmEngineSetOption0(FEngineHandle,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, @Value);
end;

end.
