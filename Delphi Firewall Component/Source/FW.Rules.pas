unit FW.Rules;

{******************************************************************************
  FW.Rules - Firewall Rule Management with JSON Persistence

  TFirewallRule wraps a TFirewallRuleData record with runtime state (installed
  WFP filter IDs). TFirewallRuleList provides collection management with
  search and JSON save/load capabilities.
******************************************************************************}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  System.JSON, FW.Types;

type
  // ===========================================================================
  // TFirewallRule - Single firewall rule with runtime state
  // ===========================================================================
  TFirewallRule = class
  private
    FData: TFirewallRuleData;
    FWFPFilterIds: TList<UINT64>;
    FInstalled: Boolean;
  public
    constructor Create; overload;
    constructor Create(const AData: TFirewallRuleData); overload;
    destructor Destroy; override;

    function ToJSON: TJSONObject;
    procedure FromJSON(AObj: TJSONObject);

    property Data: TFirewallRuleData read FData write FData;
    property WFPFilterIds: TList<UINT64> read FWFPFilterIds;
    property Installed: Boolean read FInstalled write FInstalled;
  end;

  // ===========================================================================
  // TFirewallRuleList - Collection of firewall rules
  // ===========================================================================
  TFirewallRuleList = class(TObjectList<TFirewallRule>)
  public
    function FindByGUID(const AGUID: TGUID): TFirewallRule;
    function FindByAppPath(const APath: string): TFirewallRule;
    function FindAllByAppPath(const APath: string): TArray<TFirewallRule>;

    procedure SaveToFile(const AFileName: string);
    procedure LoadFromFile(const AFileName: string);
    procedure SaveToStream(AStream: TStream);
    procedure LoadFromStream(AStream: TStream);
  end;

implementation

uses
  System.IOUtils;

// =============================================================================
// JSON field names
// =============================================================================
const
  JSON_RULE_ID       = 'ruleId';
  JSON_NAME          = 'name';
  JSON_DESCRIPTION   = 'description';
  JSON_APP_PATH      = 'applicationPath';
  JSON_DIRECTION     = 'direction';
  JSON_ACTION        = 'action';
  JSON_PROTOCOL      = 'protocol';
  JSON_IP_VERSION    = 'ipVersion';
  JSON_LOCAL_ADDR    = 'localAddress';
  JSON_REMOTE_ADDR   = 'remoteAddress';
  JSON_LOCAL_PORT    = 'localPort';
  JSON_REMOTE_PORT   = 'remotePort';
  JSON_LOCAL_PORT_END  = 'localPortRangeEnd';
  JSON_REMOTE_PORT_END = 'remotePortRangeEnd';
  JSON_WEIGHT        = 'weight';
  JSON_ENABLED       = 'enabled';

// Enum serialization helpers are now in FW.Types.pas

{ TFirewallRule }

constructor TFirewallRule.Create;
begin
  inherited Create;
  FWFPFilterIds := TList<UINT64>.Create;
  FInstalled := False;
  FData := Default(TFirewallRuleData);
  FData.RuleID := TGUID.NewGuid;
  FData.Enabled := True;
  FData.Direction := fdBoth;
  FData.Action := faBlock;
  FData.Protocol := fpAny;
  FData.IPVersion := fipBoth;
end;

constructor TFirewallRule.Create(const AData: TFirewallRuleData);
begin
  inherited Create;
  FWFPFilterIds := TList<UINT64>.Create;
  FInstalled := False;
  FData := AData;
  if FData.RuleID = TGUID.Empty then
    FData.RuleID := TGUID.NewGuid;
end;

destructor TFirewallRule.Destroy;
begin
  FWFPFilterIds.Free;
  inherited Destroy;
end;

function TFirewallRule.ToJSON: TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair(JSON_RULE_ID, GUIDToString(FData.RuleID));
  Result.AddPair(JSON_NAME, FData.Name);
  Result.AddPair(JSON_DESCRIPTION, FData.Description);
  Result.AddPair(JSON_APP_PATH, FData.ApplicationPath);
  Result.AddPair(JSON_DIRECTION, DirectionToStr(FData.Direction));
  Result.AddPair(JSON_ACTION, ActionToStr(FData.Action));
  Result.AddPair(JSON_PROTOCOL, ProtocolToStr(FData.Protocol));
  Result.AddPair(JSON_IP_VERSION, IPVersionToStr(FData.IPVersion));
  Result.AddPair(JSON_LOCAL_ADDR, FData.LocalAddress);
  Result.AddPair(JSON_REMOTE_ADDR, FData.RemoteAddress);
  Result.AddPair(JSON_LOCAL_PORT, TJSONNumber.Create(FData.LocalPort));
  Result.AddPair(JSON_REMOTE_PORT, TJSONNumber.Create(FData.RemotePort));
  Result.AddPair(JSON_LOCAL_PORT_END, TJSONNumber.Create(FData.LocalPortRangeEnd));
  Result.AddPair(JSON_REMOTE_PORT_END, TJSONNumber.Create(FData.RemotePortRangeEnd));
  Result.AddPair(JSON_WEIGHT, TJSONNumber.Create(FData.Weight));
  Result.AddPair(JSON_ENABLED, TJSONBool.Create(FData.Enabled));
end;

procedure TFirewallRule.FromJSON(AObj: TJSONObject);

  function GetStr(const AKey: string; const ADefault: string = ''): string;
  var
    V: TJSONValue;
  begin
    V := AObj.GetValue(AKey);
    if Assigned(V) then
      Result := V.Value
    else
      Result := ADefault;
  end;

  function GetInt(const AKey: string; ADefault: Integer = 0): Integer;
  var
    V: TJSONValue;
  begin
    V := AObj.GetValue(AKey);
    if Assigned(V) and (V is TJSONNumber) then
      Result := TJSONNumber(V).AsInt
    else
      Result := ADefault;
  end;

  function GetBool(const AKey: string; ADefault: Boolean = False): Boolean;
  var
    V: TJSONValue;
  begin
    V := AObj.GetValue(AKey);
    if Assigned(V) and (V is TJSONBool) then
      Result := TJSONBool(V).AsBoolean
    else
      Result := ADefault;
  end;

var
  GuidStr: string;
begin
  GuidStr := GetStr(JSON_RULE_ID);
  if GuidStr <> '' then
    FData.RuleID := StringToGUID(GuidStr)
  else
    FData.RuleID := TGUID.NewGuid;

  FData.Name := GetStr(JSON_NAME);
  FData.Description := GetStr(JSON_DESCRIPTION);
  FData.ApplicationPath := GetStr(JSON_APP_PATH);
  FData.Direction := StrToDirection(GetStr(JSON_DIRECTION, 'both'));
  FData.Action := StrToAction(GetStr(JSON_ACTION, 'block'));
  FData.Protocol := StrToProtocol(GetStr(JSON_PROTOCOL, 'any'));
  FData.IPVersion := StrToIPVersion(GetStr(JSON_IP_VERSION, 'both'));
  FData.LocalAddress := GetStr(JSON_LOCAL_ADDR);
  FData.RemoteAddress := GetStr(JSON_REMOTE_ADDR);
  FData.LocalPort := Word(GetInt(JSON_LOCAL_PORT));
  FData.RemotePort := Word(GetInt(JSON_REMOTE_PORT));
  FData.LocalPortRangeEnd := Word(GetInt(JSON_LOCAL_PORT_END));
  FData.RemotePortRangeEnd := Word(GetInt(JSON_REMOTE_PORT_END));
  FData.Weight := Byte(GetInt(JSON_WEIGHT, 4));
  FData.Enabled := GetBool(JSON_ENABLED, True);

  FInstalled := False;
  FWFPFilterIds.Clear;
end;

{ TFirewallRuleList }

function TFirewallRuleList.FindByGUID(const AGUID: TGUID): TFirewallRule;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    if IsEqualGUID(Items[I].Data.RuleID, AGUID) then
      Exit(Items[I]);
  Result := nil;
end;

function TFirewallRuleList.FindByAppPath(const APath: string): TFirewallRule;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    if SameText(Items[I].Data.ApplicationPath, APath) then
      Exit(Items[I]);
  Result := nil;
end;

function TFirewallRuleList.FindAllByAppPath(
  const APath: string): TArray<TFirewallRule>;
var
  I: Integer;
  LList: TList<TFirewallRule>;
begin
  LList := TList<TFirewallRule>.Create;
  try
    for I := 0 to Count - 1 do
      if SameText(Items[I].Data.ApplicationPath, APath) then
        LList.Add(Items[I]);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

procedure TFirewallRuleList.SaveToStream(AStream: TStream);
var
  LArray: TJSONArray;
  I: Integer;
  LBytes: TBytes;
begin
  LArray := TJSONArray.Create;
  try
    for I := 0 to Count - 1 do
      LArray.AddElement(Items[I].ToJSON);
    LBytes := TEncoding.UTF8.GetBytes(LArray.Format(2));
    AStream.WriteBuffer(LBytes[0], Length(LBytes));
  finally
    LArray.Free;
  end;
end;

procedure TFirewallRuleList.LoadFromStream(AStream: TStream);
var
  LBytes: TBytes;
  LJsonStr: string;
  LValue: TJSONValue;
  LArray: TJSONArray;
  I: Integer;
  LRule: TFirewallRule;
begin
  SetLength(LBytes, AStream.Size - AStream.Position);
  if Length(LBytes) = 0 then
    Exit;
  AStream.ReadBuffer(LBytes[0], Length(LBytes));
  LJsonStr := TEncoding.UTF8.GetString(LBytes);

  LValue := TJSONObject.ParseJSONValue(LJsonStr);
  if not Assigned(LValue) then
    raise EFirewallError.Create('Invalid JSON in rules file');
  try
    if not (LValue is TJSONArray) then
      raise EFirewallError.Create('Expected JSON array in rules file');
    LArray := TJSONArray(LValue);
    Clear;
    for I := 0 to LArray.Count - 1 do
    begin
      if LArray.Items[I] is TJSONObject then
      begin
        LRule := TFirewallRule.Create;
        LRule.FromJSON(TJSONObject(LArray.Items[I]));
        Add(LRule);
      end;
    end;
  finally
    LValue.Free;
  end;
end;

procedure TFirewallRuleList.SaveToFile(const AFileName: string);
var
  LStream: TFileStream;
begin
  TDirectory.CreateDirectory(TPath.GetDirectoryName(AFileName));
  LStream := TFileStream.Create(AFileName, fmCreate);
  try
    SaveToStream(LStream);
  finally
    LStream.Free;
  end;
end;

procedure TFirewallRuleList.LoadFromFile(const AFileName: string);
var
  LStream: TFileStream;
begin
  if not TFile.Exists(AFileName) then
    raise EFirewallError.CreateFmt('Rules file not found: %s', [AFileName]);
  LStream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    LoadFromStream(LStream);
  finally
    LStream.Free;
  end;
end;

end.
