unit FW.EventSubscriber;

{******************************************************************************
  FW.EventSubscriber - WFP Net Event Subscription

  Wraps FwpmNetEventSubscribe0 to receive real-time notifications when
  connections are classified (blocked or allowed) by WFP. Includes device
  path to DOS path conversion and first-seen application tracking.

  IMPORTANT: The WFP callback runs on an arbitrary system thread. All data
  is copied into value-type records and marshaled via anonymous method
  references. No VCL objects are accessed from the callback.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes,
  System.SyncObjs, System.Generics.Collections,
  FW.WFP.API, FW.Types;

type
  // Anonymous method references for event delivery
  TNetEventReceivedProc = reference to procedure(const AEvent: TFirewallEvent);

  TWFPEventSubscriber = class
  private
    FEventsHandle: THandle;
    FActive: Boolean;
    FKnownApps: TDictionary<string, Boolean>;
    FKnownAppsLock: TCriticalSection;

    // Static callback - must be stdcall, receives instance via context pointer
    class procedure WFPNetEventCallback(context: Pointer;
      const event: PFWPM_NET_EVENT1); stdcall; static;

    procedure HandleNetEvent(const event: PFWPM_NET_EVENT1);
    function ExtractAppPath(const appId: FWP_BYTE_BLOB_REC): string;
    function DevicePathToDosPath(const ADevicePath: string): string;
    function ParseEvent(const event: PFWPM_NET_EVENT1): TFirewallEvent;
  public
    OnEventReceived: TNetEventReceivedProc;
    OnNewAppDetected: TNetEventReceivedProc;

    constructor Create;
    destructor Destroy; override;

    procedure Subscribe(AEngineHandle: THandle);
    procedure Unsubscribe(AEngineHandle: THandle);

    function IsAppKnown(const APath: string): Boolean;
    procedure MarkAppKnown(const APath: string);
    procedure UnmarkAppKnown(const APath: string);
    procedure ClearKnownApps;

    property Active: Boolean read FActive;
  end;

implementation

uses
  FW.IpHelper.API;

function Swap32(Value: UINT32): DWORD;
begin
  Result := ((Value and $FF) shl 24) or
            ((Value and $FF00) shl 8) or
            ((Value and $FF0000) shr 8) or
            ((Value and $FF000000) shr 24);
end;

{ TWFPEventSubscriber }

constructor TWFPEventSubscriber.Create;
begin
  inherited Create;
  FEventsHandle := 0;
  FActive := False;
  FKnownApps := TDictionary<string, Boolean>.Create;
  FKnownAppsLock := TCriticalSection.Create;
end;

destructor TWFPEventSubscriber.Destroy;
begin
  FKnownAppsLock.Free;
  FKnownApps.Free;
  inherited Destroy;
end;

class procedure TWFPEventSubscriber.WFPNetEventCallback(context: Pointer;
  const event: PFWPM_NET_EVENT1);
var
  Self: TWFPEventSubscriber;
begin
  Self := TWFPEventSubscriber(context);
  if Assigned(Self) and Assigned(event) then
  begin
    try
      Self.HandleNetEvent(event);
    except
      // Swallow exceptions in WFP callback thread - cannot propagate
    end;
  end;
end;

procedure TWFPEventSubscriber.HandleNetEvent(const event: PFWPM_NET_EVENT1);
var
  FWEvent: TFirewallEvent;
  AppPath: string;
  IsNew: Boolean;
begin
  FWEvent := ParseEvent(event);

  // Check if this is a new application
  AppPath := FWEvent.ApplicationPath;
  if AppPath <> '' then
  begin
    IsNew := False;
    FKnownAppsLock.Enter;
    try
      if not FKnownApps.ContainsKey(UpperCase(AppPath)) then
      begin
        FKnownApps.Add(UpperCase(AppPath), True);
        IsNew := True;
      end;
    finally
      FKnownAppsLock.Leave;
    end;

    if IsNew and Assigned(OnNewAppDetected) then
      OnNewAppDetected(FWEvent);
  end;

  // Fire general event
  if Assigned(OnEventReceived) then
    OnEventReceived(FWEvent);
end;

function TWFPEventSubscriber.ExtractAppPath(
  const appId: FWP_BYTE_BLOB_REC): string;
var
  DevicePath: string;
begin
  Result := '';
  if (appId.size = 0) or (appId.data = nil) then
    Exit;

  // WFP app ID is a wide string in device path format
  // e.g., \device\harddiskvolume3\windows\system32\svchost.exe
  SetString(DevicePath, PWideChar(appId.data),
    (appId.size div SizeOf(WideChar)) - 1);  // -1 for null terminator

  Result := DevicePathToDosPath(DevicePath);
end;

function TWFPEventSubscriber.DevicePathToDosPath(
  const ADevicePath: string): string;
var
  Drive: Char;
  DevName: array[0..MAX_PATH - 1] of WideChar;
  DevStr: string;
  Ret: DWORD;
begin
  Result := ADevicePath;

  // Try mapping device path to drive letter
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

function TWFPEventSubscriber.ParseEvent(
  const event: PFWPM_NET_EVENT1): TFirewallEvent;
var
  Header: FWPM_NET_EVENT_HEADER1_REC;
  SysTime: TSystemTime;
begin
  FillChar(Result, SizeOf(Result), 0);
  Header := event^.header;

  // Timestamp
  if (Header.timeStamp.dwLowDateTime <> 0) or
     (Header.timeStamp.dwHighDateTime <> 0) then
  begin
    FileTimeToSystemTime(Header.timeStamp, SysTime);
    Result.TimeStamp := SystemTimeToDateTime(SysTime);
  end
  else
    Result.TimeStamp := Now;

  // IP Version
  if (Header.flags and FWPM_NET_EVENT_FLAG_IP_VERSION_SET) <> 0 then
  begin
    case Header.ipVersion of
      FWP_IP_VERSION_V4: Result.IPVersion := fipV4;
      FWP_IP_VERSION_V6: Result.IPVersion := fipV6;
    else
      Result.IPVersion := fipV4;
    end;
  end;

  // Protocol
  if (Header.flags and FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) <> 0 then
  begin
    case Header.ipProtocol of
      IPPROTO_TCP: Result.Protocol := fpTCP;
      IPPROTO_UDP: Result.Protocol := fpUDP;
      IPPROTO_ICMP, IPPROTO_ICMPV6: Result.Protocol := fpICMP;
    else
      Result.Protocol := fpAny;
    end;
  end;

  // Local address
  if (Header.flags and FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET) <> 0 then
  begin
    if Result.IPVersion = fipV4 then
      Result.LocalAddress := FW.IpHelper.API.IPv4ToStr(
        Swap32(Header.localAddr.V4))
    else if Result.IPVersion = fipV6 then
      Result.LocalAddress := FW.IpHelper.API.IPv6ToStr(Header.localAddr.V6);
  end;

  // Remote address
  if (Header.flags and FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) <> 0 then
  begin
    if Result.IPVersion = fipV4 then
      Result.RemoteAddress := FW.IpHelper.API.IPv4ToStr(
        Swap32(Header.remoteAddr.V4))
    else if Result.IPVersion = fipV6 then
      Result.RemoteAddress := FW.IpHelper.API.IPv6ToStr(Header.remoteAddr.V6);
  end;

  // Ports
  if (Header.flags and FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET) <> 0 then
    Result.LocalPort := Header.localPort;

  if (Header.flags and FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET) <> 0 then
    Result.RemotePort := Header.remotePort;

  // Application path
  if (Header.flags and FWPM_NET_EVENT_FLAG_APP_ID_SET) <> 0 then
    Result.ApplicationPath := ExtractAppPath(Header.appId);

  // Event type -> action and direction
  case event^._type of
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
    begin
      Result.Action := faBlock;
      if Assigned(event^.classifyDrop) then
      begin
        Result.FilterId := event^.classifyDrop^.filterId;
        Result.LayerId := event^.classifyDrop^.layerId;
        Result.IsLoopback := Boolean(event^.classifyDrop^.isLoopback);
        // Determine direction from msFwpDirection
        if event^.classifyDrop^.msFwpDirection = 0 then
          Result.Direction := fdOutbound
        else
          Result.Direction := fdInbound;
      end;
    end;

    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
    begin
      Result.Action := faAllow;
      if Assigned(event^.classifyAllow) then
      begin
        Result.FilterId := event^.classifyAllow^.filterId;
        Result.LayerId := event^.classifyAllow^.layerId;
        Result.IsLoopback := Boolean(event^.classifyAllow^.isLoopback);
        if event^.classifyAllow^.msFwpDirection = 0 then
          Result.Direction := fdOutbound
        else
          Result.Direction := fdInbound;
      end;
    end;
  else
    // Other event types (IPSEC, IKE failures, etc.) - treat as block
    Result.Action := faBlock;
    Result.Direction := fdInbound;
  end;
end;

procedure TWFPEventSubscriber.Subscribe(AEngineHandle: THandle);
var
  Subscription: FWPM_NET_EVENT_SUBSCRIPTION0_REC;
  EnumTemplate: FWPM_NET_EVENT_ENUM_TEMPLATE0_REC;
  Status: DWORD;
begin
  if FActive then
    Exit;

  FillChar(EnumTemplate, SizeOf(EnumTemplate), 0);
  FillChar(Subscription, SizeOf(Subscription), 0);
  Subscription.enumTemplate := @EnumTemplate;

  FEventsHandle := 0;
  Status := FwpmNetEventSubscribe0(AEngineHandle, @Subscription,
    @WFPNetEventCallback, Self, @FEventsHandle);

  if Status <> ERROR_SUCCESS then
    raise EFirewallWFPError.Create(Status, 'FwpmNetEventSubscribe0');

  FActive := True;
end;

procedure TWFPEventSubscriber.Unsubscribe(AEngineHandle: THandle);
begin
  if not FActive then
    Exit;

  if FEventsHandle <> 0 then
  begin
    FwpmNetEventUnsubscribe0(AEngineHandle, FEventsHandle);
    FEventsHandle := 0;
  end;

  FActive := False;
end;

function TWFPEventSubscriber.IsAppKnown(const APath: string): Boolean;
begin
  FKnownAppsLock.Enter;
  try
    Result := FKnownApps.ContainsKey(UpperCase(APath));
  finally
    FKnownAppsLock.Leave;
  end;
end;

procedure TWFPEventSubscriber.MarkAppKnown(const APath: string);
begin
  FKnownAppsLock.Enter;
  try
    FKnownApps.AddOrSetValue(UpperCase(APath), True);
  finally
    FKnownAppsLock.Leave;
  end;
end;

procedure TWFPEventSubscriber.UnmarkAppKnown(const APath: string);
begin
  FKnownAppsLock.Enter;
  try
    FKnownApps.Remove(UpperCase(APath));
  finally
    FKnownAppsLock.Leave;
  end;
end;

procedure TWFPEventSubscriber.ClearKnownApps;
begin
  FKnownAppsLock.Enter;
  try
    FKnownApps.Clear;
  finally
    FKnownAppsLock.Leave;
  end;
end;

end.
