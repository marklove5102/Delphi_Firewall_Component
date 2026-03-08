unit FW.Types;

{******************************************************************************
  FW.Types - Shared Type Definitions for the Delphi Firewall Component

  Contains all enumerations, records, and event type definitions used across
  the firewall component units.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.Generics.Collections;

type
  // ===========================================================================
  // Enumerations
  // ===========================================================================

  TFirewallDirection = (
    fdInbound,      // Incoming connections only
    fdOutbound,     // Outgoing connections only
    fdBoth          // Both directions
  );

  TFirewallAction = (
    faBlock,        // Block/deny the connection
    faAllow         // Allow/permit the connection
  );

  TFirewallProtocol = (
    fpAny,          // Match any protocol
    fpTCP,          // TCP only
    fpUDP,          // UDP only
    fpICMP          // ICMP only
  );

  TFirewallIPVersion = (
    fipV4,          // IPv4 only
    fipV6,          // IPv6 only
    fipBoth         // Both IPv4 and IPv6
  );

  // ===========================================================================
  // Rule Data Record
  // ===========================================================================

  TFirewallRuleData = record
    RuleID: TGUID;                 // Unique identifier for this rule
    Name: string;                  // Human-readable rule name
    Description: string;           // Optional description
    ApplicationPath: string;       // Full path to executable (empty = any app)
    Direction: TFirewallDirection;  // Inbound/Outbound/Both
    Action: TFirewallAction;       // Block or Allow
    Protocol: TFirewallProtocol;   // TCP/UDP/ICMP/Any
    IPVersion: TFirewallIPVersion; // IPv4/IPv6/Both
    LocalAddress: string;          // Local IP (empty = any, CIDR supported)
    RemoteAddress: string;         // Remote IP (empty = any, CIDR supported)
    LocalPort: Word;               // Local port (0 = any)
    RemotePort: Word;              // Remote port (0 = any)
    LocalPortRangeEnd: Word;       // End of local port range (0 = single port)
    RemotePortRangeEnd: Word;      // End of remote port range (0 = single port)
    Weight: Byte;                  // Priority 0..7 (mapped to WFP weights)
    Enabled: Boolean;              // Whether the rule is active

    class function CreateBlock(const AName, AAppPath: string;
      ADirection: TFirewallDirection = fdBoth): TFirewallRuleData; static;
    class function CreateAllow(const AName, AAppPath: string;
      ADirection: TFirewallDirection = fdBoth): TFirewallRuleData; static;
  end;

  // ===========================================================================
  // Network Connection Entry (from polling active connections)
  // ===========================================================================

  TNetworkConnection = record
    Protocol: TFirewallProtocol;   // TCP or UDP
    IPVersion: TFirewallIPVersion; // V4 or V6
    LocalAddress: string;          // Local IP address as string
    LocalPort: Word;               // Local port number
    RemoteAddress: string;         // Remote IP address as string
    RemotePort: Word;              // Remote port number
    State: string;                 // Connection state (e.g. 'ESTABLISHED')
    StateCode: DWORD;              // Raw state code
    ProcessId: DWORD;              // Owning process ID
    ProcessName: string;           // Process executable name
    ProcessPath: string;           // Full path to process executable
  end;

  TNetworkConnectionArray = TArray<TNetworkConnection>;

  // ===========================================================================
  // Firewall Event Entry (from WFP net event subscription)
  // ===========================================================================

  TFirewallEvent = record
    TimeStamp: TDateTime;           // When the event occurred
    Direction: TFirewallDirection;   // Inbound or Outbound
    Action: TFirewallAction;         // Block or Allow
    Protocol: TFirewallProtocol;     // Protocol of the connection
    IPVersion: TFirewallIPVersion;   // IPv4 or IPv6
    LocalAddress: string;            // Local IP address
    LocalPort: Word;                 // Local port
    RemoteAddress: string;           // Remote IP address
    RemotePort: Word;                // Remote port
    ApplicationPath: string;         // Full path to application
    FilterId: UINT64;                // WFP filter ID that matched
    LayerId: Word;                   // WFP layer ID
    IsLoopback: Boolean;             // Whether the connection is loopback
  end;

  TFirewallEventArray = TArray<TFirewallEvent>;

  // ===========================================================================
  // Event Types for the VCL Component
  // ===========================================================================

  // Fired when a connection is blocked by a firewall rule
  TFirewallConnectionBlockedEvent = procedure(Sender: TObject;
    const Event: TFirewallEvent) of object;

  // Fired when a connection is explicitly allowed by a firewall rule
  TFirewallConnectionAllowedEvent = procedure(Sender: TObject;
    const Event: TFirewallEvent) of object;

  // Fired when a previously unseen application attempts a connection.
  // Set Action to decide whether to allow or block it.
  TFirewallNewAppDetectedEvent = procedure(Sender: TObject;
    const ApplicationPath: string; const Event: TFirewallEvent;
    var Action: TFirewallAction) of object;

  // Fired periodically with a snapshot of all active network connections
  TFirewallNetworkActivityEvent = procedure(Sender: TObject;
    const Connections: TNetworkConnectionArray) of object;

  // Fired when a WFP error occurs
  TFirewallErrorEvent = procedure(Sender: TObject;
    ErrorCode: DWORD; const ErrorMessage: string) of object;

  // Fired when the firewall engine state changes
  TFirewallEngineStateEvent = procedure(Sender: TObject;
    Active: Boolean) of object;

  // Fired for every network event (block or allow) - for logging
  TFirewallLogEvent = procedure(Sender: TObject;
    const Event: TFirewallEvent) of object;

  // Fired whenever a rule is added, removed, updated, enabled, or disabled
  TFirewallRuleChangeEvent = procedure(Sender: TObject) of object;

  // ===========================================================================
  // ===========================================================================
  // Simple V2 Component Types
  // ===========================================================================

  TFirewallFileDetails = record
    Exists: Boolean;
    FilePath: string;
    FileName: string;
    FileSize: Int64;
    DateCreated: TDateTime;
    DateModified: TDateTime;
    Publisher: string;
    FileDescription: string;
    FileVersion: string;
    ProductName: string;
    IsSigned: Boolean;
    CertificateSubject: string;
    CertificateIssuer: string;
    CertificateSerial: string;
  end;

  TFirewallRuleInfo = record
    RuleID: TGUID;
    ApplicationPath: string;
    Action: TFirewallAction;
    Enabled: Boolean;
  end;

  TFirewallAppDetectedEvent = procedure(Sender: TObject;
    const Event: TFirewallEvent; const FileDetails: TFirewallFileDetails) of object;

  TFirewallTrafficEvent = procedure(Sender: TObject;
    const Event: TFirewallEvent) of object;

  TFirewallRuleEvent = procedure(Sender: TObject;
    const Rule: TFirewallRuleInfo) of object;

  // Exception Types
  // ===========================================================================

  EFirewallError = class(Exception);

  EFirewallElevationRequired = class(EFirewallError)
  public
    constructor Create;
  end;

  EFirewallWFPError = class(EFirewallError)
  private
    FErrorCode: DWORD;
  public
    constructor Create(AErrorCode: DWORD; const AContext: string);
    property ErrorCode: DWORD read FErrorCode;
  end;

// ===========================================================================
// Enum Serialization Helpers (shared by FW.Rules and FW.Database)
// ===========================================================================

function DirectionToStr(D: TFirewallDirection): string;
function StrToDirection(const S: string): TFirewallDirection;
function ActionToStr(A: TFirewallAction): string;
function StrToAction(const S: string): TFirewallAction;
function ProtocolToStr(P: TFirewallProtocol): string;
function StrToProtocol(const S: string): TFirewallProtocol;
function IPVersionToStr(V: TFirewallIPVersion): string;
function StrToIPVersion(const S: string): TFirewallIPVersion;

implementation

{ Enum Serialization Helpers }

function DirectionToStr(D: TFirewallDirection): string;
begin
  case D of
    fdInbound:  Result := 'inbound';
    fdOutbound: Result := 'outbound';
    fdBoth:     Result := 'both';
  else
    Result := 'both';
  end;
end;

function StrToDirection(const S: string): TFirewallDirection;
begin
  if SameText(S, 'inbound') then
    Result := fdInbound
  else if SameText(S, 'outbound') then
    Result := fdOutbound
  else
    Result := fdBoth;
end;

function ActionToStr(A: TFirewallAction): string;
begin
  case A of
    faBlock: Result := 'block';
    faAllow: Result := 'allow';
  else
    Result := 'block';
  end;
end;

function StrToAction(const S: string): TFirewallAction;
begin
  if SameText(S, 'allow') then
    Result := faAllow
  else
    Result := faBlock;
end;

function ProtocolToStr(P: TFirewallProtocol): string;
begin
  case P of
    fpAny:  Result := 'any';
    fpTCP:  Result := 'tcp';
    fpUDP:  Result := 'udp';
    fpICMP: Result := 'icmp';
  else
    Result := 'any';
  end;
end;

function StrToProtocol(const S: string): TFirewallProtocol;
begin
  if SameText(S, 'tcp') then
    Result := fpTCP
  else if SameText(S, 'udp') then
    Result := fpUDP
  else if SameText(S, 'icmp') then
    Result := fpICMP
  else
    Result := fpAny;
end;

function IPVersionToStr(V: TFirewallIPVersion): string;
begin
  case V of
    fipV4:   Result := 'v4';
    fipV6:   Result := 'v6';
    fipBoth: Result := 'both';
  else
    Result := 'both';
  end;
end;

function StrToIPVersion(const S: string): TFirewallIPVersion;
begin
  if SameText(S, 'v4') then
    Result := fipV4
  else if SameText(S, 'v6') then
    Result := fipV6
  else
    Result := fipBoth;
end;

{ TFirewallRuleData }

class function TFirewallRuleData.CreateBlock(const AName, AAppPath: string;
  ADirection: TFirewallDirection): TFirewallRuleData;
begin
  Result := Default(TFirewallRuleData);
  Result.RuleID := TGUID.NewGuid;
  Result.Name := AName;
  Result.ApplicationPath := AAppPath;
  Result.Direction := ADirection;
  Result.Action := faBlock;
  Result.Protocol := fpAny;
  Result.IPVersion := fipBoth;
  Result.Weight := 4;
  Result.Enabled := True;
end;

class function TFirewallRuleData.CreateAllow(const AName, AAppPath: string;
  ADirection: TFirewallDirection): TFirewallRuleData;
begin
  Result := Default(TFirewallRuleData);
  Result.RuleID := TGUID.NewGuid;
  Result.Name := AName;
  Result.ApplicationPath := AAppPath;
  Result.Direction := ADirection;
  Result.Action := faAllow;
  Result.Protocol := fpAny;
  Result.IPVersion := fipBoth;
  Result.Weight := 4;
  Result.Enabled := True;
end;

{ EFirewallElevationRequired }

constructor EFirewallElevationRequired.Create;
begin
  inherited Create('Administrator privileges are required to manage the ' +
    'Windows Filtering Platform. Please run the application as Administrator.');
end;

{ EFirewallWFPError }

constructor EFirewallWFPError.Create(AErrorCode: DWORD; const AContext: string);
begin
  FErrorCode := AErrorCode;
  inherited CreateFmt('WFP Error 0x%.8x in %s: %s',
    [AErrorCode, AContext, SysErrorMessage(AErrorCode)]);
end;

end.

