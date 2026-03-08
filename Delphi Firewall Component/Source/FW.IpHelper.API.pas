unit FW.IpHelper.API;

{******************************************************************************
  FW.IpHelper.API - IP Helper API Translations for Network Monitoring

  Provides access to GetExtendedTcpTable / GetExtendedUdpTable for enumerating
  active network connections with owning process information.
******************************************************************************}

interface

uses
  Winapi.Windows;

{$ALIGN 8}
{$MINENUMSIZE 4}

const
  IPHLPAPI_DLL = 'iphlpapi.dll';

  // Address families
  AF_INET  = 2;
  AF_INET6 = 23;

  // TCP table classes
  TCP_TABLE_BASIC_LISTENER           = 0;
  TCP_TABLE_BASIC_CONNECTIONS        = 1;
  TCP_TABLE_BASIC_ALL                = 2;
  TCP_TABLE_OWNER_PID_LISTENER       = 3;
  TCP_TABLE_OWNER_PID_CONNECTIONS    = 4;
  TCP_TABLE_OWNER_PID_ALL            = 5;
  TCP_TABLE_OWNER_MODULE_LISTENER    = 6;
  TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7;
  TCP_TABLE_OWNER_MODULE_ALL         = 8;

  // UDP table classes
  UDP_TABLE_BASIC       = 0;
  UDP_TABLE_OWNER_PID   = 1;
  UDP_TABLE_OWNER_MODULE = 2;

  // TCP connection states
  MIB_TCP_STATE_CLOSED     = 1;
  MIB_TCP_STATE_LISTEN     = 2;
  MIB_TCP_STATE_SYN_SENT   = 3;
  MIB_TCP_STATE_SYN_RCVD   = 4;
  MIB_TCP_STATE_ESTAB      = 5;
  MIB_TCP_STATE_FIN_WAIT1  = 6;
  MIB_TCP_STATE_FIN_WAIT2  = 7;
  MIB_TCP_STATE_CLOSE_WAIT = 8;
  MIB_TCP_STATE_CLOSING    = 9;
  MIB_TCP_STATE_LAST_ACK   = 10;
  MIB_TCP_STATE_TIME_WAIT  = 11;
  MIB_TCP_STATE_DELETE_TCB = 12;

type
  // ---------------------------------------------------------------------------
  // IPv4 TCP Row with owning PID
  // ---------------------------------------------------------------------------
  PMibTcpRowOwnerPid = ^TMibTcpRowOwnerPid;
  TMibTcpRowOwnerPid = packed record
    dwState: DWORD;
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwRemoteAddr: DWORD;
    dwRemotePort: DWORD;
    dwOwningPid: DWORD;
  end;

  // ---------------------------------------------------------------------------
  // IPv4 TCP Table with owning PIDs
  // ---------------------------------------------------------------------------
  PMibTcpTableOwnerPid = ^TMibTcpTableOwnerPid;
  TMibTcpTableOwnerPid = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of TMibTcpRowOwnerPid;
  end;

  // ---------------------------------------------------------------------------
  // IPv6 TCP Row with owning PID
  // ---------------------------------------------------------------------------
  PMibTcp6RowOwnerPid = ^TMibTcp6RowOwnerPid;
  TMibTcp6RowOwnerPid = packed record
    ucLocalAddr: array[0..15] of Byte;
    dwLocalScopeId: DWORD;
    dwLocalPort: DWORD;
    ucRemoteAddr: array[0..15] of Byte;
    dwRemoteScopeId: DWORD;
    dwRemotePort: DWORD;
    dwState: DWORD;
    dwOwningPid: DWORD;
  end;

  // ---------------------------------------------------------------------------
  // IPv6 TCP Table with owning PIDs
  // ---------------------------------------------------------------------------
  PMibTcp6TableOwnerPid = ^TMibTcp6TableOwnerPid;
  TMibTcp6TableOwnerPid = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of TMibTcp6RowOwnerPid;
  end;

  // ---------------------------------------------------------------------------
  // IPv4 UDP Row with owning PID
  // ---------------------------------------------------------------------------
  PMibUdpRowOwnerPid = ^TMibUdpRowOwnerPid;
  TMibUdpRowOwnerPid = packed record
    dwLocalAddr: DWORD;
    dwLocalPort: DWORD;
    dwOwningPid: DWORD;
  end;

  // ---------------------------------------------------------------------------
  // IPv4 UDP Table with owning PIDs
  // ---------------------------------------------------------------------------
  PMibUdpTableOwnerPid = ^TMibUdpTableOwnerPid;
  TMibUdpTableOwnerPid = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of TMibUdpRowOwnerPid;
  end;

  // ---------------------------------------------------------------------------
  // IPv6 UDP Row with owning PID
  // ---------------------------------------------------------------------------
  PMibUdp6RowOwnerPid = ^TMibUdp6RowOwnerPid;
  TMibUdp6RowOwnerPid = packed record
    ucLocalAddr: array[0..15] of Byte;
    dwLocalScopeId: DWORD;
    dwLocalPort: DWORD;
    dwOwningPid: DWORD;
  end;

  // ---------------------------------------------------------------------------
  // IPv6 UDP Table with owning PIDs
  // ---------------------------------------------------------------------------
  PMibUdp6TableOwnerPid = ^TMibUdp6TableOwnerPid;
  TMibUdp6TableOwnerPid = packed record
    dwNumEntries: DWORD;
    table: array[0..0] of TMibUdp6RowOwnerPid;
  end;

// =============================================================================
// API Function Imports
// =============================================================================

function GetExtendedTcpTable(
  pTcpTable: Pointer;
  var pdwSize: DWORD;
  bOrder: BOOL;
  ulAf: ULONG;
  TableClass: Integer;
  Reserved: ULONG
): DWORD; stdcall; external IPHLPAPI_DLL;

function GetExtendedUdpTable(
  pUdpTable: Pointer;
  var pdwSize: DWORD;
  bOrder: BOOL;
  ulAf: ULONG;
  TableClass: Integer;
  Reserved: ULONG
): DWORD; stdcall; external IPHLPAPI_DLL;

// =============================================================================
// Helper Functions
// =============================================================================

function TcpStateToString(State: DWORD): string;
function IPv4ToStr(Addr: DWORD): string;
function IPv6ToStr(const Addr: array of Byte): string;
function NtoHS(NetShort: Word): Word; inline;

implementation

uses
  System.SysUtils;

function TcpStateToString(State: DWORD): string;
begin
  case State of
    MIB_TCP_STATE_CLOSED:     Result := 'CLOSED';
    MIB_TCP_STATE_LISTEN:     Result := 'LISTEN';
    MIB_TCP_STATE_SYN_SENT:   Result := 'SYN_SENT';
    MIB_TCP_STATE_SYN_RCVD:   Result := 'SYN_RCVD';
    MIB_TCP_STATE_ESTAB:      Result := 'ESTABLISHED';
    MIB_TCP_STATE_FIN_WAIT1:  Result := 'FIN_WAIT1';
    MIB_TCP_STATE_FIN_WAIT2:  Result := 'FIN_WAIT2';
    MIB_TCP_STATE_CLOSE_WAIT: Result := 'CLOSE_WAIT';
    MIB_TCP_STATE_CLOSING:    Result := 'CLOSING';
    MIB_TCP_STATE_LAST_ACK:   Result := 'LAST_ACK';
    MIB_TCP_STATE_TIME_WAIT:  Result := 'TIME_WAIT';
    MIB_TCP_STATE_DELETE_TCB: Result := 'DELETE_TCB';
  else
    Result := Format('UNKNOWN(%d)', [State]);
  end;
end;

function IPv4ToStr(Addr: DWORD): string;
begin
  Result := Format('%d.%d.%d.%d', [
    Addr and $FF,
    (Addr shr 8) and $FF,
    (Addr shr 16) and $FF,
    (Addr shr 24) and $FF
  ]);
end;

function IPv6ToStr(const Addr: array of Byte): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to 7 do
  begin
    if I > 0 then
      Result := Result + ':';
    Result := Result + IntToHex(Word(Addr[I * 2]) shl 8 or Addr[I * 2 + 1], 1);
  end;
end;

function NtoHS(NetShort: Word): Word;
begin
  Result := Swap(NetShort);
end;

end.
