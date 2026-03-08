unit FW.Monitor;

{******************************************************************************
  FW.Monitor - Network Connection Monitor

  Polls the system TCP/UDP connection tables to provide a real-time snapshot
  of all active network connections with owning process information. Thread-
  safe: Refresh() is called from the worker thread, GetSnapshot() is safe
  to call from any thread.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils,
  System.SyncObjs, System.Generics.Collections,
  FW.IpHelper.API, FW.Types;

function QueryFullProcessImageNameW(hProcess: THandle; dwFlags: DWORD;
  lpExeName: PWideChar; lpdwSize: PDWORD): BOOL; stdcall;
  external kernel32 name 'QueryFullProcessImageNameW';

type
  TNetworkMonitor = class
  private
    FConnections: TNetworkConnectionArray;
    FLock: TCriticalSection;
    FKernelImagePath: string;

    function GetTcp4Connections: TNetworkConnectionArray;
    function GetTcp6Connections: TNetworkConnectionArray;
    function GetUdp4Connections: TNetworkConnectionArray;
    function GetUdp6Connections: TNetworkConnectionArray;
    function GetKernelImagePath: string;
    function GetProcessPath(APID: DWORD): string;
    function GetProcessName(const APath: string): string;
  public
    constructor Create;
    destructor Destroy; override;

    // Called from worker thread on a polling interval
    procedure Refresh;

    // Thread-safe snapshot of current connections
    function GetSnapshot: TNetworkConnectionArray;

    // Filtered queries
    function GetConnectionsByPID(APID: DWORD): TNetworkConnectionArray;
    function GetConnectionsByPath(const APath: string): TNetworkConnectionArray;

    // Summary stats
    function GetTotalConnectionCount: Integer;
  end;

implementation

// Disable range checking for this unit. The IP Helper table structures use
// C-style variable-length arrays declared as array[0..0]. Accessing indices
// beyond 0 is intentional and correct (the actual memory is heap-allocated
// to fit all entries), but triggers ERangeError when {$R+} is active.
{$R-}

const
  PROCESS_QUERY_LIMITED_INFORMATION = $1000;

function PortFromTableValue(APortField: DWORD): Word; inline;
begin
  // IP Helper stores ports in a DWORD where only the low 16 bits carry
  // the network-order port value. Mask first to avoid range-check failures.
  Result := NtoHS(Word(APortField and $FFFF));
end;

{ TNetworkMonitor }

constructor TNetworkMonitor.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FKernelImagePath := '';
end;

destructor TNetworkMonitor.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

function TNetworkMonitor.GetProcessPath(APID: DWORD): string;
var
  hProcess: THandle;
  Buf: array[0..MAX_PATH] of WideChar;
  BufSize: DWORD;
begin
  Result := '';
  if APID = 0 then
  begin
    Result := GetKernelImagePath;
    if Result = '' then
      Result := 'System Idle Process';
    Exit;
  end;
  if APID = 4 then
  begin
    Result := GetKernelImagePath;
    if Result <> '' then
      Exit;
  end;

  hProcess := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, APID);
  if hProcess <> 0 then
  try
    BufSize := MAX_PATH;
    FillChar(Buf, SizeOf(Buf), 0);
    if QueryFullProcessImageNameW(hProcess, 0, @Buf[0], @BufSize) then
      Result := Buf;
  finally
    CloseHandle(hProcess);
  end;

  if (Result = '') and (APID = 4) then
    Result := 'System';
end;

function TNetworkMonitor.GetKernelImagePath: string;
var
  WinDir: string;
begin
  if FKernelImagePath <> '' then
    Exit(FKernelImagePath);

  WinDir := GetEnvironmentVariable('SystemRoot');
  if WinDir = '' then
    WinDir := GetEnvironmentVariable('windir');
  if WinDir = '' then
    WinDir := 'C:\Windows';

  Result := TPath.Combine(WinDir, 'System32\ntoskrnl.exe');
  // Do not validate with FileExists here. In 32-bit processes on 64-bit
  // Windows, System32 can be WOW64-redirected and report false negatives.
  // The path is still the canonical identity we want for kernel traffic.

  FKernelImagePath := Result;
end;

function TNetworkMonitor.GetProcessName(const APath: string): string;
begin
  if APath = '' then
    Result := 'Unknown'
  else if (APath = 'System Idle Process') or (APath = 'System') then
    Result := APath
  else
    Result := ExtractFileName(APath);
end;

function TNetworkMonitor.GetTcp4Connections: TNetworkConnectionArray;
var
  TableSize: DWORD;
  Table: PMibTcpTableOwnerPid;
  I: Integer;
  Conn: TNetworkConnection;
  Status: DWORD;
begin
  Result := nil;
  TableSize := 0;

  // First call to get required buffer size
  Status := GetExtendedTcpTable(nil, TableSize, False,
    FW.IpHelper.API.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  if (Status <> ERROR_INSUFFICIENT_BUFFER) and (Status <> ERROR_SUCCESS) then
    Exit;

  GetMem(Table, TableSize);
  try
    Status := GetExtendedTcpTable(Table, TableSize, False,
      FW.IpHelper.API.AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if Status <> ERROR_SUCCESS then
      Exit;

    SetLength(Result, Table.dwNumEntries);
    for I := 0 to Table.dwNumEntries - 1 do
    begin
      Conn := Default(TNetworkConnection);
      Conn.Protocol := fpTCP;
      Conn.IPVersion := fipV4;
      Conn.LocalAddress := IPv4ToStr(Table.table[I].dwLocalAddr);
      Conn.LocalPort := PortFromTableValue(Table.table[I].dwLocalPort);
      Conn.RemoteAddress := IPv4ToStr(Table.table[I].dwRemoteAddr);
      Conn.RemotePort := PortFromTableValue(Table.table[I].dwRemotePort);
      Conn.StateCode := Table.table[I].dwState;
      Conn.State := TcpStateToString(Table.table[I].dwState);
      Conn.ProcessId := Table.table[I].dwOwningPid;
      Conn.ProcessPath := GetProcessPath(Table.table[I].dwOwningPid);
      Conn.ProcessName := GetProcessName(Conn.ProcessPath);
      Result[I] := Conn;
    end;
  finally
    FreeMem(Table);
  end;
end;

function TNetworkMonitor.GetTcp6Connections: TNetworkConnectionArray;
var
  TableSize: DWORD;
  Table: PMibTcp6TableOwnerPid;
  I: Integer;
  Conn: TNetworkConnection;
  Status: DWORD;
begin
  Result := nil;
  TableSize := 0;

  Status := GetExtendedTcpTable(nil, TableSize, False,
    FW.IpHelper.API.AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
  if (Status <> ERROR_INSUFFICIENT_BUFFER) and (Status <> ERROR_SUCCESS) then
    Exit;

  GetMem(Table, TableSize);
  try
    Status := GetExtendedTcpTable(Table, TableSize, False,
      FW.IpHelper.API.AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if Status <> ERROR_SUCCESS then
      Exit;

    SetLength(Result, Table.dwNumEntries);
    for I := 0 to Table.dwNumEntries - 1 do
    begin
      Conn := Default(TNetworkConnection);
      Conn.Protocol := fpTCP;
      Conn.IPVersion := fipV6;
      Conn.LocalAddress := IPv6ToStr(Table.table[I].ucLocalAddr);
      Conn.LocalPort := PortFromTableValue(Table.table[I].dwLocalPort);
      Conn.RemoteAddress := IPv6ToStr(Table.table[I].ucRemoteAddr);
      Conn.RemotePort := PortFromTableValue(Table.table[I].dwRemotePort);
      Conn.StateCode := Table.table[I].dwState;
      Conn.State := TcpStateToString(Table.table[I].dwState);
      Conn.ProcessId := Table.table[I].dwOwningPid;
      Conn.ProcessPath := GetProcessPath(Table.table[I].dwOwningPid);
      Conn.ProcessName := GetProcessName(Conn.ProcessPath);
      Result[I] := Conn;
    end;
  finally
    FreeMem(Table);
  end;
end;

function TNetworkMonitor.GetUdp4Connections: TNetworkConnectionArray;
var
  TableSize: DWORD;
  Table: PMibUdpTableOwnerPid;
  I: Integer;
  Conn: TNetworkConnection;
  Status: DWORD;
begin
  Result := nil;
  TableSize := 0;

  Status := GetExtendedUdpTable(nil, TableSize, False,
    FW.IpHelper.API.AF_INET, UDP_TABLE_OWNER_PID, 0);
  if (Status <> ERROR_INSUFFICIENT_BUFFER) and (Status <> ERROR_SUCCESS) then
    Exit;

  GetMem(Table, TableSize);
  try
    Status := GetExtendedUdpTable(Table, TableSize, False,
      FW.IpHelper.API.AF_INET, UDP_TABLE_OWNER_PID, 0);
    if Status <> ERROR_SUCCESS then
      Exit;

    SetLength(Result, Table.dwNumEntries);
    for I := 0 to Table.dwNumEntries - 1 do
    begin
      Conn := Default(TNetworkConnection);
      Conn.Protocol := fpUDP;
      Conn.IPVersion := fipV4;
      Conn.LocalAddress := IPv4ToStr(Table.table[I].dwLocalAddr);
      Conn.LocalPort := PortFromTableValue(Table.table[I].dwLocalPort);
      Conn.RemoteAddress := '*';
      Conn.RemotePort := 0;
      Conn.State := 'LISTENING';
      Conn.StateCode := 0;
      Conn.ProcessId := Table.table[I].dwOwningPid;
      Conn.ProcessPath := GetProcessPath(Table.table[I].dwOwningPid);
      Conn.ProcessName := GetProcessName(Conn.ProcessPath);
      Result[I] := Conn;
    end;
  finally
    FreeMem(Table);
  end;
end;

function TNetworkMonitor.GetUdp6Connections: TNetworkConnectionArray;
var
  TableSize: DWORD;
  Table: PMibUdp6TableOwnerPid;
  I: Integer;
  Conn: TNetworkConnection;
  Status: DWORD;
begin
  Result := nil;
  TableSize := 0;

  Status := GetExtendedUdpTable(nil, TableSize, False,
    FW.IpHelper.API.AF_INET6, UDP_TABLE_OWNER_PID, 0);
  if (Status <> ERROR_INSUFFICIENT_BUFFER) and (Status <> ERROR_SUCCESS) then
    Exit;

  GetMem(Table, TableSize);
  try
    Status := GetExtendedUdpTable(Table, TableSize, False,
      FW.IpHelper.API.AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if Status <> ERROR_SUCCESS then
      Exit;

    SetLength(Result, Table.dwNumEntries);
    for I := 0 to Table.dwNumEntries - 1 do
    begin
      Conn := Default(TNetworkConnection);
      Conn.Protocol := fpUDP;
      Conn.IPVersion := fipV6;
      Conn.LocalAddress := IPv6ToStr(Table.table[I].ucLocalAddr);
      Conn.LocalPort := PortFromTableValue(Table.table[I].dwLocalPort);
      Conn.RemoteAddress := '*';
      Conn.RemotePort := 0;
      Conn.State := 'LISTENING';
      Conn.StateCode := 0;
      Conn.ProcessId := Table.table[I].dwOwningPid;
      Conn.ProcessPath := GetProcessPath(Table.table[I].dwOwningPid);
      Conn.ProcessName := GetProcessName(Conn.ProcessPath);
      Result[I] := Conn;
    end;
  finally
    FreeMem(Table);
  end;
end;

procedure TNetworkMonitor.Refresh;
var
  Tcp4, Tcp6, Udp4, Udp6: TNetworkConnectionArray;
  Combined: TNetworkConnectionArray;
  TotalLen, Offset, I: Integer;
begin
  // Collect all connection types
  Tcp4 := GetTcp4Connections;
  Tcp6 := GetTcp6Connections;
  Udp4 := GetUdp4Connections;
  Udp6 := GetUdp6Connections;

  // Merge into single array
  TotalLen := Length(Tcp4) + Length(Tcp6) + Length(Udp4) + Length(Udp6);
  SetLength(Combined, TotalLen);

  Offset := 0;
  if Length(Tcp4) > 0 then
  begin
    for I := 0 to Length(Tcp4) - 1 do
    begin
      Combined[Offset] := Tcp4[I];
      Inc(Offset);
    end;
  end;
  if Length(Tcp6) > 0 then
  begin
    for I := 0 to Length(Tcp6) - 1 do
    begin
      Combined[Offset] := Tcp6[I];
      Inc(Offset);
    end;
  end;
  if Length(Udp4) > 0 then
  begin
    for I := 0 to Length(Udp4) - 1 do
    begin
      Combined[Offset] := Udp4[I];
      Inc(Offset);
    end;
  end;
  if Length(Udp6) > 0 then
  begin
    for I := 0 to Length(Udp6) - 1 do
    begin
      Combined[Offset] := Udp6[I];
      Inc(Offset);
    end;
  end;

  // Store under lock
  FLock.Enter;
  try
    FConnections := Combined;
  finally
    FLock.Leave;
  end;
end;

function TNetworkMonitor.GetSnapshot: TNetworkConnectionArray;
begin
  FLock.Enter;
  try
    Result := Copy(FConnections);
  finally
    FLock.Leave;
  end;
end;

function TNetworkMonitor.GetConnectionsByPID(
  APID: DWORD): TNetworkConnectionArray;
var
  Snapshot: TNetworkConnectionArray;
  I: Integer;
  LList: TList<TNetworkConnection>;
begin
  Snapshot := GetSnapshot;
  LList := TList<TNetworkConnection>.Create;
  try
    for I := 0 to Length(Snapshot) - 1 do
      if Snapshot[I].ProcessId = APID then
        LList.Add(Snapshot[I]);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TNetworkMonitor.GetConnectionsByPath(
  const APath: string): TNetworkConnectionArray;
var
  Snapshot: TNetworkConnectionArray;
  I: Integer;
  LList: TList<TNetworkConnection>;
begin
  Snapshot := GetSnapshot;
  LList := TList<TNetworkConnection>.Create;
  try
    for I := 0 to Length(Snapshot) - 1 do
      if SameText(Snapshot[I].ProcessPath, APath) then
        LList.Add(Snapshot[I]);
    Result := LList.ToArray;
  finally
    LList.Free;
  end;
end;

function TNetworkMonitor.GetTotalConnectionCount: Integer;
begin
  FLock.Enter;
  try
    Result := Length(FConnections);
  finally
    FLock.Leave;
  end;
end;

end.
