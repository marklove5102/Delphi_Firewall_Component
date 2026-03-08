unit FW.Database;

{******************************************************************************
  FW.Database - SQLite3 Rule Persistence

  Provides zero-dependency SQLite3 database access for persisting firewall
  rules. Dynamically loads sqlite3.dll at runtime via LoadLibrary so there
  is no compile-time dependency on FireDAC or any third-party library.

  The database stores all rule fields in a single table (fw_rules) and
  supports full CRUD operations. WAL journal mode is enabled for optimal
  concurrent read performance.

  IMPORTANT: This unit requires sqlite3.dll to be present either in the
  application directory or in the system PATH. The 64-bit DLL is required
  for 64-bit applications.

  Thread safety: All database operations should be called from the main
  thread only. The TFirewall component ensures this by performing all
  rule management on the main VCL thread.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.IOUtils,
  FW.Types;

type
  // Opaque SQLite3 handles
  TSQLite3Handle = type Pointer;
  TSQLite3Stmt = type Pointer;

  TFirewallDatabase = class
  private
    FDLLHandle: THandle;
    FDBHandle: TSQLite3Handle;
    FDatabasePath: string;
    FIsOpen: Boolean;

    // Dynamically loaded SQLite3 function pointers
    Fsqlite3_open: function(const filename: PAnsiChar;
      var db: TSQLite3Handle): Integer; cdecl;
    Fsqlite3_close: function(db: TSQLite3Handle): Integer; cdecl;
    Fsqlite3_exec: function(db: TSQLite3Handle; const sql: PAnsiChar;
      callback: Pointer; cbArg: Pointer;
      var errmsg: PAnsiChar): Integer; cdecl;
    Fsqlite3_prepare_v2: function(db: TSQLite3Handle; const sql: PAnsiChar;
      nByte: Integer; var stmt: TSQLite3Stmt;
      var tail: PAnsiChar): Integer; cdecl;
    Fsqlite3_step: function(stmt: TSQLite3Stmt): Integer; cdecl;
    Fsqlite3_finalize: function(stmt: TSQLite3Stmt): Integer; cdecl;
    Fsqlite3_reset: function(stmt: TSQLite3Stmt): Integer; cdecl;
    Fsqlite3_bind_text: function(stmt: TSQLite3Stmt; index: Integer;
      const value: PAnsiChar; nBytes: Integer;
      destructor_: Pointer): Integer; cdecl;
    Fsqlite3_bind_int: function(stmt: TSQLite3Stmt; index: Integer;
      value: Integer): Integer; cdecl;
    Fsqlite3_column_text: function(stmt: TSQLite3Stmt;
      col: Integer): PAnsiChar; cdecl;
    Fsqlite3_column_int: function(stmt: TSQLite3Stmt;
      col: Integer): Integer; cdecl;
    Fsqlite3_column_count: function(stmt: TSQLite3Stmt): Integer; cdecl;
    Fsqlite3_errmsg: function(db: TSQLite3Handle): PAnsiChar; cdecl;
    Fsqlite3_free: procedure(ptr: Pointer); cdecl;

    procedure LoadDLL;
    procedure UnloadDLL;
    procedure EnsureOpen;
    procedure CheckResult(AResult: Integer; const AContext: string);
    procedure ExecSQL(const ASQL: UTF8String);
    procedure EnsureTableExists;
    procedure BindRuleToStmt(AStmt: TSQLite3Stmt;
      const ARule: TFirewallRuleData);
    function ReadRuleFromStmt(AStmt: TSQLite3Stmt): TFirewallRuleData;
    function GetColText(AStmt: TSQLite3Stmt; ACol: Integer): string;
    function GetColInt(AStmt: TSQLite3Stmt; ACol: Integer): Integer;
  public
    constructor Create(const ADatabasePath: string);
    destructor Destroy; override;

    procedure Open;
    procedure Close;

    // CRUD operations
    procedure InsertRule(const ARule: TFirewallRuleData);
    procedure UpdateRule(const ARule: TFirewallRuleData);
    procedure DeleteRule(const ARuleID: TGUID);
    procedure DeleteAllRules;
    function LoadAllRules: TArray<TFirewallRuleData>;
    function RuleExists(const ARuleID: TGUID): Boolean;

    property IsOpen: Boolean read FIsOpen;
    property DatabasePath: string read FDatabasePath;
  end;

const
  SQLITE_OK         = 0;
  SQLITE_ERROR      = 1;
  SQLITE_ROW        = 100;
  SQLITE_DONE       = 101;
  SQLITE_TRANSIENT  = Pointer(-1);

implementation

const
  SQLITE3_DLL = 'sqlite3.dll';

  SQL_CREATE_TABLE =
    'CREATE TABLE IF NOT EXISTS fw_rules (' +
    '  rule_id TEXT PRIMARY KEY,' +
    '  name TEXT NOT NULL,' +
    '  description TEXT DEFAULT '''',' +
    '  application_path TEXT DEFAULT '''',' +
    '  direction TEXT DEFAULT ''both'',' +
    '  action TEXT DEFAULT ''block'',' +
    '  protocol TEXT DEFAULT ''any'',' +
    '  ip_version TEXT DEFAULT ''both'',' +
    '  local_address TEXT DEFAULT '''',' +
    '  remote_address TEXT DEFAULT '''',' +
    '  local_port INTEGER DEFAULT 0,' +
    '  remote_port INTEGER DEFAULT 0,' +
    '  local_port_range_end INTEGER DEFAULT 0,' +
    '  remote_port_range_end INTEGER DEFAULT 0,' +
    '  weight INTEGER DEFAULT 4,' +
    '  enabled INTEGER DEFAULT 1,' +
    '  created_at TEXT DEFAULT (datetime(''now'')),' +
    '  updated_at TEXT DEFAULT (datetime(''now''))' +
    ');';

  SQL_INSERT_RULE =
    'INSERT OR REPLACE INTO fw_rules (' +
    '  rule_id, name, description, application_path, direction, action,' +
    '  protocol, ip_version, local_address, remote_address,' +
    '  local_port, remote_port, local_port_range_end, remote_port_range_end,' +
    '  weight, enabled, updated_at' +
    ') VALUES (' +
    '  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,' +
    '  ?11, ?12, ?13, ?14, ?15, ?16, datetime(''now'')' +
    ');';

  SQL_UPDATE_RULE =
    'UPDATE fw_rules SET' +
    '  name = ?2, description = ?3, application_path = ?4,' +
    '  direction = ?5, action = ?6, protocol = ?7, ip_version = ?8,' +
    '  local_address = ?9, remote_address = ?10,' +
    '  local_port = ?11, remote_port = ?12,' +
    '  local_port_range_end = ?13, remote_port_range_end = ?14,' +
    '  weight = ?15, enabled = ?16, updated_at = datetime(''now'')' +
    ' WHERE rule_id = ?1;';

  SQL_DELETE_RULE =
    'DELETE FROM fw_rules WHERE rule_id = ?1;';

  SQL_DELETE_ALL =
    'DELETE FROM fw_rules;';

  SQL_SELECT_ALL =
    'SELECT rule_id, name, description, application_path, direction, action,' +
    '  protocol, ip_version, local_address, remote_address,' +
    '  local_port, remote_port, local_port_range_end, remote_port_range_end,' +
    '  weight, enabled' +
    ' FROM fw_rules ORDER BY weight DESC, name ASC;';

  SQL_EXISTS_RULE =
    'SELECT COUNT(*) FROM fw_rules WHERE rule_id = ?1;';

{ TFirewallDatabase }

constructor TFirewallDatabase.Create(const ADatabasePath: string);
begin
  inherited Create;
  FDatabasePath := ADatabasePath;
  FDLLHandle := 0;
  FDBHandle := nil;
  FIsOpen := False;
end;

destructor TFirewallDatabase.Destroy;
begin
  if FIsOpen then
    Close;
  UnloadDLL;
  inherited Destroy;
end;

procedure TFirewallDatabase.LoadDLL;
var
  DLLPath: string;
begin
  if FDLLHandle <> 0 then
    Exit;

  // Try application directory first
  DLLPath := TPath.Combine(ExtractFilePath(ParamStr(0)), SQLITE3_DLL);
  if FileExists(DLLPath) then
    FDLLHandle := LoadLibrary(PChar(DLLPath));

  // Fall back to system PATH
  if FDLLHandle = 0 then
    FDLLHandle := LoadLibrary(PChar(SQLITE3_DLL));

  if FDLLHandle = 0 then
    raise EFirewallError.Create(
      'sqlite3.dll not found. Place it next to the application executable ' +
      'or in the system PATH. For 64-bit applications, use the 64-bit DLL.');

  // Load function pointers
  @Fsqlite3_open := GetProcAddress(FDLLHandle, 'sqlite3_open');
  @Fsqlite3_close := GetProcAddress(FDLLHandle, 'sqlite3_close');
  @Fsqlite3_exec := GetProcAddress(FDLLHandle, 'sqlite3_exec');
  @Fsqlite3_prepare_v2 := GetProcAddress(FDLLHandle, 'sqlite3_prepare_v2');
  @Fsqlite3_step := GetProcAddress(FDLLHandle, 'sqlite3_step');
  @Fsqlite3_finalize := GetProcAddress(FDLLHandle, 'sqlite3_finalize');
  @Fsqlite3_reset := GetProcAddress(FDLLHandle, 'sqlite3_reset');
  @Fsqlite3_bind_text := GetProcAddress(FDLLHandle, 'sqlite3_bind_text');
  @Fsqlite3_bind_int := GetProcAddress(FDLLHandle, 'sqlite3_bind_int');
  @Fsqlite3_column_text := GetProcAddress(FDLLHandle, 'sqlite3_column_text');
  @Fsqlite3_column_int := GetProcAddress(FDLLHandle, 'sqlite3_column_int');
  @Fsqlite3_column_count := GetProcAddress(FDLLHandle, 'sqlite3_column_count');
  @Fsqlite3_errmsg := GetProcAddress(FDLLHandle, 'sqlite3_errmsg');
  @Fsqlite3_free := GetProcAddress(FDLLHandle, 'sqlite3_free');

  // Validate critical functions
  if not Assigned(@Fsqlite3_open) or not Assigned(@Fsqlite3_close) or
     not Assigned(@Fsqlite3_exec) or not Assigned(@Fsqlite3_prepare_v2) or
     not Assigned(@Fsqlite3_step) or not Assigned(@Fsqlite3_finalize) then
  begin
    FreeLibrary(FDLLHandle);
    FDLLHandle := 0;
    raise EFirewallError.Create(
      'sqlite3.dll is invalid or incompatible. Required functions not found.');
  end;
end;

procedure TFirewallDatabase.UnloadDLL;
begin
  if FDLLHandle <> 0 then
  begin
    FreeLibrary(FDLLHandle);
    FDLLHandle := 0;
  end;
end;

procedure TFirewallDatabase.EnsureOpen;
begin
  if not FIsOpen then
    raise EFirewallError.Create('Firewall database is not open');
end;

procedure TFirewallDatabase.CheckResult(AResult: Integer;
  const AContext: string);
var
  ErrMsg: string;
begin
  if AResult <> SQLITE_OK then
  begin
    ErrMsg := '';
    if Assigned(FDBHandle) and Assigned(@Fsqlite3_errmsg) then
      ErrMsg := string(UTF8String(Fsqlite3_errmsg(FDBHandle)));
    raise EFirewallError.CreateFmt('SQLite error in %s (code %d): %s',
      [AContext, AResult, ErrMsg]);
  end;
end;

procedure TFirewallDatabase.ExecSQL(const ASQL: UTF8String);
var
  ErrMsg: PAnsiChar;
  Res: Integer;
begin
  EnsureOpen;
  ErrMsg := nil;
  Res := Fsqlite3_exec(FDBHandle, PAnsiChar(ASQL), nil, nil, ErrMsg);
  if Res <> SQLITE_OK then
  begin
    try
      if ErrMsg <> nil then
        raise EFirewallError.CreateFmt('SQLite exec error (code %d): %s',
          [Res, string(UTF8String(ErrMsg))])
      else
        raise EFirewallError.CreateFmt('SQLite exec error (code %d)', [Res]);
    finally
      if Assigned(@Fsqlite3_free) and (ErrMsg <> nil) then
        Fsqlite3_free(ErrMsg);
    end;
  end;
end;

procedure TFirewallDatabase.Open;
var
  DBDir: string;
  Res: Integer;
  PathUTF8: UTF8String;
begin
  if FIsOpen then
    Exit;

  LoadDLL;

  // Ensure directory exists
  DBDir := ExtractFilePath(FDatabasePath);
  if (DBDir <> '') and not DirectoryExists(DBDir) then
    ForceDirectories(DBDir);

  // Open the database
  PathUTF8 := UTF8Encode(FDatabasePath);
  Res := Fsqlite3_open(PAnsiChar(PathUTF8), FDBHandle);
  if Res <> SQLITE_OK then
  begin
    FDBHandle := nil;
    raise EFirewallError.CreateFmt(
      'Failed to open firewall database at "%s" (code %d)',
      [FDatabasePath, Res]);
  end;

  FIsOpen := True;

  // Enable WAL mode for better performance
  ExecSQL(UTF8Encode('PRAGMA journal_mode=WAL;'));

  // Enable foreign keys
  ExecSQL(UTF8Encode('PRAGMA foreign_keys=ON;'));

  // Create table if it does not exist
  EnsureTableExists;
end;

procedure TFirewallDatabase.Close;
begin
  if not FIsOpen then
    Exit;

  if Assigned(FDBHandle) and Assigned(@Fsqlite3_close) then
    Fsqlite3_close(FDBHandle);

  FDBHandle := nil;
  FIsOpen := False;
end;

procedure TFirewallDatabase.EnsureTableExists;
begin
  ExecSQL(UTF8Encode(SQL_CREATE_TABLE));
end;

// ---------------------------------------------------------------------------
// Parameter binding and column reading helpers
// ---------------------------------------------------------------------------

procedure TFirewallDatabase.BindRuleToStmt(AStmt: TSQLite3Stmt;
  const ARule: TFirewallRuleData);

  procedure BindText(AIndex: Integer; const AValue: string);
  var
    U: UTF8String;
  begin
    U := UTF8Encode(AValue);
    Fsqlite3_bind_text(AStmt, AIndex, PAnsiChar(U), Length(U), SQLITE_TRANSIENT);
  end;

  procedure BindInt(AIndex, AValue: Integer);
  begin
    Fsqlite3_bind_int(AStmt, AIndex, AValue);
  end;

begin
  BindText(1, GUIDToString(ARule.RuleID));
  BindText(2, ARule.Name);
  BindText(3, ARule.Description);
  BindText(4, ARule.ApplicationPath);
  BindText(5, DirectionToStr(ARule.Direction));
  BindText(6, ActionToStr(ARule.Action));
  BindText(7, ProtocolToStr(ARule.Protocol));
  BindText(8, IPVersionToStr(ARule.IPVersion));
  BindText(9, ARule.LocalAddress);
  BindText(10, ARule.RemoteAddress);
  BindInt(11, ARule.LocalPort);
  BindInt(12, ARule.RemotePort);
  BindInt(13, ARule.LocalPortRangeEnd);
  BindInt(14, ARule.RemotePortRangeEnd);
  BindInt(15, ARule.Weight);
  BindInt(16, Ord(ARule.Enabled));
end;

function TFirewallDatabase.GetColText(AStmt: TSQLite3Stmt;
  ACol: Integer): string;
var
  P: PAnsiChar;
begin
  P := Fsqlite3_column_text(AStmt, ACol);
  if P <> nil then
    Result := string(UTF8String(P))
  else
    Result := '';
end;

function TFirewallDatabase.GetColInt(AStmt: TSQLite3Stmt;
  ACol: Integer): Integer;
begin
  Result := Fsqlite3_column_int(AStmt, ACol);
end;

function TFirewallDatabase.ReadRuleFromStmt(
  AStmt: TSQLite3Stmt): TFirewallRuleData;
var
  GuidStr: string;
begin
  Result := Default(TFirewallRuleData);

  GuidStr := GetColText(AStmt, 0);
  if GuidStr <> '' then
    Result.RuleID := StringToGUID(GuidStr)
  else
    Result.RuleID := TGUID.NewGuid;

  Result.Name              := GetColText(AStmt, 1);
  Result.Description       := GetColText(AStmt, 2);
  Result.ApplicationPath   := GetColText(AStmt, 3);
  Result.Direction         := StrToDirection(GetColText(AStmt, 4));
  Result.Action            := StrToAction(GetColText(AStmt, 5));
  Result.Protocol          := StrToProtocol(GetColText(AStmt, 6));
  Result.IPVersion         := StrToIPVersion(GetColText(AStmt, 7));
  Result.LocalAddress      := GetColText(AStmt, 8);
  Result.RemoteAddress     := GetColText(AStmt, 9);
  Result.LocalPort         := Word(GetColInt(AStmt, 10));
  Result.RemotePort        := Word(GetColInt(AStmt, 11));
  Result.LocalPortRangeEnd := Word(GetColInt(AStmt, 12));
  Result.RemotePortRangeEnd := Word(GetColInt(AStmt, 13));
  Result.Weight            := Byte(GetColInt(AStmt, 14));
  Result.Enabled           := GetColInt(AStmt, 15) <> 0;
end;

// ---------------------------------------------------------------------------
// CRUD Operations
// ---------------------------------------------------------------------------

procedure TFirewallDatabase.InsertRule(const ARule: TFirewallRuleData);
var
  Stmt: TSQLite3Stmt;
  Tail: PAnsiChar;
  SQL: UTF8String;
  Res: Integer;
begin
  EnsureOpen;
  Stmt := nil;
  SQL := UTF8Encode(SQL_INSERT_RULE);
  Res := Fsqlite3_prepare_v2(FDBHandle, PAnsiChar(SQL), -1, Stmt, Tail);
  CheckResult(Res, 'InsertRule.prepare');
  try
    BindRuleToStmt(Stmt, ARule);
    Res := Fsqlite3_step(Stmt);
    if (Res <> SQLITE_DONE) and (Res <> SQLITE_ROW) then
      CheckResult(Res, 'InsertRule.step');
  finally
    Fsqlite3_finalize(Stmt);
  end;
end;

procedure TFirewallDatabase.UpdateRule(const ARule: TFirewallRuleData);
var
  Stmt: TSQLite3Stmt;
  Tail: PAnsiChar;
  SQL: UTF8String;
  Res: Integer;
begin
  EnsureOpen;
  Stmt := nil;
  SQL := UTF8Encode(SQL_UPDATE_RULE);
  Res := Fsqlite3_prepare_v2(FDBHandle, PAnsiChar(SQL), -1, Stmt, Tail);
  CheckResult(Res, 'UpdateRule.prepare');
  try
    BindRuleToStmt(Stmt, ARule);
    Res := Fsqlite3_step(Stmt);
    if (Res <> SQLITE_DONE) and (Res <> SQLITE_ROW) then
      CheckResult(Res, 'UpdateRule.step');
  finally
    Fsqlite3_finalize(Stmt);
  end;
end;

procedure TFirewallDatabase.DeleteRule(const ARuleID: TGUID);
var
  Stmt: TSQLite3Stmt;
  Tail: PAnsiChar;
  SQL, GuidUTF8: UTF8String;
  Res: Integer;
begin
  EnsureOpen;
  Stmt := nil;
  SQL := UTF8Encode(SQL_DELETE_RULE);
  Res := Fsqlite3_prepare_v2(FDBHandle, PAnsiChar(SQL), -1, Stmt, Tail);
  CheckResult(Res, 'DeleteRule.prepare');
  try
    GuidUTF8 := UTF8Encode(GUIDToString(ARuleID));
    Fsqlite3_bind_text(Stmt, 1, PAnsiChar(GuidUTF8), Length(GuidUTF8),
      SQLITE_TRANSIENT);
    Res := Fsqlite3_step(Stmt);
    if (Res <> SQLITE_DONE) and (Res <> SQLITE_ROW) then
      CheckResult(Res, 'DeleteRule.step');
  finally
    Fsqlite3_finalize(Stmt);
  end;
end;

procedure TFirewallDatabase.DeleteAllRules;
begin
  EnsureOpen;
  ExecSQL(UTF8Encode(SQL_DELETE_ALL));
end;

function TFirewallDatabase.LoadAllRules: TArray<TFirewallRuleData>;
var
  Stmt: TSQLite3Stmt;
  Tail: PAnsiChar;
  SQL: UTF8String;
  Res: Integer;
  List: TArray<TFirewallRuleData>;
  Count: Integer;
begin
  EnsureOpen;
  Result := nil;
  Stmt := nil;
  SQL := UTF8Encode(SQL_SELECT_ALL);
  Res := Fsqlite3_prepare_v2(FDBHandle, PAnsiChar(SQL), -1, Stmt, Tail);
  CheckResult(Res, 'LoadAllRules.prepare');
  try
    Count := 0;
    SetLength(List, 64); // Pre-allocate
    while Fsqlite3_step(Stmt) = SQLITE_ROW do
    begin
      if Count >= Length(List) then
        SetLength(List, Length(List) * 2);
      List[Count] := ReadRuleFromStmt(Stmt);
      Inc(Count);
    end;
    SetLength(List, Count);
    Result := List;
  finally
    Fsqlite3_finalize(Stmt);
  end;
end;

function TFirewallDatabase.RuleExists(const ARuleID: TGUID): Boolean;
var
  Stmt: TSQLite3Stmt;
  Tail: PAnsiChar;
  SQL, GuidUTF8: UTF8String;
  Res: Integer;
begin
  EnsureOpen;
  Result := False;
  Stmt := nil;
  SQL := UTF8Encode(SQL_EXISTS_RULE);
  Res := Fsqlite3_prepare_v2(FDBHandle, PAnsiChar(SQL), -1, Stmt, Tail);
  CheckResult(Res, 'RuleExists.prepare');
  try
    GuidUTF8 := UTF8Encode(GUIDToString(ARuleID));
    Fsqlite3_bind_text(Stmt, 1, PAnsiChar(GuidUTF8), Length(GuidUTF8),
      SQLITE_TRANSIENT);
    if Fsqlite3_step(Stmt) = SQLITE_ROW then
      Result := Fsqlite3_column_int(Stmt, 0) > 0;
  finally
    Fsqlite3_finalize(Stmt);
  end;
end;

end.
