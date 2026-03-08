unit FW.WorkerThread;

{******************************************************************************
  FW.WorkerThread - Firewall Worker Thread

  Central orchestrating thread that owns all WFP operations. Processes a
  command queue posted from the main thread and periodically polls the
  network monitor. All VCL events are marshaled to the main thread via
  TThread.Queue.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes,
  System.SyncObjs, System.Generics.Collections,
  FW.WFP.API, FW.Types, FW.Rules, FW.Engine, FW.Monitor,
  FW.EventSubscriber;

type
  // Command types for the worker thread queue
  TWorkerCommandType = (
    wcStartEngine,
    wcStopEngine,
    wcInstallRule,
    wcUninstallRule,
    wcUpdateRule,
    wcInstallAllRules,
    wcUninstallAllRules,
    wcRefreshMonitor,
    wcSubscribeEvents,
    wcUnsubscribeEvents,
    wcInstallDefaultBlock,
    wcShutdown
  );

  PWorkerCommand = ^TWorkerCommand;
  TWorkerCommand = record
    CommandType: TWorkerCommandType;
    Rule: TFirewallRule;
    CompletionEvent: TEvent;
    ResultCode: DWORD;
  end;

  TFirewallWorkerThread = class(TThread)
  private
    FEngine: TWFPEngine;
    FMonitor: TNetworkMonitor;
    FEventSubscriber: TWFPEventSubscriber;
    FCommandQueue: TThreadList<PWorkerCommand>;
    FCommandAvailable: TEvent;
    FRules: TFirewallRuleList;
    FMonitorInterval: Cardinal;
    FLastMonitorTick: UInt64;
    FDefaultBlockFilterIds: TList<UINT64>;
    FEngineRunning: Boolean;

    // Callbacks to fire on main thread
    FOnConnectionBlocked: TFirewallConnectionBlockedEvent;
    FOnConnectionAllowed: TFirewallConnectionAllowedEvent;
    FOnNewAppDetected: TFirewallNewAppDetectedEvent;
    FOnNetworkActivity: TFirewallNetworkActivityEvent;
    FOnError: TFirewallErrorEvent;
    FOnEngineStateChanged: TFirewallEngineStateEvent;
    FOnLog: TFirewallLogEvent;

    procedure ProcessCommand(ACmd: PWorkerCommand);
    procedure ProcessPendingCommands;

    procedure DoStartEngine(ACmd: PWorkerCommand);
    procedure DoStopEngine(ACmd: PWorkerCommand);
    procedure DoInstallRule(ACmd: PWorkerCommand);
    procedure DoUninstallRule(ACmd: PWorkerCommand);
    procedure DoInstallAllRules(ACmd: PWorkerCommand);
    procedure DoUninstallAllRules(ACmd: PWorkerCommand);
    procedure DoSubscribeEvents(ACmd: PWorkerCommand);
    procedure DoUnsubscribeEvents(ACmd: PWorkerCommand);
    procedure DoInstallDefaultBlock(ACmd: PWorkerCommand);
    procedure DoRefreshMonitor;

    // Called from WFP event subscriber (on WFP system thread)
    procedure HandleWFPEvent(const AEvent: TFirewallEvent);
    procedure HandleNewApp(const AEvent: TFirewallEvent);
    function IsOurFilterId(AFilterId: UINT64): Boolean;
    function HasAllowRuleForApp(const AAppPath: string;
      ADirection: TFirewallDirection): Boolean;

    // Marshal events to main VCL thread
    procedure FireBlockedOnMainThread(const AEvent: TFirewallEvent);
    procedure FireAllowedOnMainThread(const AEvent: TFirewallEvent);
    procedure FireNewAppOnMainThread(const AEvent: TFirewallEvent);
    procedure FireNetworkActivityOnMainThread(
      const AConns: TNetworkConnectionArray);
    procedure FireErrorOnMainThread(ACode: DWORD; const AMsg: string);
    procedure FireEngineStateOnMainThread(AActive: Boolean);
    procedure FireLogOnMainThread(const AEvent: TFirewallEvent);
  protected
    procedure Execute; override;
  public
    constructor Create(AEngine: TWFPEngine; ARules: TFirewallRuleList;
      AMonitor: TNetworkMonitor; ASubscriber: TWFPEventSubscriber);
    destructor Destroy; override;

    // Thread-safe command posting
    procedure PostCommand(AType: TWorkerCommandType;
      ARule: TFirewallRule = nil);
    function PostCommandSync(AType: TWorkerCommandType;
      ARule: TFirewallRule = nil;
      ATimeoutMs: Cardinal = 10000): DWORD;

    property MonitorInterval: Cardinal read FMonitorInterval
      write FMonitorInterval;

    // Event wiring (set by TFirewall before starting thread)
    property OnConnectionBlocked: TFirewallConnectionBlockedEvent
      write FOnConnectionBlocked;
    property OnConnectionAllowed: TFirewallConnectionAllowedEvent
      write FOnConnectionAllowed;
    property OnNewAppDetected: TFirewallNewAppDetectedEvent
      write FOnNewAppDetected;
    property OnNetworkActivity: TFirewallNetworkActivityEvent
      write FOnNetworkActivity;
    property OnError: TFirewallErrorEvent write FOnError;
    property OnEngineStateChanged: TFirewallEngineStateEvent
      write FOnEngineStateChanged;
    property OnLog: TFirewallLogEvent write FOnLog;
  end;

implementation

uses
  System.Math;

{ TFirewallWorkerThread }

constructor TFirewallWorkerThread.Create(AEngine: TWFPEngine;
  ARules: TFirewallRuleList; AMonitor: TNetworkMonitor;
  ASubscriber: TWFPEventSubscriber);
begin
  inherited Create(True); // Create suspended
  FreeOnTerminate := False;
  FEngine := AEngine;
  FRules := ARules;
  FMonitor := AMonitor;
  FEventSubscriber := ASubscriber;
  FCommandQueue := TThreadList<PWorkerCommand>.Create;
  FCommandAvailable := TEvent.Create(nil, False, False, '');
  FDefaultBlockFilterIds := TList<UINT64>.Create;
  FMonitorInterval := 2000;
  FLastMonitorTick := 0;
  FEngineRunning := False;
end;

destructor TFirewallWorkerThread.Destroy;
var
  LList: TList<PWorkerCommand>;
  Cmd: PWorkerCommand;
begin
  // Clean up any remaining commands
  LList := FCommandQueue.LockList;
  try
    for Cmd in LList do
    begin
      if Assigned(Cmd.CompletionEvent) then
      begin
        Cmd.ResultCode := ERROR_CANCELLED;
        Cmd.CompletionEvent.SetEvent;
      end;
      Dispose(Cmd);
    end;
    LList.Clear;
  finally
    FCommandQueue.UnlockList;
  end;

  FDefaultBlockFilterIds.Free;
  FCommandAvailable.Free;
  FCommandQueue.Free;
  inherited Destroy;
end;

procedure TFirewallWorkerThread.Execute;
var
  TickNow: UInt64;
begin
  while not Terminated do
  begin
    // Wait for commands or timeout for monitor refresh
    FCommandAvailable.WaitFor(Min(FMonitorInterval, 500));

    if Terminated then
      Break;

    // Process all pending commands
    ProcessPendingCommands;

    // Periodic network monitor refresh
    if FEngineRunning then
    begin
      TickNow := GetTickCount64;
      if (TickNow - FLastMonitorTick) >= FMonitorInterval then
      begin
        DoRefreshMonitor;
        FLastMonitorTick := TickNow;
      end;
    end;
  end;
end;

procedure TFirewallWorkerThread.ProcessPendingCommands;
var
  LList: TList<PWorkerCommand>;
  Commands: TArray<PWorkerCommand>;
  Cmd: PWorkerCommand;
  I: Integer;
begin
  // Grab all pending commands at once
  LList := FCommandQueue.LockList;
  try
    if LList.Count = 0 then
      Exit;
    Commands := LList.ToArray;
    LList.Clear;
  finally
    FCommandQueue.UnlockList;
  end;

  // Process each command
  for I := 0 to Length(Commands) - 1 do
  begin
    Cmd := Commands[I];
    try
      ProcessCommand(Cmd);
    except
      on E: EFirewallWFPError do
      begin
        Cmd.ResultCode := E.ErrorCode;
        FireErrorOnMainThread(E.ErrorCode, E.Message);
      end;
      on E: Exception do
      begin
        Cmd.ResultCode := ERROR_GEN_FAILURE;
        FireErrorOnMainThread(ERROR_GEN_FAILURE, E.Message);
      end;
    end;

    // Signal completion if synchronous
    if Assigned(Cmd.CompletionEvent) then
      Cmd.CompletionEvent.SetEvent
    else
      Dispose(Cmd);
  end;
end;

procedure TFirewallWorkerThread.ProcessCommand(ACmd: PWorkerCommand);
begin
  case ACmd.CommandType of
    wcStartEngine:       DoStartEngine(ACmd);
    wcStopEngine:        DoStopEngine(ACmd);
    wcInstallRule:       DoInstallRule(ACmd);
    wcUninstallRule:     DoUninstallRule(ACmd);
    wcInstallAllRules:   DoInstallAllRules(ACmd);
    wcUninstallAllRules: DoUninstallAllRules(ACmd);
    wcSubscribeEvents:   DoSubscribeEvents(ACmd);
    wcUnsubscribeEvents: DoUnsubscribeEvents(ACmd);
    wcInstallDefaultBlock: DoInstallDefaultBlock(ACmd);
    wcShutdown:          Terminate;
  end;
end;

procedure TFirewallWorkerThread.DoStartEngine(ACmd: PWorkerCommand);
begin
  if FEngineRunning then
    Exit;

  FEngine.Open(FEngine.IsOpen);
  FEngine.InstallProvider;
  FEngine.InstallSublayer;
  FEngine.EnableNetEventCollection;

  FEngineRunning := True;
  FLastMonitorTick := GetTickCount64;

  ACmd.ResultCode := ERROR_SUCCESS;
  FireEngineStateOnMainThread(True);
end;

procedure TFirewallWorkerThread.DoStopEngine(ACmd: PWorkerCommand);
var
  I: Integer;
begin
  if not FEngineRunning then
    Exit;

  // Unsubscribe events first
  if FEventSubscriber.Active then
    FEventSubscriber.Unsubscribe(FEngine.EngineHandle);

  // Remove default block filters
  for I := 0 to FDefaultBlockFilterIds.Count - 1 do
    FEngine.UninstallFilterById(FDefaultBlockFilterIds[I]);
  FDefaultBlockFilterIds.Clear;

  // Uninstall all rules
  for I := 0 to FRules.Count - 1 do
  begin
    if FRules[I].Installed then
      FEngine.UninstallRule(FRules[I]);
  end;

  FEngine.Close;
  FEngineRunning := False;

  ACmd.ResultCode := ERROR_SUCCESS;
  FireEngineStateOnMainThread(False);
end;

procedure TFirewallWorkerThread.DoInstallRule(ACmd: PWorkerCommand);
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  if Assigned(ACmd.Rule) and ACmd.Rule.Data.Enabled then
  begin
    FEngine.BeginTransaction;
    try
      FEngine.InstallRule(ACmd.Rule);
      FEngine.CommitTransaction;
      ACmd.ResultCode := ERROR_SUCCESS;
    except
      FEngine.AbortTransaction;
      raise;
    end;
  end;
end;

procedure TFirewallWorkerThread.DoUninstallRule(ACmd: PWorkerCommand);
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  if Assigned(ACmd.Rule) and ACmd.Rule.Installed then
  begin
    FEngine.UninstallRule(ACmd.Rule);
    ACmd.ResultCode := ERROR_SUCCESS;
  end;
end;

procedure TFirewallWorkerThread.DoInstallAllRules(ACmd: PWorkerCommand);
var
  I: Integer;
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  FEngine.BeginTransaction;
  try
    for I := 0 to FRules.Count - 1 do
    begin
      if FRules[I].Data.Enabled and (not FRules[I].Installed) then
        FEngine.InstallRule(FRules[I]);
    end;
    FEngine.CommitTransaction;
    ACmd.ResultCode := ERROR_SUCCESS;
  except
    FEngine.AbortTransaction;
    raise;
  end;
end;

procedure TFirewallWorkerThread.DoUninstallAllRules(ACmd: PWorkerCommand);
var
  I: Integer;
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  for I := 0 to FRules.Count - 1 do
  begin
    if FRules[I].Installed then
      FEngine.UninstallRule(FRules[I]);
  end;

  ACmd.ResultCode := ERROR_SUCCESS;
end;

procedure TFirewallWorkerThread.DoSubscribeEvents(ACmd: PWorkerCommand);
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  if FEventSubscriber.Active then
    Exit;

  // Wire up event handlers
  FEventSubscriber.OnEventReceived :=
    procedure(const AEvent: TFirewallEvent)
    begin
      HandleWFPEvent(AEvent);
    end;

  FEventSubscriber.OnNewAppDetected :=
    procedure(const AEvent: TFirewallEvent)
    begin
      HandleNewApp(AEvent);
    end;

  FEventSubscriber.Subscribe(FEngine.EngineHandle);
  ACmd.ResultCode := ERROR_SUCCESS;
end;

procedure TFirewallWorkerThread.DoUnsubscribeEvents(ACmd: PWorkerCommand);
begin
  if FEventSubscriber.Active and FEngineRunning then
    FEventSubscriber.Unsubscribe(FEngine.EngineHandle);
  ACmd.ResultCode := ERROR_SUCCESS;
end;

procedure TFirewallWorkerThread.DoInstallDefaultBlock(ACmd: PWorkerCommand);
var
  FilterIds: TArray<UINT64>;
begin
  if not FEngineRunning then
  begin
    ACmd.ResultCode := ERROR_NOT_READY;
    Exit;
  end;

  if FDefaultBlockFilterIds.Count > 0 then
  begin
    ACmd.ResultCode := ERROR_SUCCESS;
    Exit;
  end;

  FEngine.BeginTransaction;
  try
    FilterIds := FEngine.InstallDefaultBlockAll;
    FDefaultBlockFilterIds.AddRange(FilterIds);
    FEngine.CommitTransaction;
    ACmd.ResultCode := ERROR_SUCCESS;
  except
    FEngine.AbortTransaction;
    raise;
  end;
end;

procedure TFirewallWorkerThread.DoRefreshMonitor;
var
  Conns: TNetworkConnectionArray;
begin
  try
    FMonitor.Refresh;
    if Assigned(FOnNetworkActivity) then
    begin
      Conns := FMonitor.GetSnapshot;
      FireNetworkActivityOnMainThread(Conns);
    end;
  except
    on E: Exception do
      FireErrorOnMainThread(ERROR_GEN_FAILURE,
        'Network monitor refresh failed: ' + E.Message);
  end;
end;

function TFirewallWorkerThread.IsOurFilterId(AFilterId: UINT64): Boolean;
var
  I, J: Integer;
begin
  // Check default block filters
  for I := 0 to FDefaultBlockFilterIds.Count - 1 do
    if FDefaultBlockFilterIds[I] = AFilterId then
      Exit(True);

  // Check per-rule filters
  for I := 0 to FRules.Count - 1 do
    for J := 0 to FRules[I].WFPFilterIds.Count - 1 do
      if FRules[I].WFPFilterIds[J] = AFilterId then
        Exit(True);

  Result := False;
end;

function TFirewallWorkerThread.HasAllowRuleForApp(const AAppPath: string;
  ADirection: TFirewallDirection): Boolean;
var
  I: Integer;
  R: TFirewallRuleData;
begin
  // Check if we have an active Allow rule that covers this app+direction
  for I := 0 to FRules.Count - 1 do
  begin
    R := FRules[I].Data;
    if R.Enabled and (R.Action = faAllow) and
       SameText(R.ApplicationPath, AAppPath) then
    begin
      // Rule covers this direction?
      if (R.Direction = fdBoth) or (R.Direction = ADirection) then
        Exit(True);
    end;
  end;
  Result := False;
end;

procedure TFirewallWorkerThread.HandleWFPEvent(const AEvent: TFirewallEvent);
begin
  // Only report events from OUR WFP filters. The WFP event subscription
  // receives ALL system-wide net events including Windows Firewall blocks.
  if (AEvent.FilterId <> 0) and (not IsOurFilterId(AEvent.FilterId)) then
    Exit;

  // Suppress BLOCKED events for apps we have explicitly allowed.
  // Events with FilterId=0 or from other providers can report blocks for
  // apps that WE allowed - those are external blocks (Windows Firewall etc.)
  // and should not appear in our log.
  if (AEvent.Action = faBlock) and
     HasAllowRuleForApp(AEvent.ApplicationPath, AEvent.Direction) then
    Exit;

  // Fire specific block/allow events
  case AEvent.Action of
    faBlock: FireBlockedOnMainThread(AEvent);
    faAllow: FireAllowedOnMainThread(AEvent);
  end;

  // Fire log event for all events
  FireLogOnMainThread(AEvent);
end;

procedure TFirewallWorkerThread.HandleNewApp(const AEvent: TFirewallEvent);
begin
  FireNewAppOnMainThread(AEvent);
end;

// ---------------------------------------------------------------------------
// Main thread marshaling - all use TThread.Queue for non-blocking delivery
// ---------------------------------------------------------------------------

procedure TFirewallWorkerThread.FireBlockedOnMainThread(
  const AEvent: TFirewallEvent);
var
  LocalEvent: TFirewallEvent;
  LocalHandler: TFirewallConnectionBlockedEvent;
begin
  if not Assigned(FOnConnectionBlocked) then Exit;
  LocalEvent := AEvent;
  LocalHandler := FOnConnectionBlocked;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalEvent);
    end);
end;

procedure TFirewallWorkerThread.FireAllowedOnMainThread(
  const AEvent: TFirewallEvent);
var
  LocalEvent: TFirewallEvent;
  LocalHandler: TFirewallConnectionAllowedEvent;
begin
  if not Assigned(FOnConnectionAllowed) then Exit;
  LocalEvent := AEvent;
  LocalHandler := FOnConnectionAllowed;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalEvent);
    end);
end;

procedure TFirewallWorkerThread.FireNewAppOnMainThread(
  const AEvent: TFirewallEvent);
var
  LocalEvent: TFirewallEvent;
  LocalHandler: TFirewallNewAppDetectedEvent;
  LocalAction: TFirewallAction;
begin
  if not Assigned(FOnNewAppDetected) then Exit;
  LocalEvent := AEvent;
  LocalHandler := FOnNewAppDetected;
  TThread.Queue(nil,
    procedure
    begin
      LocalAction := faAllow;
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalEvent.ApplicationPath, LocalEvent, LocalAction);
    end);
end;

procedure TFirewallWorkerThread.FireNetworkActivityOnMainThread(
  const AConns: TNetworkConnectionArray);
var
  LocalConns: TNetworkConnectionArray;
  LocalHandler: TFirewallNetworkActivityEvent;
begin
  if not Assigned(FOnNetworkActivity) then Exit;
  LocalConns := Copy(AConns);
  LocalHandler := FOnNetworkActivity;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalConns);
    end);
end;

procedure TFirewallWorkerThread.FireErrorOnMainThread(ACode: DWORD;
  const AMsg: string);
var
  LocalCode: DWORD;
  LocalMsg: string;
  LocalHandler: TFirewallErrorEvent;
begin
  if not Assigned(FOnError) then Exit;
  LocalCode := ACode;
  LocalMsg := AMsg;
  LocalHandler := FOnError;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalCode, LocalMsg);
    end);
end;

procedure TFirewallWorkerThread.FireEngineStateOnMainThread(AActive: Boolean);
var
  LocalActive: Boolean;
  LocalHandler: TFirewallEngineStateEvent;
begin
  if not Assigned(FOnEngineStateChanged) then Exit;
  LocalActive := AActive;
  LocalHandler := FOnEngineStateChanged;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalActive);
    end);
end;

procedure TFirewallWorkerThread.FireLogOnMainThread(
  const AEvent: TFirewallEvent);
var
  LocalEvent: TFirewallEvent;
  LocalHandler: TFirewallLogEvent;
begin
  if not Assigned(FOnLog) then Exit;
  LocalEvent := AEvent;
  LocalHandler := FOnLog;
  TThread.Queue(nil,
    procedure
    begin
      if Assigned(LocalHandler) then
        LocalHandler(nil, LocalEvent);
    end);
end;

// ---------------------------------------------------------------------------
// Public command posting
// ---------------------------------------------------------------------------

procedure TFirewallWorkerThread.PostCommand(AType: TWorkerCommandType;
  ARule: TFirewallRule);
var
  Cmd: PWorkerCommand;
begin
  New(Cmd);
  Cmd^.CommandType := AType;
  Cmd^.Rule := ARule;
  Cmd^.CompletionEvent := nil;
  Cmd^.ResultCode := ERROR_SUCCESS;

  FCommandQueue.LockList.Add(Cmd);
  FCommandQueue.UnlockList;
  FCommandAvailable.SetEvent;
end;

function TFirewallWorkerThread.PostCommandSync(AType: TWorkerCommandType;
  ARule: TFirewallRule; ATimeoutMs: Cardinal): DWORD;
var
  Cmd: TWorkerCommand;
  CompEvent: TEvent;
begin
  CompEvent := TEvent.Create(nil, True, False, '');
  try
    Cmd.CommandType := AType;
    Cmd.Rule := ARule;
    Cmd.CompletionEvent := CompEvent;
    Cmd.ResultCode := ERROR_SUCCESS;

    // Add to queue (allocate on heap for the queue)
    var PCmd: PWorkerCommand;
    New(PCmd);
    PCmd^ := Cmd;
    PCmd^.CompletionEvent := CompEvent;

    FCommandQueue.LockList.Add(PCmd);
    FCommandQueue.UnlockList;
    FCommandAvailable.SetEvent;

    // Wait for completion
    if CompEvent.WaitFor(ATimeoutMs) = wrTimeout then
    begin
      Result := ERROR_TIMEOUT;
      Exit;
    end;

    Result := PCmd^.ResultCode;
    Dispose(PCmd);
  finally
    CompEvent.Free;
  end;
end;

end.
