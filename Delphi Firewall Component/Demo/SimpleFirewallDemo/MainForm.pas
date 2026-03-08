unit MainForm;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.UITypes,
  Vcl.Forms,
  Vcl.Controls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Dialogs,
  Vcl.ComCtrls,
  Vcl.Menus,
  Vcl.Clipbrd,
  FireDAC.Comp.Client,
  FireDAC.Comp.DataSet,
  FireDAC.Stan.Param,
  FireDAC.Phys.SQLite,
  FireDAC.Phys.SQLiteDef,
  FW.Component,
  FW.Types, FireDAC.Stan.Intf, FireDAC.Stan.Option, FireDAC.Stan.Error,
  FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def, FireDAC.Stan.Pool,
  FireDAC.Stan.Async, FireDAC.Phys, FireDAC.VCLUI.Wait, FireDAC.DatS,
  FireDAC.DApt.Intf, FireDAC.DApt, FireDAC.Stan.ExprFuncs,
  FireDAC.Phys.SQLiteWrapper.Stat, Data.DB;

type
  TDetectedAppItem = class
  public
    AppPath: string;
    Publisher: string;
    Signed: Boolean;
    LastSeen: TDateTime;
    LastAction: TFirewallAction;
    Hits: Integer;
  end;

  TRuleListItem = class
  public
    RuleID: TGUID;
    AppPath: string;
    Action: TFirewallAction;
  end;

  TFormMain = class(TForm)
    pnlTop: TPanel;
    lblAdmin: TLabel;
    lblStatus: TLabel;
    btnStart: TButton;
    btnStop: TButton;
    lblPath: TLabel;
    edtAppPath: TEdit;
    btnBrowse: TButton;
    btnAllow: TButton;
    btnBlock: TButton;
    pnlDetected: TPanel;
    lblDetected: TLabel;
    lvDetected: TListView;
    splMain: TSplitter;
    pnlRules: TPanel;
    lblRules: TLabel;
    lvRules: TListView;
    memLog: TMemo;
    dlgOpenExe: TOpenDialog;
    Firewall1: TFirewall;
    FDConnection1: TFDConnection;
    FDQueryRules: TFDQuery;
    FDPhysSQLiteDriverLink1: TFDPhysSQLiteDriverLink;
    pmDetected: TPopupMenu;
    miDetAllow: TMenuItem;
    miDetBlock: TMenuItem;
    miDetCopyPath: TMenuItem;
    pmRules: TPopupMenu;
    miRuleDelete: TMenuItem;
    miRuleClear: TMenuItem;
    miRuleCopyPath: TMenuItem;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnStartClick(Sender: TObject);
    procedure btnStopClick(Sender: TObject);
    procedure btnBrowseClick(Sender: TObject);
    procedure btnAllowClick(Sender: TObject);
    procedure btnBlockClick(Sender: TObject);
    procedure FirewallNewAppDetected(Sender: TObject;
      const Event: TFirewallEvent; const FileDetails: TFirewallFileDetails);
    procedure FirewallAllow(Sender: TObject; const Event: TFirewallEvent);
    procedure FirewallBlock(Sender: TObject; const Event: TFirewallEvent);
    procedure FirewallNewRule(Sender: TObject; const Rule: TFirewallRuleInfo);
    procedure FirewallDeleteRule(Sender: TObject; const Rule: TFirewallRuleInfo);
    procedure FirewallError(Sender: TObject; ErrorCode: DWORD;
      const ErrorMessage: string);
    procedure miDetAllowClick(Sender: TObject);
    procedure miDetBlockClick(Sender: TObject);
    procedure miDetCopyPathClick(Sender: TObject);
    procedure miRuleDeleteClick(Sender: TObject);
    procedure miRuleClearClick(Sender: TObject);
    procedure miRuleCopyPathClick(Sender: TObject);
  private
    procedure Log(const AMsg: string);
    function EventText(const AEvent: TFirewallEvent): string;

    function FindDetectedItem(const APath: string): TListItem;
    procedure RefreshDetectedItemUI(AItem: TListItem; AData: TDetectedAppItem);
    procedure UpsertDetected(const AEvent: TFirewallEvent;
      const AFileDetails: TFirewallFileDetails; AHasDetails: Boolean);
    procedure ClearDetectedList;
    function SelectedDetectedPath: string;

    function FindRuleItem(const ARuleID: TGUID): TListItem;
    procedure UpsertRule(const ARuleID: TGUID; const APath: string;
      AAction: TFirewallAction);
    procedure ClearRuleList;
    function SelectedRuleData: TRuleListItem;
    function HasRuleForPathAction(const APath: string;
      AAction: TFirewallAction): Boolean;
    function NormalizePath(const APath: string): string;
    function ShouldTreatAsAllow(const APath: string): Boolean;
    function DatabaseFilePath: string;
    function ActionToDbText(AAction: TFirewallAction): string;
    function DbTextToAction(const AValue: string;
      out AAction: TFirewallAction): Boolean;
    procedure SetupDatabase;
    procedure EnsureDatabaseSchema;
    procedure LoadRulesFromDatabase;
    procedure ReloadRulesFromDatabase;
    procedure SaveRuleToDatabase(const APath: string; AAction: TFirewallAction);
    procedure DeleteRuleFromDatabase(const APath: string;
      AAction: TFirewallAction);
    procedure ClearRulesFromDatabase;

    function ResolveInputPath: string;
    function InstallRuleForPath(const APath: string;
      AAction: TFirewallAction; ASilent: Boolean = False): Boolean;
  private
    FLoadingRulesFromDB: Boolean;
    FDatabaseReady: Boolean;
  end;

var
  FormMain: TFormMain;

implementation

{$R *.dfm}

function ActionToText(A: TFirewallAction): string;
begin
  case A of
    faAllow: Result := 'ALLOW';
    faBlock: Result := 'BLOCK';
  else
    Result := 'UNKNOWN';
  end;
end;

function DirectionToText(D: TFirewallDirection): string;
begin
  case D of
    fdInbound: Result := 'IN';
    fdOutbound: Result := 'OUT';
    fdBoth: Result := 'BOTH';
  else
    Result := 'UNK';
  end;
end;

function ProtocolToText(P: TFirewallProtocol): string;
begin
  case P of
    fpTCP: Result := 'TCP';
    fpUDP: Result := 'UDP';
    fpICMP: Result := 'ICMP';
    fpAny: Result := 'ANY';
  else
    Result := 'UNK';
  end;
end;

procedure TFormMain.FormCreate(Sender: TObject);
begin
  FLoadingRulesFromDB := False;
  FDatabaseReady := False;

  // Ensure the firewall is not active while restoring persisted rules.
  Firewall1.Active := False;
  Firewall1.DynamicSession := False;
  if Firewall1.MonitorIntervalMs = 0 then
    Firewall1.MonitorIntervalMs := 200;

  try
    SetupDatabase;
    ReloadRulesFromDatabase;
  except
    on E: Exception do
    begin
      FDatabaseReady := False;
      Log('SQLite unavailable: ' + E.Message);
    end;
  end;

  lblStatus.Caption := 'Status: Stopped';
  Log('Demo ready. Left = detected apps, Right = allowed/blocked rules.');
  Log('Policy: DEFAULT BLOCK (only explicit allow rules are treated as allow).');
  Log('Run this demo as Administrator for full WFP control.');
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
  try
    Firewall1.Active := False;
  except
    // ignore shutdown errors
  end;

  ClearDetectedList;
  ClearRuleList;

  if FDConnection1.Connected then
    FDConnection1.Connected := False;
end;

procedure TFormMain.btnStartClick(Sender: TObject);
begin
  try
    ReloadRulesFromDatabase;
    Firewall1.Active := True;
    lblStatus.Caption := 'Status: Active';
    Log('Firewall monitoring started.');
  except
    on E: Exception do
    begin
      Log('Start failed: ' + E.Message);
      MessageDlg(E.Message, mtError, [mbOK], 0);
    end;
  end;
end;

procedure TFormMain.btnStopClick(Sender: TObject);
begin
  try
    Firewall1.Active := False;
    lblStatus.Caption := 'Status: Stopped';
    Log('Firewall monitoring stopped.');
  except
    on E: Exception do
    begin
      Log('Stop failed: ' + E.Message);
      MessageDlg(E.Message, mtError, [mbOK], 0);
    end;
  end;
end;

procedure TFormMain.btnBrowseClick(Sender: TObject);
begin
  if dlgOpenExe.Execute then
    edtAppPath.Text := dlgOpenExe.FileName;
end;

function TFormMain.ResolveInputPath: string;
begin
  Result := Trim(edtAppPath.Text);
  if Result = '' then
    Result := SelectedDetectedPath;
end;

function TFormMain.InstallRuleForPath(const APath: string;
  AAction: TFirewallAction; ASilent: Boolean): Boolean;
var
  RuleID: TGUID;
  Path: string;
begin
  Result := False;
  Path := NormalizePath(Trim(APath));
  if Path = '' then
  begin
    if not ASilent then
      MessageDlg('Select or type an app path first.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if not FileExists(Path) then
  begin
    if not ASilent then
      MessageDlg('File does not exist: ' + Path, mtWarning, [mbOK], 0);
    Exit;
  end;

  if HasRuleForPathAction(Path, AAction) then
  begin
    if not ASilent then
      Log(Format('%s rule already exists for %s', [ActionToText(AAction), Path]));
    Exit(True);
  end;

  try
    if AAction = faAllow then
      RuleID := Firewall1.AllowApplication(Path)
    else
      RuleID := Firewall1.BlockApplication(Path);

    Log(Format('%s rule added: %s', [ActionToText(AAction), GUIDToString(RuleID)]));
    Result := True;
  except
    on E: Exception do
    begin
      Log('Rule add failed: ' + E.Message);
      if not ASilent then
        MessageDlg(E.Message, mtError, [mbOK], 0);
    end;
  end;
end;

procedure TFormMain.btnAllowClick(Sender: TObject);
begin
  InstallRuleForPath(ResolveInputPath, faAllow);
end;

procedure TFormMain.btnBlockClick(Sender: TObject);
begin
  InstallRuleForPath(ResolveInputPath, faBlock);
end;

procedure TFormMain.Log(const AMsg: string);
begin
  memLog.Lines.Add(FormatDateTime('hh:nn:ss.zzz', Now) + '  ' + AMsg);
  memLog.SelStart := Length(memLog.Text);
end;

function TFormMain.EventText(const AEvent: TFirewallEvent): string;
var
  AppText: string;
begin
  AppText := AEvent.ApplicationPath;
  if AppText = '' then
    AppText := '<unknown app>';

  Result := Format('%s %s %s %s:%d -> %s:%d | %s', [
    ActionToText(AEvent.Action),
    DirectionToText(AEvent.Direction),
    ProtocolToText(AEvent.Protocol),
    AEvent.LocalAddress,
    AEvent.LocalPort,
    AEvent.RemoteAddress,
    AEvent.RemotePort,
    AppText
  ]);
end;

function TFormMain.FindDetectedItem(const APath: string): TListItem;
var
  I: Integer;
  Data: TDetectedAppItem;
begin
  Result := nil;
  for I := 0 to lvDetected.Items.Count - 1 do
  begin
    Data := TDetectedAppItem(lvDetected.Items[I].Data);
    if Assigned(Data) and SameText(Data.AppPath, APath) then
      Exit(lvDetected.Items[I]);
  end;
end;

procedure TFormMain.RefreshDetectedItemUI(AItem: TListItem;
  AData: TDetectedAppItem);
var
  AppName: string;
begin
  AppName := ExtractFileName(AData.AppPath);
  if AppName = '' then
    AppName := AData.AppPath;

  AItem.Caption := AppName;
  AItem.SubItems.Clear;
  AItem.SubItems.Add(AData.AppPath);
  AItem.SubItems.Add(AData.Publisher);
  AItem.SubItems.Add(BoolToStr(AData.Signed, True));
  AItem.SubItems.Add(FormatDateTime('yyyy-mm-dd hh:nn:ss', AData.LastSeen));
  AItem.SubItems.Add(IntToStr(AData.Hits));
  AItem.SubItems.Add(ActionToText(AData.LastAction));
end;

procedure TFormMain.UpsertDetected(const AEvent: TFirewallEvent;
  const AFileDetails: TFirewallFileDetails; AHasDetails: Boolean);
var
  Item: TListItem;
  Data: TDetectedAppItem;
  Path: string;
begin
  Path := Trim(AEvent.ApplicationPath);
  if Path = '' then
    Exit;

  Item := FindDetectedItem(Path);
  if Assigned(Item) then
    Data := TDetectedAppItem(Item.Data)
  else
  begin
    Item := lvDetected.Items.Add;
    Data := TDetectedAppItem.Create;
    Data.AppPath := Path;
    Data.Publisher := '';
    Data.Signed := False;
    Data.Hits := 0;
    Item.Data := Data;
  end;

  Inc(Data.Hits);
  if AEvent.TimeStamp > 0 then
    Data.LastSeen := AEvent.TimeStamp
  else
    Data.LastSeen := Now;
  Data.LastAction := AEvent.Action;

  if AHasDetails then
  begin
    if AFileDetails.Publisher <> '' then
      Data.Publisher := AFileDetails.Publisher;
    Data.Signed := AFileDetails.IsSigned;
  end;

  RefreshDetectedItemUI(Item, Data);
end;

procedure TFormMain.ClearDetectedList;
var
  I: Integer;
begin
  for I := 0 to lvDetected.Items.Count - 1 do
    TObject(lvDetected.Items[I].Data).Free;
  lvDetected.Items.Clear;
end;

function TFormMain.SelectedDetectedPath: string;
var
  Data: TDetectedAppItem;
begin
  Result := '';
  if not Assigned(lvDetected.Selected) then
    Exit;

  Data := TDetectedAppItem(lvDetected.Selected.Data);
  if Assigned(Data) then
    Result := Data.AppPath;
end;

function TFormMain.FindRuleItem(const ARuleID: TGUID): TListItem;
var
  I: Integer;
  Data: TRuleListItem;
begin
  Result := nil;
  for I := 0 to lvRules.Items.Count - 1 do
  begin
    Data := TRuleListItem(lvRules.Items[I].Data);
    if Assigned(Data) and IsEqualGUID(Data.RuleID, ARuleID) then
      Exit(lvRules.Items[I]);
  end;
end;

procedure TFormMain.UpsertRule(const ARuleID: TGUID; const APath: string;
  AAction: TFirewallAction);
var
  Item: TListItem;
  Data: TRuleListItem;
begin
  Item := FindRuleItem(ARuleID);
  if Assigned(Item) then
    Data := TRuleListItem(Item.Data)
  else
  begin
    Item := lvRules.Items.Add;
    Data := TRuleListItem.Create;
    Item.Data := Data;
  end;

  Data.RuleID := ARuleID;
  Data.AppPath := APath;
  Data.Action := AAction;

  Item.Caption := GUIDToString(ARuleID);
  Item.SubItems.Clear;
  Item.SubItems.Add(ActionToText(AAction));
  Item.SubItems.Add(APath);
end;

procedure TFormMain.ClearRuleList;
var
  I: Integer;
begin
  for I := 0 to lvRules.Items.Count - 1 do
    TObject(lvRules.Items[I].Data).Free;
  lvRules.Items.Clear;
end;

function TFormMain.SelectedRuleData: TRuleListItem;
begin
  Result := nil;
  if Assigned(lvRules.Selected) then
    Result := TRuleListItem(lvRules.Selected.Data);
end;

function TFormMain.HasRuleForPathAction(const APath: string;
  AAction: TFirewallAction): Boolean;
var
  I: Integer;
  Data: TRuleListItem;
  TargetPath: string;
begin
  Result := False;
  TargetPath := NormalizePath(APath);
  for I := 0 to lvRules.Items.Count - 1 do
  begin
    Data := TRuleListItem(lvRules.Items[I].Data);
    if Assigned(Data) and SameText(NormalizePath(Data.AppPath), TargetPath) and
       (Data.Action = AAction) then
      Exit(True);
  end;
end;

function TFormMain.NormalizePath(const APath: string): string;
begin
  Result := Trim(APath);
  if Result = '' then
    Exit;

  try
    if FileExists(Result) then
      Result := ExpandFileName(Result);
  except
    // Keep original path when normalization fails.
  end;
end;

function TFormMain.ShouldTreatAsAllow(const APath: string): Boolean;
var
  Path: string;
begin
  Path := NormalizePath(APath);
  Result := (Path <> '') and HasRuleForPathAction(Path, faAllow);
end;

function TFormMain.DatabaseFilePath: string;
begin
  Result := TPath.Combine(ExtractFilePath(ParamStr(0)), 'firewall_rules.db');
end;

function TFormMain.ActionToDbText(AAction: TFirewallAction): string;
begin
  case AAction of
    faAllow: Result := 'ALLOW';
    faBlock: Result := 'BLOCK';
  else
    Result := 'BLOCK';
  end;
end;

function TFormMain.DbTextToAction(const AValue: string;
  out AAction: TFirewallAction): Boolean;
begin
  Result := True;
  if SameText(Trim(AValue), 'ALLOW') then
    AAction := faAllow
  else if SameText(Trim(AValue), 'BLOCK') then
    AAction := faBlock
  else
    Result := False;
end;

procedure TFormMain.SetupDatabase;
var
  DBPath: string;
begin
  DBPath := DatabaseFilePath;

  FDConnection1.Connected := False;
  FDConnection1.LoginPrompt := False;
  FDConnection1.Params.Clear;
  FDConnection1.DriverName := 'SQLite';
  FDConnection1.Params.Values['Database'] := DBPath;
  FDConnection1.Params.Values['LockingMode'] := 'Normal';
  FDConnection1.Params.Values['Synchronous'] := 'Normal';
  FDConnection1.Connected := True;

  EnsureDatabaseSchema;
  FDatabaseReady := True;
  Log('SQLite DB ready: ' + DBPath);
end;

procedure TFormMain.EnsureDatabaseSchema;
begin
  FDConnection1.ExecSQL(
    'CREATE TABLE IF NOT EXISTS rules (' +
    '  id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
    '  app_path TEXT NOT NULL, ' +
    '  action TEXT NOT NULL CHECK(action IN (''ALLOW'',''BLOCK'')), ' +
    '  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, ' +
    '  UNIQUE(app_path, action)' +
    ')'
  );
end;

procedure TFormMain.LoadRulesFromDatabase;
var
  LoadedCount: Integer;
  SkippedCount: Integer;
  RulePath: string;
  RuleAction: TFirewallAction;
begin
  if not FDatabaseReady then
    Exit;

  LoadedCount := 0;
  SkippedCount := 0;

  FDQueryRules.Close;
  FDQueryRules.SQL.Text :=
    'SELECT app_path, action FROM rules ORDER BY id';
  FDQueryRules.Open;
  try
    FLoadingRulesFromDB := True;
    while not FDQueryRules.Eof do
    begin
      RulePath := Trim(FDQueryRules.FieldByName('app_path').AsString);
      if DbTextToAction(FDQueryRules.FieldByName('action').AsString, RuleAction) and
         InstallRuleForPath(RulePath, RuleAction, True) then
        Inc(LoadedCount)
      else
        Inc(SkippedCount);

      FDQueryRules.Next;
    end;
  finally
    FLoadingRulesFromDB := False;
    FDQueryRules.Close;
  end;

  Log(Format('Loaded %d saved rule(s) from SQLite (%d skipped).',
    [LoadedCount, SkippedCount]));
end;

procedure TFormMain.ReloadRulesFromDatabase;
begin
  if Firewall1.Active then
    Firewall1.Active := False;

  Firewall1.ClearRules;
  ClearRuleList;
  LoadRulesFromDatabase;
end;

procedure TFormMain.SaveRuleToDatabase(const APath: string;
  AAction: TFirewallAction);
var
  RulePath: string;
begin
  if not FDatabaseReady then
    Exit;

  RulePath := NormalizePath(APath);
  if RulePath = '' then
    Exit;

  FDQueryRules.Close;
  FDQueryRules.SQL.Text :=
    'INSERT OR IGNORE INTO rules (app_path, action) VALUES (:app_path, :action)';
  FDQueryRules.ParamByName('app_path').AsString := RulePath;
  FDQueryRules.ParamByName('action').AsString := ActionToDbText(AAction);
  FDQueryRules.ExecSQL;
end;

procedure TFormMain.DeleteRuleFromDatabase(const APath: string;
  AAction: TFirewallAction);
var
  RulePath: string;
begin
  if not FDatabaseReady then
    Exit;

  RulePath := NormalizePath(APath);
  if RulePath = '' then
    Exit;

  FDQueryRules.Close;
  FDQueryRules.SQL.Text :=
    'DELETE FROM rules WHERE app_path = :app_path AND action = :action';
  FDQueryRules.ParamByName('app_path').AsString := RulePath;
  FDQueryRules.ParamByName('action').AsString := ActionToDbText(AAction);
  FDQueryRules.ExecSQL;
end;

procedure TFormMain.ClearRulesFromDatabase;
begin
  if not FDatabaseReady then
    Exit;

  FDConnection1.ExecSQL('DELETE FROM rules');
end;

procedure TFormMain.miDetAllowClick(Sender: TObject);
begin
  InstallRuleForPath(SelectedDetectedPath, faAllow);
end;

procedure TFormMain.miDetBlockClick(Sender: TObject);
begin
  InstallRuleForPath(SelectedDetectedPath, faBlock);
end;

procedure TFormMain.miDetCopyPathClick(Sender: TObject);
var
  Path: string;
begin
  Path := SelectedDetectedPath;
  if Path = '' then
    Exit;
  Clipboard.AsText := Path;
  Log('Copied detected app path to clipboard.');
end;

procedure TFormMain.miRuleDeleteClick(Sender: TObject);
var
  Data: TRuleListItem;
begin
  Data := SelectedRuleData;
  if not Assigned(Data) then
  begin
    MessageDlg('Select a rule first.', mtInformation, [mbOK], 0);
    Exit;
  end;

  if not Firewall1.DeleteRule(Data.RuleID) then
    Log('Delete skipped (rule not found): ' + GUIDToString(Data.RuleID));
end;

procedure TFormMain.miRuleClearClick(Sender: TObject);
begin
  Firewall1.ClearRules;
  ClearRuleList;
  try
    ClearRulesFromDatabase;
  except
    on E: Exception do
      Log('SQLite clear failed: ' + E.Message);
  end;
  Log('All rules cleared.');
end;

procedure TFormMain.miRuleCopyPathClick(Sender: TObject);
var
  Data: TRuleListItem;
begin
  Data := SelectedRuleData;
  if not Assigned(Data) then
    Exit;
  Clipboard.AsText := Data.AppPath;
  Log('Copied rule app path to clipboard.');
end;

procedure TFormMain.FirewallNewAppDetected(Sender: TObject;
  const Event: TFirewallEvent; const FileDetails: TFirewallFileDetails);
var
  PolicyEvent: TFirewallEvent;
  Path: string;
begin
  Path := NormalizePath(Event.ApplicationPath);
  PolicyEvent := Event;

  // Default-deny: only explicit allow rules are treated as allow.
  if ShouldTreatAsAllow(Path) then
    PolicyEvent.Action := faAllow
  else
    PolicyEvent.Action := faBlock;

  UpsertDetected(PolicyEvent, FileDetails, True);
  Log('NEW APP: ' + Event.ApplicationPath);


  Log(EventText(PolicyEvent));
end;

procedure TFormMain.FirewallAllow(Sender: TObject; const Event: TFirewallEvent);
var
  EmptyDetails: TFirewallFileDetails;
  PolicyEvent: TFirewallEvent;
  Path: string;
begin
  FillChar(EmptyDetails, SizeOf(EmptyDetails), 0);
  Path := NormalizePath(Event.ApplicationPath);

  PolicyEvent := Event;
  if ShouldTreatAsAllow(Path) then
    PolicyEvent.Action := faAllow
  else
    PolicyEvent.Action := faBlock;

  UpsertDetected(PolicyEvent, EmptyDetails, False);


  Log(EventText(PolicyEvent));
end;

procedure TFormMain.FirewallBlock(Sender: TObject; const Event: TFirewallEvent);
var
  EmptyDetails: TFirewallFileDetails;
  PolicyEvent: TFirewallEvent;
begin
  FillChar(EmptyDetails, SizeOf(EmptyDetails), 0);

  PolicyEvent := Event;
  PolicyEvent.Action := faBlock;
  UpsertDetected(PolicyEvent, EmptyDetails, False);

  Log(EventText(PolicyEvent));
end;

procedure TFormMain.FirewallNewRule(Sender: TObject;
  const Rule: TFirewallRuleInfo);
begin
  UpsertRule(Rule.RuleID, Rule.ApplicationPath, Rule.Action);

  if not FLoadingRulesFromDB then
  begin
    try
      SaveRuleToDatabase(Rule.ApplicationPath, Rule.Action);
    except
      on E: Exception do
        Log('SQLite save failed: ' + E.Message);
    end;
  end;

  Log('Rule created: ' + GUIDToString(Rule.RuleID));
end;

procedure TFormMain.FirewallDeleteRule(Sender: TObject;
  const Rule: TFirewallRuleInfo);
var
  Item: TListItem;
begin
  Item := FindRuleItem(Rule.RuleID);
  if Assigned(Item) then
  begin
    TObject(Item.Data).Free;
    Item.Delete;
  end;

  try
    DeleteRuleFromDatabase(Rule.ApplicationPath, Rule.Action);
  except
    on E: Exception do
      Log('SQLite delete failed: ' + E.Message);
  end;

  Log('Rule deleted: ' + GUIDToString(Rule.RuleID));
end;

procedure TFormMain.FirewallError(Sender: TObject; ErrorCode: DWORD;
  const ErrorMessage: string);
begin
  Log(Format('ERROR 0x%.8x: %s', [ErrorCode, ErrorMessage]));
end;

end.
