unit MainForm;

interface

uses
  Winapi.Windows,
  Winapi.ShellAPI,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Math,
  System.Generics.Collections,
  System.Generics.Defaults,
  Vcl.Forms,
  Vcl.Controls,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.Graphics,
  Vcl.Menus,
  Vcl.WinXCtrls,
  FireDAC.Comp.Client,
  FireDAC.Comp.DataSet,
  FireDAC.Stan.Param,
  FireDAC.Phys.SQLite,
  FireDAC.Phys.SQLiteDef,
  FW.Component,
  FW.Notification,
  FW.Types, FireDAC.Stan.Intf, FireDAC.Stan.Option, FireDAC.Stan.Error,
  FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def, FireDAC.Stan.Pool,
  FireDAC.Stan.Async, FireDAC.Phys, FireDAC.VCLUI.Wait, FireDAC.DatS,
  FireDAC.DApt.Intf, FireDAC.DApt, FireDAC.Stan.ExprFuncs,
  FireDAC.Phys.SQLiteWrapper.Stat, Data.DB;

type
  TRuleState = record
    AllowRuleID: TGUID;
    BlockRuleID: TGUID;
  end;

  TAppEntry = class
  public
    AppPath: string;
    DisplayName: string;
    SortIndex: Integer;
    LastSeen: TDateTime;
    RowPanel: TPanel;
    IconImage: TImage;
    NameLabel: TLabel;
    PathLabel: TLabel;
    SeenLabel: TLabel;
    StateLabel: TLabel;
    Toggle: TToggleSwitch;
    UpdatingToggle: Boolean;
  end;

  TFormMain = class(TForm)
    MainMenu1: TMainMenu;
    miFile: TMenuItem;
    miFileExit: TMenuItem;
    miNotification: TMenuItem;
    miNotifyTrue: TMenuItem;
    miNotifyFalse: TMenuItem;
    pnlHeader: TPanel;
    lblTitle: TLabel;
    lblSubtitle: TLabel;
    lblStatus: TLabel;
    sbApps: TScrollBox;
    Firewall1: TFirewall;
    FDConnection1: TFDConnection;
    FDQuery1: TFDQuery;
    FDPhysSQLiteDriverLink1: TFDPhysSQLiteDriverLink;
    TrayIcon1: TTrayIcon;
    TrayPopup: TPopupMenu;
    Exit1: TMenuItem;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure FirewallNewAppDetected(Sender: TObject;
      const Event: TFirewallEvent; const FileDetails: TFirewallFileDetails);
    procedure FirewallAllow(Sender: TObject; const Event: TFirewallEvent);
    procedure FirewallBlock(Sender: TObject; const Event: TFirewallEvent);
    procedure FirewallNewRule(Sender: TObject; const Rule: TFirewallRuleInfo);
    procedure FirewallDeleteRule(Sender: TObject; const Rule: TFirewallRuleInfo);
    procedure FirewallError(Sender: TObject; ErrorCode: DWORD;
      const ErrorMessage: string);
    procedure miFileExitClick(Sender: TObject);
    procedure miNotifyTrueClick(Sender: TObject);
    procedure miNotifyFalseClick(Sender: TObject);
    procedure Exit1Click(Sender: TObject);
  private
    FApps: TObjectDictionary<string, TAppEntry>;
    FRulesByPath: TDictionary<string, TRuleState>;
    FLoadingPolicies: Boolean;
    FDatabaseReady: Boolean;
    FNextSortIndex: Integer;
    FNotifyOnNewApp: Boolean;
    FNotificationManager: TFirewallNotificationManager;
    FTrayHintShown: Boolean;
    FTrayTransition: Boolean;

    function NormalizePath(const APath: string): string;
    function KeyForPath(const APath: string): string;
    function DatabaseFilePath: string;

    function GetRuleState(const APath: string): TRuleState;
    procedure SetRuleState(const APath: string; const AState: TRuleState);

    procedure EnsureDatabase;
    procedure EnsureSchema;
    procedure LoadPoliciesFromDatabase;
    procedure SavePolicyToDatabase(const APath: string; AAllow: Boolean);
    procedure LoadEntryIcon(AEntry: TAppEntry);
    procedure SetNotifyOnNewApp(const AValue: Boolean);
    procedure MaybeShowNewAppNotification(const APath: string;
      const AEvent: TFirewallEvent; const AState: TRuleState;
      AWasTracked: Boolean);
    procedure MinimizeToTray;
    procedure RestoreFromTray;
    procedure TrayIcon1DblClick(Sender: TObject);

    function EnsureEntry(const APath: string;
      const ADisplayName: string = ''): TAppEntry;
    procedure RelayoutGrid;
    procedure UpdateEntryLayout(AEntry: TAppEntry);
    procedure UpdateEntryState(AEntry: TAppEntry; const AState: TRuleState);
    procedure PolicyToggleClick(Sender: TObject);

    procedure ApplyPolicy(const APath: string; AAllow: Boolean;
      APersist: Boolean);
    procedure ObserveApp(const APath: string; AObservedAt: TDateTime;
      const ADisplayName: string = '');
    procedure UpdateHeaderStatus;
  end;

var
  FormMain: TFormMain;

implementation

{$R *.dfm}

function EmptyRuleState: TRuleState; inline;
begin
  Result.AllowRuleID := TGUID.Empty;
  Result.BlockRuleID := TGUID.Empty;
end;

procedure TFormMain.FormCreate(Sender: TObject);
begin
  FApps := TObjectDictionary<string, TAppEntry>.Create([doOwnsValues]);
  FRulesByPath := TDictionary<string, TRuleState>.Create;
  FLoadingPolicies := False;
  FDatabaseReady := False;
  FNextSortIndex := 0;
  FNotifyOnNewApp := True;
  FTrayHintShown := False;
  FTrayTransition := False;
  FNotificationManager := TFirewallNotificationManager.Create;
  FNotificationManager.TimeoutSeconds := 20;
  FNotificationManager.DefaultAction := fprBlock;
  FNotificationManager.Callback :=
    procedure(const AAppPath: string; AResult: TFirewallPromptResult;
      ADirection: TFirewallDirection)
    begin
      TThread.Queue(nil,
        procedure
        begin
          try
            ApplyPolicy(AAppPath, AResult = fprAllow, True);
          except
            on E: Exception do
            begin
              lblStatus.Font.Color := clMaroon;
              lblStatus.Caption := 'Notification action failed: ' + E.Message;
            end;
          end;
        end);
    end;

  SetNotifyOnNewApp(True);

  TrayIcon1.Hint := Caption;
  TrayIcon1.Visible := True;
  TrayIcon1.OnDblClick := TrayIcon1DblClick;

  Firewall1.Active := False;
  Firewall1.DynamicSession := False;
  Firewall1.MonitorIntervalMs := 200;

  try
    EnsureDatabase;
    LoadPoliciesFromDatabase;
  except
    on E: Exception do
    begin
      FDatabaseReady := False;
      lblStatus.Font.Color := clMaroon;
      lblStatus.Caption := 'SQLite unavailable: ' + E.Message;
    end;
  end;

  try
    Firewall1.Active := True;
    lblStatus.Font.Color := clGreen;
    lblStatus.Caption := 'Monitoring active';
  except
    on E: Exception do
    begin
      lblStatus.Font.Color := clMaroon;
      lblStatus.Caption := 'Startup failed: ' + E.Message;
    end;
  end;

  RelayoutGrid;
  UpdateHeaderStatus;
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
  try
    Firewall1.Active := False;
  except
    // keep shutdown clean
  end;

  if Assigned(FNotificationManager) then
  begin
    FNotificationManager.ClearAll;
    FreeAndNil(FNotificationManager);
  end;

  if FDConnection1.Connected then
    FDConnection1.Connected := False;

  TrayIcon1.Visible := False;

  FRulesByPath.Free;
  FApps.Free;
end;

procedure TFormMain.SetNotifyOnNewApp(const AValue: Boolean);
begin
  FNotifyOnNewApp := AValue;
  miNotifyTrue.Checked := AValue;
  miNotifyFalse.Checked := not AValue;

  if not AValue and Assigned(FNotificationManager) then
    FNotificationManager.ClearAll;
end;

procedure TFormMain.MaybeShowNewAppNotification(const APath: string;
  const AEvent: TFirewallEvent; const AState: TRuleState;
  AWasTracked: Boolean);
begin
  if not FNotifyOnNewApp then
    Exit;
  if not Assigned(FNotificationManager) then
    Exit;
  if APath = '' then
    Exit;
  if AWasTracked then
    Exit;
  if (AState.AllowRuleID <> TGUID.Empty) or
     (AState.BlockRuleID <> TGUID.Empty) then
    Exit;
  if FLoadingPolicies then
    Exit;

  FNotificationManager.ShowNotification(APath, AEvent);
end;

procedure TFormMain.MinimizeToTray;
begin
  if FTrayTransition then
    Exit;

  FTrayTransition := True;
  try
    TrayIcon1.Visible := True;
    Hide;

    if not FTrayHintShown then
    begin
      TrayIcon1.BalloonTitle := 'Firewall Monitor';
      TrayIcon1.BalloonHint :=
        'Firewall App Switchboard is still running in the system tray.';
      TrayIcon1.BalloonFlags := bfInfo;
      TrayIcon1.ShowBalloonHint;
      FTrayHintShown := True;
    end;
  finally
    FTrayTransition := False;
  end;
end;

procedure TFormMain.RestoreFromTray;
begin
  if FTrayTransition then
    Exit;

  FTrayTransition := True;
  try
    Show;
    WindowState := wsNormal;
    Application.Restore;
    BringToFront;
    SetForegroundWindow(Handle);
  finally
    FTrayTransition := False;
  end;
end;

procedure TFormMain.TrayIcon1DblClick(Sender: TObject);
begin
  RestoreFromTray;
end;

procedure TFormMain.miFileExitClick(Sender: TObject);
begin
  halt;
end;

procedure TFormMain.miNotifyTrueClick(Sender: TObject);
begin
  SetNotifyOnNewApp(True);
end;

procedure TFormMain.miNotifyFalseClick(Sender: TObject);
begin
  SetNotifyOnNewApp(False);
end;

procedure TFormMain.FormResize(Sender: TObject);
begin
  if WindowState = wsMinimized then
  begin
    MinimizeToTray;
    Exit;
  end;

  RelayoutGrid;
end;

function TFormMain.NormalizePath(const APath: string): string;
var
  WinDir: string;
  BaseName: string;
begin
  Result := Trim(APath);
  if Result = '' then
    Exit;

  BaseName := ExtractFileName(Result);
  if SameText(Result, 'System') or
     SameText(Result, 'System Idle Process') or
     (not FileExists(Result) and
      (SameText(BaseName, 'System') or SameText(BaseName, 'System Idle Process'))) then
  begin
    WinDir := GetEnvironmentVariable('SystemRoot');
    if WinDir = '' then
      WinDir := GetEnvironmentVariable('windir');
    if WinDir = '' then
      WinDir := 'C:\Windows';
    Result := TPath.Combine(WinDir, 'System32\ntoskrnl.exe');
  end;

  try
    if (Pos(':\', Result) > 0) or (Pos('\\', Result) = 1) then
      Result := ExpandFileName(Result);
  except
    // Keep original value if normalization fails.
  end;
end;

function TFormMain.KeyForPath(const APath: string): string;
begin
  Result := UpperCase(NormalizePath(APath));
end;

function TFormMain.DatabaseFilePath: string;
begin
  Result := TPath.Combine(ExtractFilePath(ParamStr(0)), 'polished_rules.db');
end;

function TFormMain.GetRuleState(const APath: string): TRuleState;
var
  Key: string;
begin
  Result := EmptyRuleState;
  Key := KeyForPath(APath);
  if (Key <> '') and FRulesByPath.TryGetValue(Key, Result) then
    Exit;
  Result := EmptyRuleState;
end;

procedure TFormMain.SetRuleState(const APath: string; const AState: TRuleState);
var
  Key: string;
begin
  Key := KeyForPath(APath);
  if Key = '' then
    Exit;

  if (AState.AllowRuleID = TGUID.Empty) and (AState.BlockRuleID = TGUID.Empty) then
    FRulesByPath.Remove(Key)
  else
    FRulesByPath.AddOrSetValue(Key, AState);
end;

procedure TFormMain.EnsureDatabase;
begin
  FDConnection1.Connected := False;
  FDConnection1.LoginPrompt := False;
  FDConnection1.Params.Clear;
  FDConnection1.DriverName := 'SQLite';
  FDConnection1.Params.Values['Database'] := DatabaseFilePath;
  FDConnection1.Params.Values['LockingMode'] := 'Normal';
  FDConnection1.Params.Values['Synchronous'] := 'Normal';
  FDConnection1.Connected := True;

  EnsureSchema;
  FDatabaseReady := True;
end;

procedure TFormMain.EnsureSchema;
begin
  FDConnection1.ExecSQL(
    'CREATE TABLE IF NOT EXISTS app_policy (' +
    '  app_path TEXT PRIMARY KEY, ' +
    '  action TEXT NOT NULL CHECK(action IN (''ALLOW'',''BLOCK'')), ' +
    '  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP' +
    ')'
  );
end;

procedure TFormMain.Exit1Click(Sender: TObject);
begin
halt;
end;

procedure TFormMain.LoadPoliciesFromDatabase;
var
  Path: string;
  AllowMode: Boolean;
begin
  if not FDatabaseReady then
    Exit;

  FLoadingPolicies := True;
  FDQuery1.Close;
  FDQuery1.SQL.Text :=
    'SELECT app_path, action FROM app_policy ORDER BY updated_at DESC';
  FDQuery1.Open;
  try
    while not FDQuery1.Eof do
    begin
      Path := NormalizePath(FDQuery1.FieldByName('app_path').AsString);
      if Path <> '' then
      begin
        AllowMode := SameText(FDQuery1.FieldByName('action').AsString, 'ALLOW');
        EnsureEntry(Path);
        ApplyPolicy(Path, AllowMode, False);
      end;
      FDQuery1.Next;
    end;
  finally
    FLoadingPolicies := False;
    FDQuery1.Close;
  end;
end;

procedure TFormMain.SavePolicyToDatabase(const APath: string; AAllow: Boolean);
begin
  if not FDatabaseReady then
    Exit;

  FDQuery1.Close;
  FDQuery1.SQL.Text :=
    'INSERT OR REPLACE INTO app_policy (app_path, action, updated_at) ' +
    'VALUES (:app_path, :action, CURRENT_TIMESTAMP)';
  FDQuery1.ParamByName('app_path').AsString := NormalizePath(APath);
  if AAllow then
    FDQuery1.ParamByName('action').AsString := 'ALLOW'
  else
    FDQuery1.ParamByName('action').AsString := 'BLOCK';
  FDQuery1.ExecSQL;
end;

procedure TFormMain.LoadEntryIcon(AEntry: TAppEntry);
var
  FileInfo: SHFILEINFOW;
  Flags: UINT;
  Icon: TIcon;
begin
  if not Assigned(AEntry) or not Assigned(AEntry.IconImage) then
    Exit;

  FillChar(FileInfo, SizeOf(FileInfo), 0);
  Flags := SHGFI_ICON or SHGFI_LARGEICON;
  if not FileExists(AEntry.AppPath) then
    Flags := Flags or SHGFI_USEFILEATTRIBUTES;

  if SHGetFileInfoW(PWideChar(AEntry.AppPath), FILE_ATTRIBUTE_NORMAL, FileInfo,
    SizeOf(FileInfo), Flags) = 0 then
    Exit;

  try
    Icon := TIcon.Create;
    try
      Icon.Handle := CopyIcon(FileInfo.hIcon);
      AEntry.IconImage.Picture.Icon := Icon;
    finally
      Icon.Free;
    end;
  finally
    if FileInfo.hIcon <> 0 then
      DestroyIcon(FileInfo.hIcon);
  end;
end;

function TFormMain.EnsureEntry(const APath: string;
  const ADisplayName: string): TAppEntry;
var
  Key: string;
  DisplayName: string;
begin
  Key := KeyForPath(APath);
  if Key = '' then
    Exit(nil);

  if FApps.TryGetValue(Key, Result) then
    Exit;

  DisplayName := Trim(ADisplayName);
  if DisplayName = '' then
    DisplayName := ExtractFileName(APath);
  if DisplayName = '' then
    DisplayName := APath;

  Result := TAppEntry.Create;
  Result.AppPath := NormalizePath(APath);
  Result.DisplayName := DisplayName;
  Result.SortIndex := FNextSortIndex;
  Inc(FNextSortIndex);
  Result.LastSeen := 0;
  Result.UpdatingToggle := False;

  Result.RowPanel := TPanel.Create(Self);
  Result.RowPanel.Parent := sbApps;
  Result.RowPanel.Align := alNone;
  Result.RowPanel.SetBounds(0, 0, 320, 116);
  Result.RowPanel.BevelOuter := bvNone;
  Result.RowPanel.ParentBackground := False;
  Result.RowPanel.Color := TColor($00FDFDFD);
  Result.RowPanel.Hint := Key;

  Result.IconImage := TImage.Create(Self);
  Result.IconImage.Parent := Result.RowPanel;
  Result.IconImage.Width := 40;
  Result.IconImage.Height := 40;
  Result.IconImage.Center := True;
  Result.IconImage.Proportional := True;
  Result.IconImage.Stretch := True;
  Result.IconImage.Transparent := True;

  Result.NameLabel := TLabel.Create(Self);
  Result.NameLabel.Parent := Result.RowPanel;
  Result.NameLabel.Font.Style := [fsBold];
  Result.NameLabel.Font.Height := -15;
  Result.NameLabel.Caption := DisplayName;
  Result.NameLabel.Transparent := True;

  Result.PathLabel := TLabel.Create(Self);
  Result.PathLabel.Parent := Result.RowPanel;
  Result.PathLabel.Font.Height := -12;
  Result.PathLabel.Font.Color := TColor($00707070);
  Result.PathLabel.Caption := Result.AppPath;
  Result.PathLabel.Transparent := True;
  Result.PathLabel.ShowHint := True;
  Result.PathLabel.Hint := Result.AppPath;

  Result.SeenLabel := TLabel.Create(Self);
  Result.SeenLabel.Parent := Result.RowPanel;
  Result.SeenLabel.Font.Height := -12;
  Result.SeenLabel.Font.Color := TColor($00606060);
  Result.SeenLabel.Caption := 'Last seen --:--:--';
  Result.SeenLabel.Transparent := True;

  Result.StateLabel := TLabel.Create(Self);
  Result.StateLabel.Parent := Result.RowPanel;
  Result.StateLabel.Font.Style := [fsBold];
  Result.StateLabel.Font.Height := -12;
  Result.StateLabel.Caption := 'BLOCK';
  Result.StateLabel.Transparent := True;

  Result.Toggle := TToggleSwitch.Create(Self);
  Result.Toggle.Parent := Result.RowPanel;
  Result.Toggle.Width := 72;
  Result.Toggle.Height := 24;
  Result.Toggle.State := tssOff;
  Result.Toggle.StateCaptions.CaptionOn := 'ON';
  Result.Toggle.StateCaptions.CaptionOff := 'OFF';
  Result.Toggle.Hint := Key;
  Result.Toggle.OnClick := PolicyToggleClick;
  LoadEntryIcon(Result);

  FApps.Add(Key, Result);
  RelayoutGrid;
  UpdateEntryLayout(Result);
end;

procedure TFormMain.RelayoutGrid;
const
  GAP = 14;
  CARD_MIN_WIDTH = 300;
  CARD_MAX_WIDTH = 440;
  CARD_HEIGHT = 116;
var
  Entries: TList<TAppEntry>;
  Entry: TAppEntry;
  AvailableWidth: Integer;
  ColCount: Integer;
  CardWidth: Integer;
  Index: Integer;
  Col: Integer;
  Row: Integer;
  TotalRows: Integer;
begin
  if not Assigned(sbApps) then
    Exit;

  Entries := TList<TAppEntry>.Create;
  try
    for Entry in FApps.Values do
      Entries.Add(Entry);

    Entries.Sort(
      TComparer<TAppEntry>.Construct(
        function(const Left, Right: TAppEntry): Integer
        begin
          Result := Left.SortIndex - Right.SortIndex;
        end
      )
    );

    AvailableWidth := Max(220, sbApps.ClientWidth - GetSystemMetrics(SM_CXVSCROLL));
    ColCount := Max(1, (AvailableWidth - GAP) div (CARD_MIN_WIDTH + GAP));
    CardWidth := (AvailableWidth - ((ColCount + 1) * GAP)) div ColCount;
    CardWidth := EnsureRange(CardWidth, CARD_MIN_WIDTH, CARD_MAX_WIDTH);

    for Index := 0 to Entries.Count - 1 do
    begin
      Entry := Entries[Index];
      Col := Index mod ColCount;
      Row := Index div ColCount;
      Entry.RowPanel.SetBounds(
        GAP + Col * (CardWidth + GAP),
        GAP + Row * (CARD_HEIGHT + GAP),
        CardWidth,
        CARD_HEIGHT
      );
      UpdateEntryLayout(Entry);
    end;

    TotalRows := (Entries.Count + ColCount - 1) div ColCount;
    sbApps.VertScrollBar.Range := GAP + TotalRows * (CARD_HEIGHT + GAP);
  finally
    Entries.Free;
  end;
end;

procedure TFormMain.UpdateEntryLayout(AEntry: TAppEntry);
const
  PAD = 14;
  ICON_SIZE = 40;
  TEXT_LEFT = PAD + ICON_SIZE + 12;
begin
  if not Assigned(AEntry) then
    Exit;

  AEntry.IconImage.SetBounds(PAD, 16, ICON_SIZE, ICON_SIZE);
  AEntry.Toggle.Left := AEntry.RowPanel.ClientWidth - AEntry.Toggle.Width - PAD;
  AEntry.Toggle.Top := 14;

  AEntry.NameLabel.SetBounds(
    TEXT_LEFT,
    14,
    AEntry.Toggle.Left - TEXT_LEFT - PAD,
    18
  );

  AEntry.PathLabel.SetBounds(
    TEXT_LEFT,
    38,
    AEntry.Toggle.Left - TEXT_LEFT - PAD,
    15
  );

  AEntry.SeenLabel.SetBounds(TEXT_LEFT, 82, 135, 16);
  AEntry.StateLabel.SetBounds(TEXT_LEFT + 142, 82, 90, 16);
end;

procedure TFormMain.UpdateEntryState(AEntry: TAppEntry; const AState: TRuleState);
var
  IsAllow: Boolean;
begin
  if not Assigned(AEntry) then
    Exit;

  if AEntry.LastSeen > 0 then
    AEntry.SeenLabel.Caption := 'Last seen ' + FormatDateTime('hh:nn:ss', AEntry.LastSeen)
  else
    AEntry.SeenLabel.Caption := 'Last seen --:--:--';

  IsAllow := AState.AllowRuleID <> TGUID.Empty;

  AEntry.UpdatingToggle := True;
  try
    if IsAllow then
      AEntry.Toggle.State := tssOn
    else
      AEntry.Toggle.State := tssOff;
  finally
    AEntry.UpdatingToggle := False;
  end;

  if IsAllow then
  begin
    AEntry.StateLabel.Caption := 'ALLOW';
    AEntry.StateLabel.Font.Color := TColor($00007A3D);
  end
  else
  begin
    AEntry.StateLabel.Caption := 'BLOCK';
    AEntry.StateLabel.Font.Color := TColor($001A41B5);
  end;
end;

procedure TFormMain.PolicyToggleClick(Sender: TObject);
var
  Toggle: TToggleSwitch;
  Entry: TAppEntry;
  Key: string;
begin
  Toggle := Sender as TToggleSwitch;
  Key := Toggle.Hint;
  if not FApps.TryGetValue(Key, Entry) then
    Exit;

  if Entry.UpdatingToggle then
    Exit;

  try
    ApplyPolicy(Entry.AppPath, Toggle.State = tssOn, True);
    lblStatus.Font.Color := clGreen;
    lblStatus.Caption := 'Monitoring active';
  except
    on E: Exception do
    begin
      Entry.UpdatingToggle := True;
      try
        if Toggle.State = tssOn then
          Toggle.State := tssOff
        else
          Toggle.State := tssOn;
      finally
        Entry.UpdatingToggle := False;
      end;

      lblStatus.Font.Color := clMaroon;
      lblStatus.Caption := 'Policy change failed: ' + E.Message;
    end;
  end;
end;

procedure TFormMain.ApplyPolicy(const APath: string; AAllow: Boolean;
  APersist: Boolean);
var
  Path: string;
  State: TRuleState;
  Entry: TAppEntry;
begin
  Path := NormalizePath(APath);
  if Path = '' then
    Exit;

  Entry := EnsureEntry(Path);
  if not Assigned(Entry) then
    Exit;

  if (not FileExists(Path)) and
     (not SameText(ExtractFileName(Path), 'ntoskrnl.exe')) then
  begin
    Entry.Toggle.Enabled := False;
    Exit;
  end;
  Entry.Toggle.Enabled := True;

  State := GetRuleState(Path);

  if AAllow then
  begin
    if State.BlockRuleID <> TGUID.Empty then
    begin
      Firewall1.DeleteRule(State.BlockRuleID);
      State.BlockRuleID := TGUID.Empty;
    end;

    if State.AllowRuleID = TGUID.Empty then
      State.AllowRuleID := Firewall1.AllowApplication(Path);
  end
  else
  begin
    if State.AllowRuleID <> TGUID.Empty then
    begin
      Firewall1.DeleteRule(State.AllowRuleID);
      State.AllowRuleID := TGUID.Empty;
    end;

    if State.BlockRuleID = TGUID.Empty then
      State.BlockRuleID := Firewall1.BlockApplication(Path);
  end;

  SetRuleState(Path, State);
  UpdateEntryState(Entry, State);

  if APersist and FDatabaseReady and not FLoadingPolicies then
    SavePolicyToDatabase(Path, AAllow);

  UpdateHeaderStatus;
end;

procedure TFormMain.ObserveApp(const APath: string; AObservedAt: TDateTime;
  const ADisplayName: string);
var
  Path: string;
  Entry: TAppEntry;
  State: TRuleState;
begin
  Path := NormalizePath(APath);
  if Path = '' then
    Exit;

  Entry := EnsureEntry(Path, ADisplayName);
  if not Assigned(Entry) then
    Exit;

  if AObservedAt > 0 then
    Entry.LastSeen := AObservedAt
  else
    Entry.LastSeen := Now;

  State := GetRuleState(Path);
  if (State.AllowRuleID = TGUID.Empty) and (State.BlockRuleID = TGUID.Empty) and
     not FLoadingPolicies then
  begin
    // If notifications are enabled, let the popup drive first-time policy.
    // Otherwise preserve the default behavior of blocking unknown apps.
    if not FNotifyOnNewApp then
    begin
      ApplyPolicy(Path, False, True);
      State := GetRuleState(Path);
    end;
  end;

  UpdateEntryState(Entry, State);
  UpdateHeaderStatus;
end;

procedure TFormMain.UpdateHeaderStatus;
var
  Pair: TPair<string, TRuleState>;
  AllowCount: Integer;
begin
  AllowCount := 0;
  for Pair in FRulesByPath do
    if Pair.Value.AllowRuleID <> TGUID.Empty then
      Inc(AllowCount);

  lblSubtitle.Caption := Format(
    '%d app(s) tracked  |  %d allowed  |  %d blocked',
    [FApps.Count, AllowCount, Max(0, FApps.Count - AllowCount)]
  );
end;

procedure TFormMain.FirewallNewAppDetected(Sender: TObject;
  const Event: TFirewallEvent; const FileDetails: TFirewallFileDetails);
var
  DisplayName: string;
  Path: string;
  Key: string;
  WasTracked: Boolean;
  State: TRuleState;
begin
  Path := NormalizePath(Event.ApplicationPath);
  Key := KeyForPath(Path);
  WasTracked := (Key <> '') and FApps.ContainsKey(Key);
  State := GetRuleState(Path);
  MaybeShowNewAppNotification(Path, Event, State, WasTracked);

  DisplayName := FileDetails.FileName;
  if DisplayName = '' then
    DisplayName := ExtractFileName(Event.ApplicationPath);
  ObserveApp(Event.ApplicationPath, Event.TimeStamp, DisplayName);
end;

procedure TFormMain.FirewallAllow(Sender: TObject; const Event: TFirewallEvent);
var
  Path: string;
  Key: string;
  WasTracked: Boolean;
  State: TRuleState;
begin
  Path := NormalizePath(Event.ApplicationPath);
  Key := KeyForPath(Path);
  WasTracked := (Key <> '') and FApps.ContainsKey(Key);
  State := GetRuleState(Path);
  MaybeShowNewAppNotification(Path, Event, State, WasTracked);
  ObserveApp(Event.ApplicationPath, Event.TimeStamp);
end;

procedure TFormMain.FirewallBlock(Sender: TObject; const Event: TFirewallEvent);
var
  Path: string;
  Key: string;
  WasTracked: Boolean;
  State: TRuleState;
begin
  Path := NormalizePath(Event.ApplicationPath);
  Key := KeyForPath(Path);
  WasTracked := (Key <> '') and FApps.ContainsKey(Key);
  State := GetRuleState(Path);
  MaybeShowNewAppNotification(Path, Event, State, WasTracked);
  ObserveApp(Event.ApplicationPath, Event.TimeStamp);
end;

procedure TFormMain.FirewallNewRule(Sender: TObject;
  const Rule: TFirewallRuleInfo);
var
  Path: string;
  State: TRuleState;
  Entry: TAppEntry;
begin
  Path := NormalizePath(Rule.ApplicationPath);
  if Path = '' then
    Exit;

  State := GetRuleState(Path);
  if Rule.Action = faAllow then
    State.AllowRuleID := Rule.RuleID
  else
    State.BlockRuleID := Rule.RuleID;
  SetRuleState(Path, State);

  Entry := EnsureEntry(Path);
  UpdateEntryState(Entry, State);
  UpdateHeaderStatus;
end;

procedure TFormMain.FirewallDeleteRule(Sender: TObject;
  const Rule: TFirewallRuleInfo);
var
  Path: string;
  State: TRuleState;
  Entry: TAppEntry;
begin
  Path := NormalizePath(Rule.ApplicationPath);
  if Path = '' then
    Exit;

  State := GetRuleState(Path);
  if (Rule.Action = faAllow) and IsEqualGUID(State.AllowRuleID, Rule.RuleID) then
    State.AllowRuleID := TGUID.Empty
  else if (Rule.Action = faBlock) and IsEqualGUID(State.BlockRuleID, Rule.RuleID) then
    State.BlockRuleID := TGUID.Empty;
  SetRuleState(Path, State);

  Entry := EnsureEntry(Path);
  UpdateEntryState(Entry, State);
  UpdateHeaderStatus;
end;

procedure TFormMain.FirewallError(Sender: TObject; ErrorCode: DWORD;
  const ErrorMessage: string);
begin
  lblStatus.Font.Color := clMaroon;
  lblStatus.Caption := Format('Error 0x%.8x: %s', [ErrorCode, ErrorMessage]);
end;

end.
