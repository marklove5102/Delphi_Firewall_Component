unit FW.Notification;

{******************************************************************************
  FW.Notification - Interactive Firewall Notification Prompt

  Displays a comprehensive toast-style notification in the bottom-right corner
  when a new (previously unseen) application attempts a network connection.
  Shows full details: application name, publisher, file description, file
  version, full path, connection direction, protocol, and IP:port info.

  The user can Allow or Block the application. If no action is taken within
  the timeout period, the default action (Block) is applied automatically.

  Notifications stack upward when multiple appear simultaneously. Each
  notification manages its own countdown timer and self-destructs on close.

  This unit is used internally by TFirewall when PromptUnknownApps is True.
  It can also be used standalone by creating a TFirewallNotificationManager.
******************************************************************************}

interface

uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils, System.Classes, System.Generics.Collections,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.StdCtrls, Vcl.ExtCtrls,
  FW.Types;

type
  TFirewallPromptResult = (fprAllow, fprBlock);

  TFirewallPromptCallback = reference to procedure(const AAppPath: string;
    AResult: TFirewallPromptResult; ADirection: TFirewallDirection);

  TFirewallNotificationManager = class;

  TFirewallNotificationForm = class(TForm)
  private
    FPnlMain: TPanel;
    FPnlAccent: TPanel;
    FLblTitle: TLabel;
    FLblAppName: TLabel;
    FLblPublisher: TLabel;
    FLblDescription: TLabel;
    FLblAppPath: TLabel;
    FLblDirection: TLabel;
    FLblConnection: TLabel;
    FLblProtocol: TLabel;
    FLblCountdown: TLabel;
    FBtnAllow: TButton;
    FBtnBlock: TButton;
    FCountdownTimer: TTimer;
    FCountdown: Integer;
    FAppPath: string;
    FDirection: TFirewallDirection;
    FCallback: TFirewallPromptCallback;
    FManager: TFirewallNotificationManager;
    FResultSent: Boolean;

    procedure BuildUI;
    procedure PopulateData(const AAppPath: string; const AEvent: TFirewallEvent);
    procedure HandleAllow(Sender: TObject);
    procedure HandleBlock(Sender: TObject);
    procedure HandleTimer(Sender: TObject);
    procedure SendResult(AResult: TFirewallPromptResult);
  protected
    procedure CreateParams(var Params: TCreateParams); override;
    procedure DoClose(var Action: TCloseAction); override;
  public
    constructor CreateNotification(AManager: TFirewallNotificationManager;
      const AAppPath: string; const AEvent: TFirewallEvent;
      ACallback: TFirewallPromptCallback; ATimeoutSec: Integer);
    procedure PositionAt(ASlot: Integer);
  end;

  TFirewallNotificationManager = class
  private
    FActive: TList<TFirewallNotificationForm>;
    FPendingPaths: TDictionary<string, Boolean>;
    FCallback: TFirewallPromptCallback;
    FTimeoutSeconds: Integer;
    FDefaultAction: TFirewallPromptResult;
  public
    constructor Create;
    destructor Destroy; override;

    procedure ShowNotification(const AAppPath: string;
      const AEvent: TFirewallEvent);
    procedure NotificationClosed(AForm: TFirewallNotificationForm);
    procedure ClearAll;
    procedure Reposition;

    property Callback: TFirewallPromptCallback read FCallback write FCallback;
    property TimeoutSeconds: Integer read FTimeoutSeconds write FTimeoutSeconds;
    property DefaultAction: TFirewallPromptResult read FDefaultAction
      write FDefaultAction;
  end;

implementation

const
  NOTIF_WIDTH       = 480;
  NOTIF_HEIGHT      = 290;
  NOTIF_MARGIN      = 10;
  NOTIF_ACCENT_W    = 5;
  CONTENT_LEFT      = 16;
  CONTENT_WIDTH     = NOTIF_WIDTH - NOTIF_ACCENT_W - 30;

  // Colors - dark theme
  CLR_BACKGROUND    = $00303030;
  CLR_ACCENT_BLOCK  = $002222DD; // Red accent (BGR) - default
  CLR_ACCENT_ALLOW  = $00228B22; // Green accent
  CLR_TITLE         = $000088FF; // Orange title (BGR)
  CLR_APP_NAME      = $00FFFFFF; // White
  CLR_PUBLISHER     = $0080D0FF; // Light orange (BGR)
  CLR_DESCRIPTION   = $00C0C0C0; // Silver
  CLR_PATH          = $00909090; // Gray
  CLR_DIRECTION_IN  = $006060FF; // Light red for inbound (BGR)
  CLR_DIRECTION_OUT = $0060D060; // Light green for outbound
  CLR_CONNECTION    = $00E0E0E0; // Near-white
  CLR_PROTOCOL      = $00FFD080; // Light blue (BGR)
  CLR_COUNTDOWN     = $008080FF; // Light red (BGR)
  CLR_LABEL_DIM     = $00808080; // Dim gray for field labels

// =============================================================================
// File Version Info Helpers
// =============================================================================

type
  TFileVersionInfo = record
    CompanyName: string;
    FileDescription: string;
    FileVersion: string;
    ProductName: string;
    OriginalFileName: string;
  end;

function GetFileVersionInfo(const AFilePath: string): TFileVersionInfo;
var
  InfoSize, Handle: DWORD;
  InfoBuf: TBytes;
  LangPtr: Pointer;
  LangLen: UINT;
  LangCode: string;
  ValuePtr: Pointer;
  ValueLen: UINT;

  function QueryStr(const AKey: string): string;
  var
    SubBlock: string;
  begin
    Result := '';
    SubBlock := Format('\StringFileInfo\%s\%s', [LangCode, AKey]);
    if VerQueryValueW(Pointer(InfoBuf), PWideChar(SubBlock),
      ValuePtr, ValueLen) and (ValueLen > 0) then
      Result := Trim(PWideChar(ValuePtr));
  end;

begin
  Result := Default(TFileVersionInfo);
  if not FileExists(AFilePath) then
    Exit;

  InfoSize := Winapi.Windows.GetFileVersionInfoSizeW(PWideChar(AFilePath), Handle);
  if InfoSize = 0 then
    Exit;

  SetLength(InfoBuf, InfoSize);
  if not Winapi.Windows.GetFileVersionInfoW(PWideChar(AFilePath), Handle,
    InfoSize, Pointer(InfoBuf)) then
    Exit;

  // Get translation table to build language code
  if not VerQueryValueW(Pointer(InfoBuf), '\VarFileInfo\Translation',
    LangPtr, LangLen) or (LangLen < 4) then
    Exit;

  // Build language/codepage string from first translation entry
  LangCode := Format('%.4x%.4x', [
    PWord(LangPtr)^,
    PWord(PByte(LangPtr) + 2)^]);

  Result.CompanyName := QueryStr('CompanyName');
  Result.FileDescription := QueryStr('FileDescription');
  Result.FileVersion := QueryStr('FileVersion');
  Result.ProductName := QueryStr('ProductName');
  Result.OriginalFileName := QueryStr('OriginalFilename');
end;

function DirectionToDisplayStr(D: TFirewallDirection): string;
begin
  case D of
    fdInbound:  Result := 'INBOUND (incoming connection)';
    fdOutbound: Result := 'OUTBOUND (outgoing connection)';
    fdBoth:     Result := 'ALL DIRECTIONS';
  else
    Result := 'UNKNOWN';
  end;
end;

function ProtocolToStr(P: TFirewallProtocol): string;
begin
  case P of
    fpTCP:  Result := 'TCP';
    fpUDP:  Result := 'UDP';
    fpICMP: Result := 'ICMP';
    fpAny:  Result := 'ANY';
  else
    Result := 'Unknown';
  end;
end;

// =============================================================================
// Helper to create a styled label
// =============================================================================

function MakeLabel(AOwner: TComponent; AParent: TWinControl;
  ALeft, ATop, AWidth: Integer; AFontSize: Integer;
  AFontColor: TColor; ABold: Boolean; AEllipsis: Boolean): TLabel;
begin
  Result := TLabel.Create(AOwner);
  Result.Parent := AParent;
  Result.Left := ALeft;
  Result.Top := ATop;
  Result.Font.Name := 'Segoe UI';
  Result.Font.Size := AFontSize;
  Result.Font.Color := AFontColor;
  if ABold then
    Result.Font.Style := [fsBold]
  else
    Result.Font.Style := [];
  Result.Transparent := True;
  if AWidth > 0 then
  begin
    Result.Width := AWidth;
    Result.AutoSize := False;
    if AEllipsis then
      Result.EllipsisPosition := epEndEllipsis;
  end
  else
    Result.AutoSize := True;
end;

{ TFirewallNotificationForm }

constructor TFirewallNotificationForm.CreateNotification(
  AManager: TFirewallNotificationManager;
  const AAppPath: string; const AEvent: TFirewallEvent;
  ACallback: TFirewallPromptCallback; ATimeoutSec: Integer);
begin
  inherited CreateNew(nil);
  FManager := AManager;
  FAppPath := AAppPath;
  FDirection := AEvent.Direction;
  FCallback := ACallback;
  FCountdown := ATimeoutSec;
  FResultSent := False;

  // Form properties
  BorderStyle := bsNone;
  FormStyle := fsStayOnTop;
  Position := poDesigned;
  Width := NOTIF_WIDTH;
  Height := NOTIF_HEIGHT;
  Color := CLR_BACKGROUND;
  AlphaBlend := True;
  AlphaBlendValue := 245;
  Font.Name := 'Segoe UI';

  BuildUI;
  PopulateData(AAppPath, AEvent);

  // Start countdown timer
  FCountdownTimer := TTimer.Create(Self);
  FCountdownTimer.Interval := 1000;
  FCountdownTimer.OnTimer := HandleTimer;
  FCountdownTimer.Enabled := True;
end;

procedure TFirewallNotificationForm.CreateParams(var Params: TCreateParams);
begin
  inherited;
  Params.ExStyle := Params.ExStyle or WS_EX_TOOLWINDOW or WS_EX_TOPMOST;
  Params.ExStyle := Params.ExStyle and not WS_EX_APPWINDOW;
end;

procedure TFirewallNotificationForm.BuildUI;
var
  Y: Integer;
begin
  // Accent bar on the left edge
  FPnlAccent := TPanel.Create(Self);
  FPnlAccent.Parent := Self;
  FPnlAccent.Align := alLeft;
  FPnlAccent.Width := NOTIF_ACCENT_W;
  FPnlAccent.BevelOuter := bvNone;
  FPnlAccent.Color := CLR_ACCENT_BLOCK;
  FPnlAccent.ParentBackground := False;

  // Main panel
  FPnlMain := TPanel.Create(Self);
  FPnlMain.Parent := Self;
  FPnlMain.Align := alClient;
  FPnlMain.BevelOuter := bvNone;
  FPnlMain.Color := CLR_BACKGROUND;
  FPnlMain.ParentBackground := False;

  Y := 8;

  // Title bar
  FLblTitle := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    9, CLR_TITLE, True, False);
  FLblTitle.Caption := 'FIREWALL ALERT - New Application Detected';
  Inc(Y, 22);

  // Application name (large, bold, white)
  FLblAppName := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    14, CLR_APP_NAME, True, True);
  Inc(Y, 28);

  // Publisher
  FLblPublisher := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    8, CLR_PUBLISHER, False, True);
  Inc(Y, 16);

  // File description + version
  FLblDescription := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    8, CLR_DESCRIPTION, False, True);
  Inc(Y, 16);

  // Full path
  FLblAppPath := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    7, CLR_PATH, False, True);
  Inc(Y, 18);

  // Direction (colored)
  FLblDirection := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    9, CLR_DIRECTION_OUT, True, False);
  Inc(Y, 20);

  // Connection: local -> remote
  FLblConnection := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    9, CLR_CONNECTION, False, True);
  Inc(Y, 18);

  // Protocol
  FLblProtocol := MakeLabel(Self, FPnlMain, CONTENT_LEFT, Y, CONTENT_WIDTH,
    8, CLR_PROTOCOL, True, False);
  Inc(Y, 24);

  // Buttons row
  FBtnAllow := TButton.Create(Self);
  FBtnAllow.Parent := FPnlMain;
  FBtnAllow.Left := CONTENT_LEFT;
  FBtnAllow.Top := Y;
  FBtnAllow.Width := 180;
  FBtnAllow.Height := 38;
  FBtnAllow.Caption := 'ALLOW';
  FBtnAllow.Font.Name := 'Segoe UI';
  FBtnAllow.Font.Size := 11;
  FBtnAllow.Font.Style := [fsBold];
  FBtnAllow.OnClick := HandleAllow;

  FBtnBlock := TButton.Create(Self);
  FBtnBlock.Parent := FPnlMain;
  FBtnBlock.Left := CONTENT_LEFT + 190;
  FBtnBlock.Top := Y;
  FBtnBlock.Width := 150;
  FBtnBlock.Height := 38;
  FBtnBlock.Caption := 'BLOCK';
  FBtnBlock.Font.Name := 'Segoe UI';
  FBtnBlock.Font.Size := 11;
  FBtnBlock.Font.Style := [fsBold];
  FBtnBlock.OnClick := HandleBlock;

  // Countdown label (right-aligned next to buttons)
  FLblCountdown := MakeLabel(Self, FPnlMain, CONTENT_LEFT + 350, Y + 12,
    0, 8, CLR_COUNTDOWN, False, False);
end;

procedure TFirewallNotificationForm.PopulateData(const AAppPath: string;
  const AEvent: TFirewallEvent);
var
  VerInfo: TFileVersionInfo;
  ConnStr: string;
  PubStr: string;
  DescStr: string;
begin
  // Get file version info (publisher, description, version)
  VerInfo := GetFileVersionInfo(AAppPath);

  // Application name
  FLblAppName.Caption := ExtractFileName(AAppPath);

  // Publisher line
  PubStr := '';
  if VerInfo.CompanyName <> '' then
    PubStr := 'Publisher: ' + VerInfo.CompanyName
  else
    PubStr := 'Publisher: Unknown';
  FLblPublisher.Caption := PubStr;

  // Description + version line
  DescStr := '';
  if VerInfo.FileDescription <> '' then
    DescStr := VerInfo.FileDescription;
  if VerInfo.ProductName <> '' then
  begin
    if DescStr = '' then
      DescStr := VerInfo.ProductName;
  end;
  if VerInfo.FileVersion <> '' then
  begin
    if DescStr <> '' then
      DescStr := DescStr + '  (v' + VerInfo.FileVersion + ')'
    else
      DescStr := 'Version: ' + VerInfo.FileVersion;
  end;
  if DescStr = '' then
    DescStr := 'No file description available';
  FLblDescription.Caption := DescStr;

  // Full path
  FLblAppPath.Caption := 'Path: ' + AAppPath;

  // Direction with color coding
  FLblDirection.Caption := DirectionToDisplayStr(AEvent.Direction);
  case AEvent.Direction of
    fdInbound:
    begin
      FLblDirection.Font.Color := CLR_DIRECTION_IN;
      FPnlAccent.Color := CLR_ACCENT_BLOCK;
    end;
    fdOutbound:
    begin
      FLblDirection.Font.Color := CLR_DIRECTION_OUT;
      FPnlAccent.Color := CLR_ACCENT_BLOCK;
    end;
  end;

  // Connection details: FROM -> TO
  ConnStr := '';
  if AEvent.LocalAddress <> '' then
    ConnStr := AEvent.LocalAddress
  else
    ConnStr := '*';
  if AEvent.LocalPort > 0 then
    ConnStr := ConnStr + ':' + IntToStr(AEvent.LocalPort);

  ConnStr := ConnStr + '  -->  ';

  if AEvent.RemoteAddress <> '' then
    ConnStr := ConnStr + AEvent.RemoteAddress
  else
    ConnStr := ConnStr + '*';
  if AEvent.RemotePort > 0 then
    ConnStr := ConnStr + ':' + IntToStr(AEvent.RemotePort);

  FLblConnection.Caption := ConnStr;

  // Protocol
  FLblProtocol.Caption := 'Protocol: ' + ProtocolToStr(AEvent.Protocol);

  // Countdown text
  if FManager.DefaultAction = fprBlock then
    FLblCountdown.Caption := Format('Auto-BLOCK in %ds', [FCountdown])
  else
    FLblCountdown.Caption := Format('Auto-ALLOW in %ds', [FCountdown]);
end;

procedure TFirewallNotificationForm.HandleAllow(Sender: TObject);
begin
  SendResult(fprAllow);
  Close;
end;

procedure TFirewallNotificationForm.HandleBlock(Sender: TObject);
begin
  SendResult(fprBlock);
  Close;
end;

procedure TFirewallNotificationForm.HandleTimer(Sender: TObject);
begin
  Dec(FCountdown);
  if FCountdown <= 0 then
  begin
    FCountdownTimer.Enabled := False;
    SendResult(FManager.DefaultAction);
    Close;
  end
  else
  begin
    if FManager.DefaultAction = fprBlock then
      FLblCountdown.Caption := Format('Auto-BLOCK in %ds', [FCountdown])
    else
      FLblCountdown.Caption := Format('Auto-ALLOW in %ds', [FCountdown]);
  end;
end;

procedure TFirewallNotificationForm.SendResult(
  AResult: TFirewallPromptResult);
begin
  if FResultSent then
    Exit;
  FResultSent := True;
  if Assigned(FCallback) then
    FCallback(FAppPath, AResult, FDirection);
end;

procedure TFirewallNotificationForm.DoClose(var Action: TCloseAction);
begin
  FCountdownTimer.Enabled := False;

  if not FResultSent then
    SendResult(FManager.DefaultAction);

  if Assigned(FManager) then
    FManager.NotificationClosed(Self);

  Action := caFree;
  inherited;
end;

procedure TFirewallNotificationForm.PositionAt(ASlot: Integer);
var
  WorkArea: TRect;
  M: TMonitor;
  X: Integer;
  Y: Integer;
begin
  // Always anchor to the primary monitor so the toast consistently appears
  // in the screen's bottom-right corner.
  M := Screen.PrimaryMonitor;
  if Assigned(M) then
    WorkArea := M.WorkareaRect
  else
    WorkArea := Screen.WorkAreaRect;

  X := WorkArea.Right - Width - NOTIF_MARGIN;
  Y := WorkArea.Bottom - (Height + NOTIF_MARGIN) * (ASlot + 1);
  SetBounds(X, Y, Width, Height);

  if HandleAllocated then
    SetWindowPos(Handle, HWND_TOPMOST, X, Y, Width, Height,
      SWP_NOACTIVATE or SWP_SHOWWINDOW);
end;

{ TFirewallNotificationManager }

constructor TFirewallNotificationManager.Create;
begin
  inherited Create;
  FActive := TList<TFirewallNotificationForm>.Create;
  FPendingPaths := TDictionary<string, Boolean>.Create;
  FTimeoutSeconds := 15;
  FDefaultAction := fprBlock;
end;

destructor TFirewallNotificationManager.Destroy;
begin
  ClearAll;
  FPendingPaths.Free;
  FActive.Free;
  inherited Destroy;
end;

procedure TFirewallNotificationManager.ShowNotification(
  const AAppPath: string; const AEvent: TFirewallEvent);
var
  Form: TFirewallNotificationForm;
  Key: string;
begin
  Key := UpperCase(AAppPath);

  // Don't show duplicate notification for the same app
  if FPendingPaths.ContainsKey(Key) then
    Exit;
  FPendingPaths.Add(Key, True);

  Form := TFirewallNotificationForm.CreateNotification(
    Self, AAppPath, AEvent, FCallback, FTimeoutSeconds);
  FActive.Add(Form);
  Form.PositionAt(FActive.Count - 1);
  Form.Show;
  // Re-apply after show to avoid OS/default placement overriding coordinates.
  Form.PositionAt(FActive.Count - 1);
end;

procedure TFirewallNotificationManager.NotificationClosed(
  AForm: TFirewallNotificationForm);
var
  Key: string;
begin
  Key := UpperCase(AForm.FAppPath);
  FPendingPaths.Remove(Key);
  FActive.Remove(AForm);
  Reposition;
end;

procedure TFirewallNotificationManager.ClearAll;
var
  I: Integer;
begin
  // Close all active notifications (they free themselves via caFree)
  for I := FActive.Count - 1 downto 0 do
    FActive[I].Close;
  FActive.Clear;
  FPendingPaths.Clear;
end;

procedure TFirewallNotificationManager.Reposition;
var
  I: Integer;
begin
  for I := 0 to FActive.Count - 1 do
    FActive[I].PositionAt(I);
end;

end.
