program PolishedDemo;

uses
  System.SysUtils,
  System.IOUtils,
  Vcl.Forms,
  Vcl.Themes,
  Vcl.Styles,
  MainForm in 'MainForm.pas' {FormMain},
  FW.Component in '..\..\Source\FW.Component.pas',
  FW.Notification in '..\..\Source\FW.Notification.pas',
  FW.Types in '..\..\Source\FW.Types.pas',
  FW.WFP.API in '..\..\Source\FW.WFP.API.pas',
  FW.IpHelper.API in '..\..\Source\FW.IpHelper.API.pas',
  FW.Monitor in '..\..\Source\FW.Monitor.pas';

{$R *.res}

function TryLoadStyleFromFile(const AFileName: string): Boolean;
var
  StyleHandle: TStyleManager.TStyleServicesHandle;
begin
  Result := False;
  if not FileExists(AFileName) then
    Exit;

  try
    StyleHandle := TStyleManager.LoadFromFile(AFileName);
    TStyleManager.SetStyle(StyleHandle);
    Result := True;
  except
    Result := False;
  end;
end;

function TrySetCarbonStyle: Boolean;
var
  Candidate: string;
  StudioRoot: string;
  StudioDir: string;
begin
  try
    Result := TStyleManager.TrySetStyle('Carbon');
  except
    Result := False;
  end;
  if Result then
    Exit;

  Candidate := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Carbon.vsf');
  if TryLoadStyleFromFile(Candidate) then
    Exit(True);

  Candidate := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Styles\Carbon.vsf');
  if TryLoadStyleFromFile(Candidate) then
    Exit(True);

  StudioRoot := TPath.Combine(
    TPath.Combine(GetEnvironmentVariable('PUBLIC'), 'Documents\Embarcadero'),
    'Studio'
  );
  if TDirectory.Exists(StudioRoot) then
  begin
    for StudioDir in TDirectory.GetDirectories(StudioRoot) do
    begin
      Candidate := TPath.Combine(StudioDir, 'Styles\Carbon.vsf');
      if TryLoadStyleFromFile(Candidate) then
        Exit(True);
    end;
  end;
end;

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  TrySetCarbonStyle;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
