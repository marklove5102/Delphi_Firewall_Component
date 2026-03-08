program SimpleFirewallDemo;

uses
  Vcl.Forms,
  MainForm in 'MainForm.pas' {FormMain},
  FW.Component in '..\..\Source\FW.Component.pas',
  FW.Types in '..\..\Source\FW.Types.pas',
  FW.WFP.API in '..\..\Source\FW.WFP.API.pas',
  FW.IpHelper.API in '..\..\Source\FW.IpHelper.API.pas',
  FW.Monitor in '..\..\Source\FW.Monitor.pas';

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
