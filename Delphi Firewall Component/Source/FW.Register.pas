unit FW.Register;

{******************************************************************************
  FW.Register - Design-Time Registration for TFirewall VCL Component

  Registers the TFirewall component in the 'Firewall' category of the
  Delphi Component Palette for drag-and-drop usage.
******************************************************************************}

interface

procedure Register;

implementation

{$R 'FW.Register.dcr'}

uses
  System.Classes, DesignIntf, DesignEditors, FW.Component;

type
  TFirewallSelectionEditor = class(TSelectionEditor)
  public
    procedure RequiresUnits(Proc: TGetStrProc); override;
  end;

procedure TFirewallSelectionEditor.RequiresUnits(Proc: TGetStrProc);
begin
  inherited;
  // Ensure event parameter types (TFirewallEvent, TNetworkConnectionArray, etc.)
  // are always resolvable in forms that host TFirewall.
  Proc('FW.Types');
end;

procedure Register;
begin
  RegisterComponents('Firewall', [TFirewall]);
  RegisterSelectionEditor(TFirewall, TFirewallSelectionEditor);
end;

end.

