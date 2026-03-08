object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'Delphi Firewall Demo'
  ClientHeight = 760
  ClientWidth = 1260
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object splMain: TSplitter
    Left = 640
    Top = 96
    Height = 464
    ExplicitHeight = 569
  end
  object pnlTop: TPanel
    Left = 0
    Top = 0
    Width = 1260
    Height = 96
    Align = alTop
    TabOrder = 0
    object lblAdmin: TLabel
      Left = 16
      Top = 8
      Width = 368
      Height = 15
      Caption = 
        'Run this demo as Administrator for full WFP visibility and rule ' +
        'control.'
    end
    object lblStatus: TLabel
      Left = 430
      Top = 8
      Width = 82
      Height = 15
      Caption = 'Status: Stopped'
    end
    object lblPath: TLabel
      Left = 16
      Top = 68
      Width = 47
      Height = 15
      Caption = 'App EXE:'
    end
    object btnStart: TButton
      Left = 16
      Top = 30
      Width = 90
      Height = 28
      Caption = 'Start'
      TabOrder = 0
      OnClick = btnStartClick
    end
    object btnStop: TButton
      Left = 112
      Top = 30
      Width = 90
      Height = 28
      Caption = 'Stop'
      TabOrder = 1
      OnClick = btnStopClick
    end
    object edtAppPath: TEdit
      Left = 72
      Top = 64
      Width = 820
      Height = 23
      TabOrder = 2
    end
    object btnBrowse: TButton
      Left = 898
      Top = 62
      Width = 80
      Height = 27
      Caption = 'Browse'
      TabOrder = 3
      OnClick = btnBrowseClick
    end
    object btnAllow: TButton
      Left = 984
      Top = 62
      Width = 85
      Height = 27
      Caption = 'Allow App'
      TabOrder = 4
      OnClick = btnAllowClick
    end
    object btnBlock: TButton
      Left = 1075
      Top = 62
      Width = 85
      Height = 27
      Caption = 'Block App'
      TabOrder = 5
      OnClick = btnBlockClick
    end
  end
  object memLog: TMemo
    Left = 0
    Top = 560
    Width = 1260
    Height = 200
    Align = alBottom
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object pnlDetected: TPanel
    Left = 0
    Top = 96
    Width = 640
    Height = 464
    Align = alLeft
    TabOrder = 2
    object lblDetected: TLabel
      Left = 1
      Top = 1
      Width = 638
      Height = 18
      Align = alTop
      Alignment = taCenter
      AutoSize = False
      Caption = 'Detected Apps'
      Layout = tlCenter
    end
    object lvDetected: TListView
      Left = 1
      Top = 19
      Width = 638
      Height = 444
      Align = alClient
      Columns = <
        item
          Caption = 'App'
          Width = 120
        end
        item
          Caption = 'Full Path'
          Width = 230
        end
        item
          Caption = 'Publisher'
          Width = 120
        end
        item
          Caption = 'Signed'
          Width = 55
        end
        item
          Caption = 'Last Seen'
          Width = 130
        end
        item
          Caption = 'Hits'
          Width = 45
        end
        item
          Caption = 'Last Action'
          Width = 75
        end>
      ReadOnly = True
      RowSelect = True
      PopupMenu = pmDetected
      TabOrder = 0
      ViewStyle = vsReport
    end
  end
  object pnlRules: TPanel
    Left = 643
    Top = 96
    Width = 617
    Height = 464
    Align = alClient
    TabOrder = 3
    object lblRules: TLabel
      Left = 1
      Top = 1
      Width = 615
      Height = 18
      Align = alTop
      Alignment = taCenter
      AutoSize = False
      Caption = 'Allowed / Blocked Apps (Rules)'
      Layout = tlCenter
    end
    object lvRules: TListView
      Left = 1
      Top = 19
      Width = 615
      Height = 444
      Align = alClient
      Columns = <
        item
          Caption = 'Rule ID'
          Width = 260
        end
        item
          Caption = 'Action'
          Width = 80
        end
        item
          Caption = 'App Path'
          Width = 260
        end>
      ReadOnly = True
      RowSelect = True
      PopupMenu = pmRules
      TabOrder = 0
      ViewStyle = vsReport
    end
  end
  object dlgOpenExe: TOpenDialog
    Filter = 'Executable (*.exe)|*.exe|All files (*.*)|*.*'
    Left = 688
    Top = 168
  end
  object Firewall1: TFirewall
    ProviderName = 'DelphiFirewall'
    ProviderGUID = '{B0D553E2-C6A0-4A9A-AEB8-C7524838D62F}'
    SublayerName = 'DelphiFirewall Sublayer'
    SublayerGUID = '{9FEE6F59-B951-4F9A-B52F-133DCF7A4279}'
    OnNewAppDetected = FirewallNewAppDetected
    OnBlock = FirewallBlock
    OnAllow = FirewallAllow
    OnNewRule = FirewallNewRule
    OnDeleteRule = FirewallDeleteRule
    OnError = FirewallError
    Left = 48
    Top = 152
  end
  object FDConnection1: TFDConnection
    LoginPrompt = False
    Left = 48
    Top = 208
  end
  object FDQueryRules: TFDQuery
    Connection = FDConnection1
    Left = 48
    Top = 264
  end
  object FDPhysSQLiteDriverLink1: TFDPhysSQLiteDriverLink
    Left = 48
    Top = 320
  end
  object pmDetected: TPopupMenu
    Left = 1040
    Top = 184
    object miDetAllow: TMenuItem
      Caption = 'Allow App'
      OnClick = miDetAllowClick
    end
    object miDetBlock: TMenuItem
      Caption = 'Block App'
      OnClick = miDetBlockClick
    end
    object miDetCopyPath: TMenuItem
      Caption = 'Copy Path'
      OnClick = miDetCopyPathClick
    end
  end
  object pmRules: TPopupMenu
    Left = 1120
    Top = 184
    object miRuleDelete: TMenuItem
      Caption = 'Delete Rule'
      OnClick = miRuleDeleteClick
    end
    object miRuleClear: TMenuItem
      Caption = 'Clear All Rules'
      OnClick = miRuleClearClick
    end
    object miRuleCopyPath: TMenuItem
      Caption = 'Copy Path'
      OnClick = miRuleCopyPathClick
    end
  end
end
