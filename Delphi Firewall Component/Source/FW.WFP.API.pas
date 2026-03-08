unit FW.WFP.API;

{******************************************************************************
  FW.WFP.API - Windows Filtering Platform API Translations for Delphi

  Translates the essential WFP types, constants, GUIDs, and function imports
  from fwpmu.h / fwptypes.h / fwpmtypes.h for use with the TFirewall VCL
  component. Targets both 32-bit and 64-bit Windows.
******************************************************************************}

interface

uses
  Winapi.Windows, System.SysUtils;

{$ALIGN 8}
{$MINENUMSIZE 4}

const
  FWPUCLNT_DLL = 'fwpuclnt.dll';

  // ---------------------------------------------------------------------------
  // RPC Authentication
  // ---------------------------------------------------------------------------
  RPC_C_AUTHN_WINNT   = 10;
  RPC_C_AUTHN_DEFAULT = DWORD($FFFFFFFF);

  // ---------------------------------------------------------------------------
  // Session flags
  // ---------------------------------------------------------------------------
  FWPM_SESSION_FLAG_DYNAMIC = $00000001;

  // ---------------------------------------------------------------------------
  // Provider flags
  // ---------------------------------------------------------------------------
  FWPM_PROVIDER_FLAG_PERSISTENT  = $00000001;
  FWPM_PROVIDER_FLAG_DISABLED    = $00000010;

  // ---------------------------------------------------------------------------
  // Sublayer flags
  // ---------------------------------------------------------------------------
  FWPM_SUBLAYER_FLAG_PERSISTENT = $00000001;

  // ---------------------------------------------------------------------------
  // Filter action type flags and values
  // ---------------------------------------------------------------------------
  FWP_ACTION_FLAG_TERMINATING     = $00001000;
  FWP_ACTION_FLAG_NON_TERMINATING = $00002000;

  FWP_ACTION_BLOCK                  = $00000001 or FWP_ACTION_FLAG_TERMINATING;
  FWP_ACTION_PERMIT                 = $00000002 or FWP_ACTION_FLAG_TERMINATING;
  FWP_ACTION_CALLOUT_TERMINATING    = $00000003 or FWP_ACTION_FLAG_TERMINATING;
  FWP_ACTION_CALLOUT_INSPECTION     = $00000004 or FWP_ACTION_FLAG_NON_TERMINATING;
  FWP_ACTION_CALLOUT_UNKNOWN        = $00000005 or FWP_ACTION_FLAG_TERMINATING;

  // ---------------------------------------------------------------------------
  // Filter flags
  // ---------------------------------------------------------------------------
  FWPM_FILTER_FLAG_NONE                   = $00000000;
  FWPM_FILTER_FLAG_PERSISTENT             = $00000001;
  FWPM_FILTER_FLAG_BOOTTIME               = $00000002;
  FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT   = $00000004;
  FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT     = $00000020;
  FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED = $00000040;
  FWPM_FILTER_FLAG_DISABLED               = $00000080;
  FWPM_FILTER_FLAG_INDEXED                = $00000100;

  // ---------------------------------------------------------------------------
  // Engine option types
  // ---------------------------------------------------------------------------
  FWPM_ENGINE_COLLECT_NET_EVENTS       = 0;
  FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS = 1;
  FWPM_ENGINE_NAME_CACHE               = 2;
  FWPM_ENGINE_MONITOR_IPSEC_CONNECTIONS = 3;
  FWPM_ENGINE_PACKET_QUEUING           = 4;
  FWPM_ENGINE_TXN_WATCHDOG_TIMEOUT_IN_MSEC = 5;

  // ---------------------------------------------------------------------------
  // Net event subscription keywords
  // ---------------------------------------------------------------------------
  FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST     = 1;
  FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST     = 2;
  FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW    = 16;
  FWPM_NET_EVENT_KEYWORD_PORT_SCANNING_DROP = 32;

  // ---------------------------------------------------------------------------
  // Net event header flags
  // ---------------------------------------------------------------------------
  FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET  = $00000001;
  FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET   = $00000002;
  FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET  = $00000004;
  FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET   = $00000008;
  FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET  = $00000010;
  FWPM_NET_EVENT_FLAG_APP_ID_SET       = $00000020;
  FWPM_NET_EVENT_FLAG_USER_ID_SET      = $00000040;
  FWPM_NET_EVENT_FLAG_SCOPE_ID_SET     = $00000080;
  FWPM_NET_EVENT_FLAG_IP_VERSION_SET   = $00000100;
  FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET = $00000200;
  FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET   = $00000400;

  // ---------------------------------------------------------------------------
  // IP Protocol numbers
  // ---------------------------------------------------------------------------
  IPPROTO_ICMP = 1;
  IPPROTO_TCP  = 6;
  IPPROTO_UDP  = 17;
  IPPROTO_ICMPV6 = 58;

  // ---------------------------------------------------------------------------
  // Filter weight constants (matching simplewall scheme)
  // ---------------------------------------------------------------------------
  FW_WEIGHT_HIGHEST_IMPORTANT = $0F;
  FW_WEIGHT_HIGHEST           = $0E;
  FW_WEIGHT_RULE_BLOCKLIST    = $0D;
  FW_WEIGHT_RULE_USER_BLOCK   = $0C;
  FW_WEIGHT_RULE_USER         = $0B;
  FW_WEIGHT_RULE_SYSTEM       = $0A;
  FW_WEIGHT_APP               = $09;
  FW_WEIGHT_LOWEST            = $08;

  // ---------------------------------------------------------------------------
  // Transaction timeout (milliseconds)
  // ---------------------------------------------------------------------------
  WFP_TRANSACTION_TIMEOUT = 9000;

  // ---------------------------------------------------------------------------
  // FWP_V6_ADDR_SIZE
  // ---------------------------------------------------------------------------
  FWP_V6_ADDR_SIZE = 16;

// =============================================================================
// Layer GUIDs
// =============================================================================
var
  // Outbound connection authorization
  FWPM_LAYER_ALE_AUTH_CONNECT_V4: TGUID;
  FWPM_LAYER_ALE_AUTH_CONNECT_V6: TGUID;

  // Inbound connection authorization
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: TGUID;
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: TGUID;

  // Outbound transport
  FWPM_LAYER_OUTBOUND_TRANSPORT_V4: TGUID;
  FWPM_LAYER_OUTBOUND_TRANSPORT_V6: TGUID;

  // Inbound transport
  FWPM_LAYER_INBOUND_TRANSPORT_V4: TGUID;
  FWPM_LAYER_INBOUND_TRANSPORT_V6: TGUID;

  // Listen layers
  FWPM_LAYER_ALE_AUTH_LISTEN_V4: TGUID;
  FWPM_LAYER_ALE_AUTH_LISTEN_V6: TGUID;

// =============================================================================
// Condition Field Key GUIDs
// =============================================================================
  FWPM_CONDITION_ALE_APP_ID: TGUID;
  FWPM_CONDITION_IP_LOCAL_ADDRESS: TGUID;
  FWPM_CONDITION_IP_REMOTE_ADDRESS: TGUID;
  FWPM_CONDITION_IP_LOCAL_PORT: TGUID;
  FWPM_CONDITION_IP_REMOTE_PORT: TGUID;
  FWPM_CONDITION_IP_PROTOCOL: TGUID;
  FWPM_CONDITION_ALE_USER_ID: TGUID;
  FWPM_CONDITION_ALE_PACKAGE_ID: TGUID;

// =============================================================================
// Enumerations
// =============================================================================
type
  FWP_DATA_TYPE = (
    FWP_EMPTY                      = 0,
    FWP_UINT8                      = 1,
    FWP_UINT16                     = 2,
    FWP_UINT32                     = 3,
    FWP_UINT64                     = 4,
    FWP_INT8                       = 5,
    FWP_INT16                      = 6,
    FWP_INT32                      = 7,
    FWP_INT64                      = 8,
    FWP_FLOAT                      = 9,
    FWP_DOUBLE                     = 10,
    FWP_BYTE_ARRAY16_TYPE          = 11,
    FWP_BYTE_BLOB_TYPE             = 12,
    FWP_SID                        = 13,
    FWP_SECURITY_DESCRIPTOR_TYPE   = 14,
    FWP_TOKEN_INFORMATION_TYPE     = 15,
    FWP_TOKEN_ACCESS_INFORMATION_TYPE = 16,
    FWP_UNICODE_STRING_TYPE        = 17,
    FWP_BYTE_ARRAY6_TYPE           = 18,
    FWP_V4_ADDR_MASK               = 19,
    FWP_V6_ADDR_MASK               = 20,
    FWP_RANGE_TYPE                 = 21
  );

  FWP_MATCH_TYPE = (
    FWP_MATCH_EQUAL                    = 0,
    FWP_MATCH_GREATER                  = 1,
    FWP_MATCH_LESS                     = 2,
    FWP_MATCH_GREATER_OR_EQUAL         = 3,
    FWP_MATCH_LESS_OR_EQUAL            = 4,
    FWP_MATCH_RANGE                    = 5,
    FWP_MATCH_FLAGS_ALL_SET            = 6,
    FWP_MATCH_FLAGS_ANY_SET            = 7,
    FWP_MATCH_FLAGS_NONE_SET           = 8,
    FWP_MATCH_EQUAL_CASE_INSENSITIVE   = 9,
    FWP_MATCH_NOT_EQUAL                = 10,
    FWP_MATCH_PREFIX                   = 11,
    FWP_MATCH_NOT_PREFIX               = 12
  );

  FWP_IP_VERSION = (
    FWP_IP_VERSION_V4   = 0,
    FWP_IP_VERSION_V6   = 1,
    FWP_IP_VERSION_NONE = 2
  );

  FWP_DIRECTION = (
    FWP_DIRECTION_OUTBOUND = 0,
    FWP_DIRECTION_INBOUND  = 1,
    FWP_DIRECTION_MAX      = 2
  );

  FWPM_NET_EVENT_TYPE = (
    FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE = 0,
    FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE = 1,
    FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE = 2,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP     = 3,
    FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP = 4,
    FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP   = 5,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW    = 6,
    FWPM_NET_EVENT_TYPE_CAPABILITY_DROP   = 7,
    FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW  = 8,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC = 9
  );

// =============================================================================
// Record Types (Structures)
// =============================================================================

  // FWP_BYTE_ARRAY16
  PFWP_BYTE_ARRAY16 = ^FWP_BYTE_ARRAY16_REC;
  FWP_BYTE_ARRAY16_REC = record
    byteArray16: array[0..15] of Byte;
  end;

  // FWP_BYTE_ARRAY6
  PFWP_BYTE_ARRAY6 = ^FWP_BYTE_ARRAY6_REC;
  FWP_BYTE_ARRAY6_REC = record
    byteArray6: array[0..5] of Byte;
  end;

  // FWP_BYTE_BLOB
  PFWP_BYTE_BLOB = ^FWP_BYTE_BLOB_REC;
  PPFWP_BYTE_BLOB = ^PFWP_BYTE_BLOB;
  FWP_BYTE_BLOB_REC = record
    size: UINT32;
    data: PByte;
  end;

  // FWP_V4_ADDR_AND_MASK
  PFWP_V4_ADDR_AND_MASK = ^FWP_V4_ADDR_AND_MASK_REC;
  FWP_V4_ADDR_AND_MASK_REC = record
    addr: UINT32;
    mask: UINT32;
  end;

  // FWP_V6_ADDR_AND_MASK
  PFWP_V6_ADDR_AND_MASK = ^FWP_V6_ADDR_AND_MASK_REC;
  FWP_V6_ADDR_AND_MASK_REC = record
    addr: array[0..15] of Byte;
    prefixLength: UINT8;
  end;

  // FWP_VALUE0 - used for filter weight and condition values
  PFWP_RANGE0 = ^FWP_RANGE0_REC;  // forward declaration

  PFWP_VALUE0 = ^FWP_VALUE0_REC;
  FWP_VALUE0_REC = record
    _type: FWP_DATA_TYPE;
    case Integer of
      0:  (uint8: UINT8);
      1:  (uint16: UINT16);
      2:  (uint32: UINT32);
      3:  (puint64: PUINT64);
      4:  (int8: ShortInt);
      5:  (int16: SmallInt);
      6:  (int32: Integer);
      7:  (pint64: PInt64);
      8:  (float32: Single);
      9:  (pdouble64: PDouble);
      10: (byteArray16: PFWP_BYTE_ARRAY16);
      11: (byteBlob: PFWP_BYTE_BLOB);
      12: (sid: PSID);
      13: (sd: PFWP_BYTE_BLOB);
      14: (unicodeString: PWideChar);
      15: (byteArray6: PFWP_BYTE_ARRAY6);
      16: (v4AddrMask: PFWP_V4_ADDR_AND_MASK);
      17: (v6AddrMask: PFWP_V6_ADDR_AND_MASK);
      18: (rangeValue: PFWP_RANGE0);
  end;

  // FWP_CONDITION_VALUE0 - same layout as FWP_VALUE0
  FWP_CONDITION_VALUE0_REC = FWP_VALUE0_REC;
  PFWP_CONDITION_VALUE0 = ^FWP_CONDITION_VALUE0_REC;

  // FWP_RANGE0
  FWP_RANGE0_REC = record
    valueLow: FWP_VALUE0_REC;
    valueHigh: FWP_VALUE0_REC;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_DISPLAY_DATA0
  // ---------------------------------------------------------------------------
  PFWPM_DISPLAY_DATA0 = ^FWPM_DISPLAY_DATA0_REC;
  FWPM_DISPLAY_DATA0_REC = record
    name: PWideChar;
    description: PWideChar;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_SESSION0
  // ---------------------------------------------------------------------------
  PFWPM_SESSION0 = ^FWPM_SESSION0_REC;
  FWPM_SESSION0_REC = record
    sessionKey: TGUID;
    displayData: FWPM_DISPLAY_DATA0_REC;
    flags: UINT32;
    txnWaitTimeoutInMSec: UINT32;
    processId: DWORD;
    sid: PSID;
    username: PWideChar;
    kernelMode: BOOL;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_PROVIDER0
  // ---------------------------------------------------------------------------
  PFWPM_PROVIDER0 = ^FWPM_PROVIDER0_REC;
  FWPM_PROVIDER0_REC = record
    providerKey: TGUID;
    displayData: FWPM_DISPLAY_DATA0_REC;
    flags: UINT32;
    providerData: FWP_BYTE_BLOB_REC;
    serviceName: PWideChar;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_SUBLAYER0
  // ---------------------------------------------------------------------------
  PFWPM_SUBLAYER0 = ^FWPM_SUBLAYER0_REC;
  FWPM_SUBLAYER0_REC = record
    subLayerKey: TGUID;
    displayData: FWPM_DISPLAY_DATA0_REC;
    flags: UINT32;
    providerKey: PGUID;
    providerData: FWP_BYTE_BLOB_REC;
    weight: UINT16;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_FILTER_CONDITION0
  // ---------------------------------------------------------------------------
  PFWPM_FILTER_CONDITION0 = ^FWPM_FILTER_CONDITION0_REC;
  FWPM_FILTER_CONDITION0_REC = record
    fieldKey: TGUID;
    matchType: FWP_MATCH_TYPE;
    conditionValue: FWP_CONDITION_VALUE0_REC;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_ACTION0
  // ---------------------------------------------------------------------------
  FWPM_ACTION0_REC = record
    _type: UINT32;
    case Integer of
      0: (filterType: TGUID);
      1: (calloutKey: TGUID);
  end;

  // ---------------------------------------------------------------------------
  // FWPM_FILTER0 context union
  // ---------------------------------------------------------------------------
  FWPM_FILTER_CONTEXT0_REC = record
    case Integer of
      0: (rawContext: UINT64);
      1: (providerContextKey: TGUID);
  end;

  // ---------------------------------------------------------------------------
  // FWPM_FILTER0
  // ---------------------------------------------------------------------------
  PFWPM_FILTER0 = ^FWPM_FILTER0_REC;
  PPFWPM_FILTER0 = ^PFWPM_FILTER0;
  FWPM_FILTER0_REC = record
    filterKey: TGUID;
    displayData: FWPM_DISPLAY_DATA0_REC;
    flags: UINT32;
    providerKey: PGUID;
    providerData: FWP_BYTE_BLOB_REC;
    layerKey: TGUID;
    subLayerKey: TGUID;
    weight: FWP_VALUE0_REC;
    numFilterConditions: UINT32;
    filterCondition: PFWPM_FILTER_CONDITION0;
    action: FWPM_ACTION0_REC;
    context: FWPM_FILTER_CONTEXT0_REC;
    // NOTE: These fields are part of FWPM_FILTER0 and must be present so
    // the record layout/size matches fwpmtypes.h for FwpmFilterAdd0.
    reserved: PGUID;
    filterId: UINT64;
    effectiveWeight: FWP_VALUE0_REC;
  end;

  // ---------------------------------------------------------------------------
  // Address union for net event headers
  // In C this is: union { UINT32 localAddrV4; FWP_BYTE_ARRAY16 localAddrV6; }
  // The union is always 16 bytes (size of the largest member).
  // ---------------------------------------------------------------------------
  FWPM_NET_EVENT_ADDR = record
    case Integer of
      0: (V4: UINT32; _pad: array[0..11] of Byte);
      1: (V6: array[0..15] of Byte);
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT_HEADER1 - used by FwpmNetEventSubscribe0 callback
  //
  // CRITICAL: The local/remote address fields are 16-byte unions, not plain
  // UINT32. Using UINT32 here causes every field after them (ports, appId,
  // etc.) to be read at the wrong offset - resulting in empty IPs and zero
  // ports in event data.
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT_HEADER1 = ^FWPM_NET_EVENT_HEADER1_REC;
  FWPM_NET_EVENT_HEADER1_REC = record
    timeStamp: TFileTime;
    flags: UINT32;
    ipVersion: FWP_IP_VERSION;
    ipProtocol: UINT8;
    localAddr: FWPM_NET_EVENT_ADDR;   // 16-byte union (V4 uses first 4 bytes)
    remoteAddr: FWPM_NET_EVENT_ADDR;  // 16-byte union (V4 uses first 4 bytes)
    localPort: UINT16;
    remotePort: UINT16;
    scopeId: UINT32;
    appId: FWP_BYTE_BLOB_REC;
    userId: PSID;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT_CLASSIFY_DROP2
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT_CLASSIFY_DROP2 = ^FWPM_NET_EVENT_CLASSIFY_DROP2_REC;
  FWPM_NET_EVENT_CLASSIFY_DROP2_REC = record
    filterId: UINT64;
    layerId: UINT16;
    reauthReason: UINT32;
    originalProfile: UINT32;
    currentProfile: UINT32;
    msFwpDirection: UINT32;
    isLoopback: BOOL;
    vSwitchId: FWP_BYTE_BLOB_REC;
    vSwitchSourcePort: UINT32;
    vSwitchDestinationPort: UINT32;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT_CLASSIFY_ALLOW0
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT_CLASSIFY_ALLOW0 = ^FWPM_NET_EVENT_CLASSIFY_ALLOW0_REC;
  FWPM_NET_EVENT_CLASSIFY_ALLOW0_REC = record
    filterId: UINT64;
    layerId: UINT16;
    reauthReason: UINT32;
    originalProfile: UINT32;
    currentProfile: UINT32;
    msFwpDirection: UINT32;
    isLoopback: BOOL;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT1 - used for FwpmNetEventSubscribe0 callback
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT1 = ^FWPM_NET_EVENT1_REC;
  FWPM_NET_EVENT1_REC = record
    header: FWPM_NET_EVENT_HEADER1_REC;
    _type: FWPM_NET_EVENT_TYPE;
    case Integer of
      0: (ikeMmFailure: Pointer);
      1: (ikeQmFailure: Pointer);
      2: (ikeEmFailure: Pointer);
      3: (classifyDrop: PFWPM_NET_EVENT_CLASSIFY_DROP2);
      4: (ipsecDrop: Pointer);
      5: (idpDrop: Pointer);
      6: (classifyAllow: PFWPM_NET_EVENT_CLASSIFY_ALLOW0);
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT_ENUM_TEMPLATE0
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT_ENUM_TEMPLATE0 = ^FWPM_NET_EVENT_ENUM_TEMPLATE0_REC;
  FWPM_NET_EVENT_ENUM_TEMPLATE0_REC = record
    startTime: TFileTime;
    endTime: TFileTime;
    numFilterConditions: UINT32;
    filterCondition: PFWPM_FILTER_CONDITION0;
  end;

  // ---------------------------------------------------------------------------
  // FWPM_NET_EVENT_SUBSCRIPTION0
  // ---------------------------------------------------------------------------
  PFWPM_NET_EVENT_SUBSCRIPTION0 = ^FWPM_NET_EVENT_SUBSCRIPTION0_REC;
  FWPM_NET_EVENT_SUBSCRIPTION0_REC = record
    enumTemplate: PFWPM_NET_EVENT_ENUM_TEMPLATE0;
    flags: UINT32;
    sessionKey: TGUID;
  end;

  // ---------------------------------------------------------------------------
  // Callback type for FwpmNetEventSubscribe0
  // ---------------------------------------------------------------------------
  FWPM_NET_EVENT_CALLBACK0 = procedure(context: Pointer;
    const event: PFWPM_NET_EVENT1); stdcall;

  // ---------------------------------------------------------------------------
  // Filter enum handle
  // ---------------------------------------------------------------------------
  PFWPM_FILTER_ENUM_TEMPLATE0 = ^FWPM_FILTER_ENUM_TEMPLATE0_REC;
  FWPM_FILTER_ENUM_TEMPLATE0_REC = record
    providerKey: PGUID;
    layerKey: TGUID;
    enumType: UINT32;
    flags: UINT32;
    providerContextTemplate: Pointer;
    numFilterConditions: UINT32;
    filterCondition: PFWPM_FILTER_CONDITION0;
    actionMask: UINT32;
    calloutKey: PGUID;
  end;

// =============================================================================
// WFP API Function Imports
// =============================================================================

// Engine management
function FwpmEngineOpen0(
  serverName: PWideChar;
  authnService: UINT32;
  authIdentity: Pointer;
  session: PFWPM_SESSION0;
  engineHandle: PHANDLE
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmEngineClose0(
  engineHandle: THandle
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmEngineSetOption0(
  engineHandle: THandle;
  option: UINT32;
  newValue: PFWP_VALUE0
): DWORD; stdcall; external FWPUCLNT_DLL;

// Provider management
function FwpmProviderAdd0(
  engineHandle: THandle;
  provider: PFWPM_PROVIDER0;
  sd: PSECURITY_DESCRIPTOR
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmProviderDeleteByKey0(
  engineHandle: THandle;
  const key: TGUID
): DWORD; stdcall; external FWPUCLNT_DLL;

// Sublayer management
function FwpmSubLayerAdd0(
  engineHandle: THandle;
  subLayer: PFWPM_SUBLAYER0;
  sd: PSECURITY_DESCRIPTOR
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmSubLayerDeleteByKey0(
  engineHandle: THandle;
  const key: TGUID
): DWORD; stdcall; external FWPUCLNT_DLL;

// Filter management
function FwpmFilterAdd0(
  engineHandle: THandle;
  filter: PFWPM_FILTER0;
  sd: PSECURITY_DESCRIPTOR;
  id: PUINT64
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmFilterDeleteById0(
  engineHandle: THandle;
  id: UINT64
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmFilterDeleteByKey0(
  engineHandle: THandle;
  const key: TGUID
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmFilterGetById0(
  engineHandle: THandle;
  id: UINT64;
  filter: PPFWPM_FILTER0
): DWORD; stdcall; external FWPUCLNT_DLL;

// Filter enumeration
function FwpmFilterCreateEnumHandle0(
  engineHandle: THandle;
  enumTemplate: PFWPM_FILTER_ENUM_TEMPLATE0;
  enumHandle: PHANDLE
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmFilterEnum0(
  engineHandle: THandle;
  enumHandle: THandle;
  numEntriesRequested: UINT32;
  entries: Pointer;  // PFWPM_FILTER0**
  numEntriesReturned: PUINT32
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmFilterDestroyEnumHandle0(
  engineHandle: THandle;
  enumHandle: THandle
): DWORD; stdcall; external FWPUCLNT_DLL;

// Transaction management
function FwpmTransactionBegin0(
  engineHandle: THandle;
  flags: UINT32
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmTransactionCommit0(
  engineHandle: THandle
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmTransactionAbort0(
  engineHandle: THandle
): DWORD; stdcall; external FWPUCLNT_DLL;

// Net event subscription
function FwpmNetEventSubscribe0(
  engineHandle: THandle;
  subscription: PFWPM_NET_EVENT_SUBSCRIPTION0;
  callback: FWPM_NET_EVENT_CALLBACK0;
  context: Pointer;
  eventsHandle: PHANDLE
): DWORD; stdcall; external FWPUCLNT_DLL;

function FwpmNetEventUnsubscribe0(
  engineHandle: THandle;
  eventsHandle: THandle
): DWORD; stdcall; external FWPUCLNT_DLL;

// App ID helper
function FwpmGetAppIdFromFileName0(
  fileName: PWideChar;
  var appId: PFWP_BYTE_BLOB
): DWORD; stdcall; external FWPUCLNT_DLL;

// Memory management
procedure FwpmFreeMemory0(
  p: PPointer
); stdcall; external FWPUCLNT_DLL;

// =============================================================================
// Helper Functions
// =============================================================================

function WfpActionIsBlock(Action: UINT32): Boolean; inline;
function WfpActionIsPermit(Action: UINT32): Boolean; inline;
function WfpActionIsTerminating(Action: UINT32): Boolean; inline;

implementation

function WfpActionIsBlock(Action: UINT32): Boolean;
begin
  Result := (Action and $0FFF) = $0001;
end;

function WfpActionIsPermit(Action: UINT32): Boolean;
begin
  Result := (Action and $0FFF) = $0002;
end;

function WfpActionIsTerminating(Action: UINT32): Boolean;
begin
  Result := (Action and FWP_ACTION_FLAG_TERMINATING) <> 0;
end;

initialization
  // Layer GUIDs - from Microsoft documentation
  FWPM_LAYER_ALE_AUTH_CONNECT_V4         := StringToGUID('{c38d57d1-05a7-4c33-904f-7fbceee60e82}');
  FWPM_LAYER_ALE_AUTH_CONNECT_V6         := StringToGUID('{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}');
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4     := StringToGUID('{e1cd9fe7-f4b5-4273-96c0-592e487b8650}');
  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6     := StringToGUID('{a3b42c97-9f04-4672-b87e-cee9c483257f}');
  FWPM_LAYER_OUTBOUND_TRANSPORT_V4       := StringToGUID('{09e61aea-d214-46e2-9b21-b26b0b2f28c8}');
  FWPM_LAYER_OUTBOUND_TRANSPORT_V6       := StringToGUID('{e4a8b27f-b3ef-4f26-b53d-8ed5d97a3698}');
  FWPM_LAYER_INBOUND_TRANSPORT_V4        := StringToGUID('{5926dfc8-e3cf-4426-a283-dc393f5d0f9d}');
  FWPM_LAYER_INBOUND_TRANSPORT_V6        := StringToGUID('{634a869f-fc23-4b90-b0c1-bf620a36ae6f}');
  FWPM_LAYER_ALE_AUTH_LISTEN_V4          := StringToGUID('{88bb5dad-76d7-4227-9c71-df0a3ed7be7e}');
  FWPM_LAYER_ALE_AUTH_LISTEN_V6          := StringToGUID('{7ac9de24-17dd-4814-b4bd-a9fbc95a321b}');

  // Condition Field Key GUIDs - from Microsoft documentation
  FWPM_CONDITION_ALE_APP_ID              := StringToGUID('{d78e1e87-8644-4ea5-9437-d809ecefc971}');
  FWPM_CONDITION_IP_LOCAL_ADDRESS        := StringToGUID('{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}');
  FWPM_CONDITION_IP_REMOTE_ADDRESS       := StringToGUID('{b235ae9a-1d64-49b8-a44c-5ff3d9095045}');
  FWPM_CONDITION_IP_LOCAL_PORT           := StringToGUID('{0c1ba1af-5765-453f-af22-a8f4fe262c62}');
  FWPM_CONDITION_IP_REMOTE_PORT          := StringToGUID('{c35a604d-d22b-4e1a-91b4-68f674ee674b}');
  FWPM_CONDITION_IP_PROTOCOL             := StringToGUID('{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}');
  FWPM_CONDITION_ALE_USER_ID             := StringToGUID('{af043a0a-b34d-4f86-979c-c90371af6e66}');
  FWPM_CONDITION_ALE_PACKAGE_ID          := StringToGUID('{71bc78fa-f17c-4997-a602-6abb261f351c}');

end.
