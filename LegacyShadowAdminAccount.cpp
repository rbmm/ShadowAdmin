NTSTATUS CuipGetClientLUID(_In_ HANDLE hToken, _Out_ PSID_AND_ATTRIBUTES LogonSid)
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

ULONG AccountNameToSid(_In_ PCWSTR lpAccountName, _Out_ PSID Sid, _In_ ULONG cbSid)
{
	SID_NAME_USE Use;
	WCHAR ReferencedDomainName[0x100];
	ULONG cch = _countof(ReferencedDomainName);

	return LookupAccountNameW(0, lpAccountName, Sid, &cbSid, ReferencedDomainName, &cch, &Use) ? NOERROR : GetLastError();
}

ULONG CuipGetShadowAdminAccountSuffix(_In_ PCWSTR lpAccountName, _Out_writes_(10) PWSTR buf)
{
	UCHAR Sid[SECURITY_MAX_SID_SIZE] = {}, hash[0x20];

	union {
		ULONG dwError;
		NTSTATUS status;
	};

	if (dwError = AccountNameToSid(lpAccountName, Sid, sizeof(Sid)))
	{
		return dwError;
	}

	if (0 > (status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, 0, 0, Sid, sizeof(Sid), hash, sizeof(hash))))
	{
		return RtlNtStatusToDosError(status);
	}

	*buf++ = '_';

	ULONG n = 8;
	PUCHAR pb = hash;

	do 
	{
		*buf++ = L"abcdefghijklmnopqrstuvwxyz0123456789"[*pb++ % 36];

	} while (--n);

	*buf = 0;

	return NOERROR;
}

NTSTATUS CuipHideShadowAdminFromLogonUi(PSID UserSid)
{
	SAM_HANDLE UserHandle, ServerHandle, DomainHandle;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status = SamConnect(0, &ServerHandle, SAM_SERVER_LOOKUP_DOMAIN, &oa);
	if (0 <= status)
	{
		PUCHAR pn = RtlSubAuthorityCountSid(UserSid);
		--*pn;
		status = SamOpenDomain(ServerHandle, DOMAIN_EXECUTE|DOMAIN_READ, UserSid, &DomainHandle);
		++*pn;
		SamCloseHandle(ServerHandle);
		if (0 <= status)
		{
			status = SamOpenUser(DomainHandle, USER_ALL_ACCESS, *RtlSubAuthoritySid(UserSid, *pn - 1), &UserHandle);
			SamCloseHandle(DomainHandle);
			if (0 <= status)
			{
				USER_EXTENDED_INFORMATION uei = { };
				//C_ASSERT(sizeof(USER_EXTENDED_INFORMATION) == 0xa8);
				uei.ExtendedWhichFields = USER_EXTENDED_FIELD_DONT_SHOW_IN_LOGON_UI;
				uei.DontShowInLogonUI = TRUE;
				status = SamSetInformationUser(UserHandle, UserExtendedInformation, &uei);
				SamCloseHandle(UserHandle);
			}
		}
	}
	return status;
}

// ?!?
#define UF_SHADOW_ADMIN_ACCOUNT         0x4000

ULONG AddUser(_In_ PCWSTR username)
{
	USER_INFO_4 ui = { };
	ui.usri4_name = const_cast<PWSTR>(username);
	ui.usri4_priv = USER_PRIV_ADMIN;
	ui.usri4_flags = UF_DONT_EXPIRE_PASSWD|UF_SHADOW_ADMIN_ACCOUNT|UF_PASSWD_CANT_CHANGE|UF_PASSWD_NOTREQD|UF_SCRIPT;
	ui.usri4_full_name = const_cast<PWSTR>(L"");
	ui.usri4_logon_server = const_cast<PWSTR>(L"\\\\*");
	ui.usri4_primary_group_id = DOMAIN_GROUP_RID_USERS;
	ui.usri4_acct_expires = TIMEQ_FOREVER;
	ui.usri4_max_storage = USER_MAXSTORAGE_UNLIMITED;

	//SamConnect
	//SamOpenDomain()
	//SamCreateUser2InDomain(USER_NORMAL_ACCOUNT)
	//SamQueryInformationUser
	//SamSetInformationUser

	// always fail due UF_SHADOW_ADMIN_ACCOUNT flag !!
	return NetUserAdd(0, 4, (BYTE*)&ui, 0);
}

NTSTATUS CreateShadowAdminLink(_In_ HANDLE hAdminToken, _In_ HANDLE hUserHandle)
{
	ULONG cb;
	HANDLE hLinkedToken;
	NTSTATUS status = NtQueryInformationToken(hAdminToken, TokenLinkedToken, &hLinkedToken, sizeof(hLinkedToken), &cb);

	if (0 <= status)
	{
		status = NtSetInformationToken(hLinkedToken, (TOKEN_INFORMATION_CLASS)-2, &hUserHandle, sizeof(hUserHandle));
		NtClose(hLinkedToken);
	}

	return status;
}

ULONG CuipCreateAutomaticAdminAccount(_In_ HANDLE hToken, _Outptr_ PHANDLE TokenHandle)
{
	if (ImpersonateLoggedOnUser(hToken))
	{
		WCHAR AccountName[0x100+10], *username;
		ULONG cch = _countof(AccountName);
		BOOL fOk = GetUserNameExW(NameSamCompatible, AccountName, &cch);
		RevertToSelf();
		if (fOk)
		{
			union {
				ULONG dwError;
				NTSTATUS status;
			};

			if (NOERROR == (dwError = CuipGetShadowAdminAccountSuffix(AccountName, AccountName + cch)))
			{
				if (username = wcsrchr(AccountName, '\\'))
				{
					username++;
				}
				else
				{
					username = AccountName;
				}

				PUSER_INFO_4 pui = 0;
				switch (dwError = NetUserGetInfo(0, username, 4, (BYTE**)&pui))
				{
				case NERR_UserNotFound:
					if (NOERROR == (dwError = AddUser(username))) {
				case NOERROR:
					NetApiBufferFree(pui);
					UCHAR Sid[SECURITY_MAX_SID_SIZE] = {};

					LOCALGROUP_MEMBERS_INFO_0 mi = { Sid };
					if (NOERROR == (dwError = AccountNameToSid(AccountName, Sid, sizeof(Sid))))
					{
						status = CuipHideShadowAdminFromLogonUi(Sid);
						// SamConnect 
						// SamOpenDomain
						// SamLookupNamesInDomain
						// SamOpenAlias
						// SamAddMemberToAlias
						switch (dwError = NetLocalGroupAddMembers(0, L"Administrators", 0, (PBYTE)&mi, 1))
						{
						case NOERROR:
						case ERROR_MEMBER_IN_ALIAS:
							//[S-1-2-0] '\LOCAL' [WellKnownGroup] really exist yet here
							TOKEN_GROUPS LocalGroups = { 1, { Sid } };
							if (0 <= (status = CuipGetClientLUID(hToken, LocalGroups.Groups)))
							{
								if (LogonUserExExW(username, L".", L"", 
									LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
									&LocalGroups, TokenHandle, 0, 0, 0, 0))
								{
									// always fail !!
									if (0 > (status = CreateShadowAdminLink(*TokenHandle, hToken)))
									{
										NtClose(*TokenHandle);
									}
								}
								else
								{
									dwError = GetLastError();
								}
							}
							break;
						}
					}}
					break;
				}
			}

			return dwError;
		}
	}

	return GetLastError();
}

NTSTATUS CuipGetElevatedToken(_In_ HANDLE hToken, _Outptr_ PHANDLE TokenHandle)
{
	ULONG cb;
	return NtQueryInformationToken(hToken, TokenLinkedToken, TokenHandle, sizeof(HANDLE), &cb);
}

NTSTATUS SetProcessOptions()
{
	HANDLE LsaHandle;
	NTSTATUS status = LsaConnectUntrusted(&LsaHandle), SubStatus;
	if (0 <= status)
	{
		ULONG ulAuthPackage;
		LSA_STRING PackageName;
		RtlInitString(&PackageName, MSV1_0_PACKAGE_NAME);
		if (0 <= (status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &ulAuthPackage)))
		{
			PVOID ProtocolReturnBuffer = 0;
			ULONG ReturnBufferLength;
			MSV1_0_SETPROCESSOPTION_REQUEST spo = {
				MsV1_0SetProcessOption, MSV1_0_OPTION_ALLOW_BLANK_PASSWORD|MSV1_0_OPTION_DISABLE_ADMIN_LOCKOUT, FALSE
			};

			if (0 <= (status = LsaCallAuthenticationPackage(
				LsaHandle, ulAuthPackage, &spo, sizeof(spo), 
				&ProtocolReturnBuffer, &ReturnBufferLength, &SubStatus)))
			{
				status = SubStatus;
			}

			if (ProtocolReturnBuffer) LsaFreeReturnBuffer(ProtocolReturnBuffer);
		}

		LsaDeregisterLogonProcess(LsaHandle);
	}
	return status;
}

ULONG GetCredentials(_Outptr_ PHANDLE TokenHandle)
{
	HANDLE LsaHandle;

	NTSTATUS SubStatus, status = LsaConnectUntrusted(&LsaHandle);

	if (STATUS_SUCCESS == status)
	{
		ULONG AuthPackage, ulOutAuthBufferSize;
		PVOID pvOutAuthBuffer;
		LSA_STRING lsaOriginName = RTL_CONSTANT_STRING("CredProvConsent");
		TOKEN_SOURCE tokenSource {};

		CREDUI_INFO ci = { sizeof(ci), 0, 0, L"" };

		// AttemptLogon -> AttemptCredProvLogon
		while (NOERROR == (status = CredUIPromptForWindowsCredentialsW(&ci, status, 
			&AuthPackage, 0, 0, &pvOutAuthBuffer, &ulOutAuthBufferSize, 0, CREDUIWIN_ENUMERATE_ADMINS)))
		{
			PVOID ProfileBuffer = 0;
			ULONG ulProfileBufferLen;
			LUID LogonId;
			QUOTA_LIMITS Quotas;

			status = LsaLogonUser(LsaHandle, &lsaOriginName, Interactive, AuthPackage, 
				pvOutAuthBuffer, ulOutAuthBufferSize,
				0, 
				&tokenSource,
				&ProfileBuffer,
				&ulProfileBufferLen,
				&LogonId,
				TokenHandle,
				&Quotas,
				&SubStatus);

			if (0 > status)
			{
				status = RtlNtStatusToDosError(SubStatus ? SubStatus : status);
				LocalFree(pvOutAuthBuffer);
				continue;
			}

			LsaFreeReturnBuffer(ProfileBuffer);
			break;
		}

		LsaDeregisterLogonProcess(LsaHandle);
		return status;
	}

	return RtlNtStatusToDosError(status);
}

ULONG CuiGetTokenForApp(BOOL bUseShadowAdmin, _Outptr_ PHANDLE TokenHandle)
{
	HANDLE hToken, hShadowToken;
	ULONG dwError = GetCredentials(&hToken);

	if (NOERROR == dwError)
	{
		if (bUseShadowAdmin)
		{
			if (NOERROR == (dwError = CuipCreateAutomaticAdminAccount(hToken, &hShadowToken)))
			{
				NtClose(hToken);
				hToken = hShadowToken;
			}
			else
			{
				goto __exit;
			}
		}

		dwError = CuipGetElevatedToken(hToken, TokenHandle);
__exit:
		NtClose(hToken);
	}

	return dwError;
}
