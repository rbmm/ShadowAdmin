BOOLEAN LsapShadowAdminEnabled;
BOOLEAN __WilFeatureTraits_Feature_AdminlessElevatedToken;

BOOLEAN LsapIsShadowAdminUser(PCWSTR username)
{
	if (LsapShadowAdminEnabled && __WilFeatureTraits_Feature_AdminlessElevatedToken)
	{
		PUSER_INFO_1 pui;

		if (NOERROR == NetUserGetInfo(0, username, 1, (BYTE**)&pui))
		{
			ULONG usri1_flags = pui->usri1_flags;

			NetApiBufferFree(pui);

			return (usri1_flags & UF_SHADOW_ADMIN_ACCOUNT) != 0;
		}
	}

	return FALSE;
}

BOOLEAN LsapIsShadowAdminUser(PSID Sid)
{
	BOOLEAN b;
	PWSTR username;
	if (0 <= SamiIsShadowAdminAccount(Sid, &b, &username, &Sid))
	{
		if (b)
		{
			SamFreeMemory(username);
			SamFreeMemory(Sid);
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN LsapIsProcessOnShadowAdminAllowList(ULONG dwProcessId)
{
	BOOLEAN fOk = FALSE;
	if (HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId))
	{
		WCHAR ExeName[MAX_PATH], buf[MAX_PATH];
		ULONG cch = _countof(ExeName);

		if (QueryFullProcessImageNameW(hProcess, 0, ExeName, &cch))
		{
			if (cch = GetWindowsDirectoryW(buf, _countof(buf)))
			{
				fOk = (!wcscpy_s(buf + cch, _countof(buf) - cch, L"\\System32\\Consent.exe") &&
					!_wcsicmp(ExeName, buf)) || 
					(!wcscpy_s(buf + cch, _countof(buf) - cch, L"\\System32\\Lsass.exe") &&
					!_wcsicmp(ExeName, buf));
			}
		}

		NtClose(hProcess);
	}

	return fOk;
}

BOOLEAN LsapCanLogonShadowAdmin(HANDLE hToken, ULONG dwProcessId)
{
	ULONG cb;
	union {
		TOKEN_MANDATORY_LABEL sml;
		UCHAR buf[TOKEN_INTEGRITY_LEVEL_MAX_SIZE];
		SE_TOKEN_USER stu;
	};

	if (GetTokenInformation(hToken, TokenIntegrityLevel, &sml, sizeof(buf), &cb) &&
		SECURITY_MANDATORY_SYSTEM_RID <= *GetSidSubAuthority(sml.Label.Sid, *GetSidSubAuthorityCount(sml.Label.Sid) - 1) &&
		GetTokenInformation(hToken, TokenUser, &stu, sizeof(stu), &cb))
	{
		SID LocalSystem = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, { SECURITY_LOCAL_SYSTEM_RID }};

		if (RtlEqualSid(&LocalSystem, stu.TokenUser.User.Sid))
		{
			return LsapIsProcessOnShadowAdminAllowList(dwProcessId);
		}
	}

	return FALSE;
}

NTSTATUS CheckForShadowAdmin(PCWSTR username, PSID Sid, HANDLE hToken, ULONG dwProcessId)
{
	if (LsapIsShadowAdminUser(username) || LsapIsShadowAdminUser(Sid))
	{
		if (!LsapShadowAdminEnabled || LsapCanLogonShadowAdmin(hToken, dwProcessId)) 
		{
			return STATUS_ACCESS_DENIED;
		}
	}

	return STATUS_SUCCESS;
}