#include "stdafx.h"

EXTERN_C_START

NTSYSCALLAPI
NTSTATUS
NTAPI
SamiFindOrCreateShadowAdminAccount(_In_ PSID UserSid, _Out_ PWSTR* AdminName, _Out_ PSID ShadowSid);

NTSYSCALLAPI
NTSTATUS
NTAPI
SamiIsShadowAdminAccount(_In_ PSID ShadowSid, _Out_ PBOOLEAN pbShadow, _Out_ PWSTR* AdminName, _Out_ PSID UserSid);

#ifdef _X86_

#pragma warning(disable: 4483) // Allow use of __identifier

#define __imp_SamiFindOrCreateShadowAdminAccount __identifier("_imp__SamiFindOrCreateShadowAdminAccount@12")
#define __imp_SamiIsShadowAdminAccount __identifier("_imp__SamiIsShadowAdminAccount@16")

#endif

PVOID __imp_SamiIsShadowAdminAccount = 0, __imp_SamiFindOrCreateShadowAdminAccount = 0;

#define GetApi(hmod, name) (__imp_##name = GetProcAddress(hmod, #name))

EXTERN_C_END

class WLog
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;

	PWSTR _buf()
	{
		return (PWSTR)_BaseAddress + _Ptr;
	}

	ULONG _cch()
	{
		return _RegionSize - _Ptr;
	}

public:
	void operator >> (HWND hwnd)
	{
		PVOID pv = (PVOID)SendMessage(hwnd, EM_GETHANDLE, 0, 0);
		SendMessage(hwnd, EM_SETHANDLE, (WPARAM)_BaseAddress, 0);
		_BaseAddress = 0;
		if (pv)
		{
			LocalFree(pv);
		}
	}

	WLog& operator << (PSID Sid)
	{
		UNICODE_STRING StringSid;
		if (0 <= RtlConvertSidToUnicodeString(&StringSid, Sid, TRUE))
		{
			operator << (&StringSid);
			RtlFreeUnicodeString(&StringSid);
		}
		return *this;
	}

	WLog& operator << (PCUNICODE_STRING pus)
	{
		ULONG cb = pus->Length;
		ULONG len = cb / sizeof(WCHAR);
		if (_cch() > len)
		{
			memcpy(_buf(), pus->Buffer, cb);
			_Ptr += len;
			*_buf() = 0;
		}
		return *this;
	}

	WLog& operator << (PCWSTR pcsz)
	{
		SIZE_T len = wcslen(pcsz) + 1;
		if (_cch() >= len)
		{
			memcpy(_buf(), pcsz, len * sizeof(WCHAR));
			_Ptr += (ULONG)len - 1;
		}
		return *this;
	}

	WLog& operator << (WCHAR c)
	{
		if (_cch() > 1)
		{
			PWSTR buf = _buf();
			*buf++ = c, *buf = 0;
			_Ptr++;
		}

		return *this;
	}

	ULONG Init(SIZE_T RegionSize)
	{
		if (_BaseAddress = LocalAlloc(0, RegionSize))
		{
			_RegionSize = (ULONG)RegionSize / sizeof(WCHAR), _Ptr = 0;
			return NOERROR;
		}
		return GetLastError();
	}

	~WLog()
	{
		if (_BaseAddress)
		{
			LocalFree(_BaseAddress);
		}
	}

	WLog(WLog&&) = delete;
	WLog(WLog&) = delete;
	WLog() : _BaseAddress(0) {  }

	operator PCWSTR()
	{
		return (PCWSTR)_BaseAddress;
	}

	WLog& operator ()(PCWSTR format, ...)
	{
		va_list args;
		va_start(args, format);

		int len = _vsnwprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

		if (0 < len)
		{
			_Ptr += len;
		}

		va_end(args);

		return *this;
	}

	WLog& operator[](NTSTATUS dwError)
	{
		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return *this;
		LPCVOID lpSource = ghnt;
		ULONG dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS;

		if (dwFlags = FormatMessageW(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
		{
			_Ptr += dwFlags;
		}
		return *this;
	}
};

NTSTATUS EnumShadowAdmins(WLog& log)
{
	SAM_HANDLE ServerHandle, DomainHandle, AliasHandle;
	OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status = SamConnect(0, &ServerHandle, SAM_SERVER_LOOKUP_DOMAIN, &oa);
	if (0 <= status)
	{
		SID BUILTIN = { SID_REVISION, 1, SECURITY_NT_AUTHORITY, {SECURITY_BUILTIN_DOMAIN_RID } };

		status = SamOpenDomain(ServerHandle, DOMAIN_EXECUTE | DOMAIN_READ, &BUILTIN, &DomainHandle);
		SamCloseHandle(ServerHandle);

		if (0 <= status)
		{
			status = SamOpenAlias(DomainHandle, ALIAS_LIST_MEMBERS, DOMAIN_ALIAS_RID_ADMINS, &AliasHandle);
			SamCloseHandle(DomainHandle);

			if (0 <= status)
			{
				ULONG MemberCount;
				PSID* MemberIds, UserSid, Sid;
				status = SamGetMembersInAlias(AliasHandle, &MemberIds, &MemberCount);
				SamCloseHandle(AliasHandle);

				if (0 <= status)
				{
					PVOID buf = MemberIds;
					if (MemberCount)
					{
						LSA_HANDLE PolicyHandle;
						NTSTATUS s = LsaOpenPolicy(0, &oa, POLICY_LOOKUP_NAMES, &PolicyHandle);

						do
						{
							BOOLEAN bShadowAdmin;
							PWSTR Name;
							if (0 <= SamiIsShadowAdminAccount(Sid = *MemberIds++, &bShadowAdmin, &Name, &UserSid))
							{
								if (bShadowAdmin)
								{
									PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;
									PLSA_TRANSLATED_NAME Names = 0;
									PCUNICODE_STRING UserName = 0, DomainName = 0;
									if (0 <= s && 0 <= LsaLookupSids2(PolicyHandle, 0, 1, &UserSid, &ReferencedDomains, &Names))
									{
										UserName = &Names->Name;
										ULONG DomainIndex = Names->DomainIndex;
										if (DomainIndex < ReferencedDomains->Entries)
										{
											DomainName = &ReferencedDomains->Domains[DomainIndex].Name;
										}
									}

									WCHAR sz1[SECURITY_MAX_SID_STRING_CHARACTERS], sz2[SECURITY_MAX_SID_STRING_CHARACTERS];
									UNICODE_STRING us1 = { 0, sizeof(sz1), sz1 }, us2 = { 0, sizeof(sz2), sz2 };
									RtlConvertSidToUnicodeString(&us1, Sid, FALSE);
									RtlConvertSidToUnicodeString(&us2, UserSid, FALSE);
									log(L"%ws[%wZ] -> %wZ\\%wZ [%wZ]\r\n", Name, &us1, DomainName, UserName, &us2);
									SamFreeMemory(UserSid);
									SamFreeMemory(Name);
								}
							}
						} while (--MemberCount);

						if (0 <= s)
						{
							LsaClose(PolicyHandle);
						}
					}
					SamFreeMemory(buf);
				}
			}
		}

	}
	return status;
}

void WINAPI ep(void*)
{
	WLog log;
	if (!log.Init(0x10000))
	{
		if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"Shadow Admins",
			WS_OVERLAPPEDWINDOW | WS_HSCROLL | WS_VSCROLL | ES_MULTILINE,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, HWND_DESKTOP, 0, 0, 0))
		{
			static const int
				X_index[] = { SM_CXSMICON, SM_CXICON },
				Y_index[] = { SM_CYSMICON, SM_CYICON },
				icon_type[] = { ICON_SMALL, ICON_BIG };

			ULONG i = _countof(icon_type) - 1;

			HICON hii[2]{};
			do
			{
				HICON hi;

				if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1),
					GetSystemMetrics(X_index[i]), GetSystemMetrics(Y_index[i]), &hi))
				{
					hii[i] = hi;
				}
			} while (i--);

			HFONT hFont = 0;
			NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
			if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
			{
				wcscpy(ncm.lfMessageFont.lfFaceName, L"Courier New");
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;
				ncm.lfMessageFont.lfWeight = FW_NORMAL;
				ncm.lfMessageFont.lfQuality = CLEARTYPE_QUALITY;
				ncm.lfMessageFont.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
				ncm.lfMessageFont.lfHeight = -ncm.iMenuHeight;

				hFont = CreateFontIndirect(&ncm.lfMessageFont);
			}

			if (hFont) SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, 0);

			ULONG n = 8;
			SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);

			if (HMODULE hmod = LoadLibraryW(L"samlib.dll"))
			{
				if (GetApi(hmod, SamiFindOrCreateShadowAdminAccount) && GetApi(hmod, SamiIsShadowAdminAccount))
				{
					if (NTSTATUS status = EnumShadowAdmins(log))
					{
						log[status];
					}
				}
				else
				{
					log << L"Fail get Shadow Admin API\r\n";
				}
			}

			log >> hwnd;

			SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hii[0]);
			SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hii[1]);

			ShowWindow(hwnd, SW_SHOWNORMAL);

			MSG msg;
			while (IsWindow(hwnd) && 0 < GetMessageW(&msg, 0, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}

			if (hFont) DeleteObject(hFont);

			i = _countof(hii);
			do
			{
				if (HICON hi = hii[--i])
				{
					DestroyIcon(hi);
				}
			} while (i);
		}
	}
	ExitProcess(0);
}
