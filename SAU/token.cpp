#include "stdafx.h"

#define label(x) _CRT_CONCATENATE(x, __LINE__)

#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }

#define END_PRIVILEGES }};};

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof(sqos), SecurityDelegation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

#define echo(x) x
#define showmacro(x) __pragma(message(__FILE__ _CRT_STRINGIZE((__LINE__): \t) #x " =>\n" _CRT_STRINGIZE(x)))

HRESULT GetLastHrEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS GetToken(_Out_ PHANDLE TokenHandle, _In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet, _In_ BOOL bImpersonate = FALSE)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_DUPLICATE | 
						TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT,
						0, FALSE, TokenPrimary, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)
						{
							if (bImpersonate)
							{
								if (0 <= (status = NtDuplicateToken(hNewToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
									const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hToken)))
								{
									status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
									NtClose(hToken);
								}

								if (0 > status)
								{
									NtClose(hNewToken);
									return status;
								}
							}
							*TokenHandle = hNewToken;
							return STATUS_SUCCESS;
						}

						NtClose(hNewToken);

					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS GetToken(_Out_ PHANDLE TokenHandle, _In_ const TOKEN_PRIVILEGES* RequiredSet, _In_ BOOL bImpersonate = FALSE)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = GetToken(TokenHandle, buf, RequiredSet, bImpersonate);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete[] buf;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

NTSTATUS ExecConsent()
{
	BEGIN_PRIVILEGES(tp_ai, 2)
		LAA(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE),
		LAA(SE_INCREASE_QUOTA_PRIVILEGE),
	END_PRIVILEGES;

	HANDLE hToken;
	NTSTATUS status;
	WCHAR app[MAX_PATH];
	static const WCHAR consent[] = L"\\system32\\consent.exe";
	if (UINT len = GetWindowsDirectoryW(app, _countof(app) - _countof(consent)))
	{
		wcscpy(app + len, consent);
		if (STATUS_SUCCESS == (status = GetToken(&hToken, &tp_ai, TRUE)))
		{
			ULONG SessionId = RtlGetCurrentPeb()->SessionId;
			NtSetInformationToken(hToken, TokenSessionId, &SessionId, sizeof(SessionId));

			STARTUPINFOW si = { sizeof(si) };
			PROCESS_INFORMATION pi;
			if (CreateProcessAsUserW(hToken, app, const_cast<PWSTR>(L"\n"), 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
			{
				if (PWSTR psz = new WCHAR[0x8000])
				{
					ULONG cb = (GetModuleFileNameW((HMODULE)&__ImageBase, psz, 0x8000) + 1) * sizeof(WCHAR);
					if (!GetLastError())
					{
						PVOID BaseAddress = 0;
						SIZE_T RegionSize = cb;
						if (0 <= (status = ZwAllocateVirtualMemory(pi.hProcess, &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE)) &&
							0 <= (status = ZwWriteVirtualMemory(pi.hProcess, BaseAddress, psz, cb, 0)) &&
							0 <= (status = ZwQueueApcThread(pi.hThread, (PPS_APC_ROUTINE)LoadLibraryExW, BaseAddress, 0, 0)) &&
							0 <= (status = ZwQueueApcThread(pi.hThread, (PPS_APC_ROUTINE)VirtualFree, BaseAddress, 0, (void*)MEM_RELEASE)))
						{
							__nop();
						}
					}

					delete[] psz;
				}
				;
				NtResumeThread(pi.hThread, 0);
				NtClose(pi.hThread);
				NtClose(pi.hProcess);
			}
			else
			{
				status = GetLastHrEx();
			}
			NtClose(hToken);
		}
	}
	else
	{
		status = GetLastHrEx();
	}

	return status;
}
