#include "stdafx.h"

#include "sami.h"

EXTERN_C_START
PVOID __imp_SamiIsShadowAdminAccount = 0, __imp_SamiFindOrCreateShadowAdminAccount = 0;
EXTERN_C_END

#define GetApi(hmod, name) (__imp_##name = GetProcAddress(hmod, #name))

NTSTATUS ExecConsent();

BOOLEAN IsShadowAdminApiPresent()
{
	if (IsDebuggerPresent()) __debugbreak();
	if (HMODULE hmod = GetModuleHandleW(L"samlib.dll"))
	{
		if (GetApi(hmod, SamiFindOrCreateShadowAdminAccount) && GetApi(hmod, SamiIsShadowAdminAccount))
		{
			return TRUE;
		}
	}

	return FALSE;
}

EXTERN_C PVOID __imp_ShellExecuteExW = 0;

STDAPI DllRegisterServer()
{
	if (IsShadowAdminApiPresent())
	{
		//MessageBoxW(0, 0, 0, 0);
		BOOLEAN b;
		if (0 <= RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b))
		{
			return ExecConsent();
		}

		if (PCWSTR cmd = wcschr(GetCommandLineW(), '\"'))
		{
			if (HMODULE hmod = LoadLibraryW(L"shell32.dll"))
			{
				if (GetApi(hmod, ShellExecuteExW))
				{
					WCHAR app[MAX_PATH];
					if (UINT len = GetModuleFileNameW(0, app, _countof(app)))
					{
						SHELLEXECUTEINFOW sei = {
							sizeof(sei), 0, 0, L"runas", app, cmd, 0, SW_SHOW
						};

						if (ShellExecuteExW(&sei)) return S_OK;
					}
				}
			}
		}
	}

	return E_FAIL;
}

NTSTATUS ExecShadowAdmin();

VOID NTAPI ExecAdmin(_In_opt_ PVOID , _In_opt_ PVOID , _In_opt_ PVOID )
{
	if (IsShadowAdminApiPresent())
	{
		ExecShadowAdmin();
	}
}

BOOLEAN NTAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID /*lpReserved*/)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		LdrDisableThreadCalloutsForDll(hInstance);
		if ('\n' == *GetCommandLineW())
		{
			if (IsDebuggerPresent()) __debugbreak();
			ZwQueueApcThread(NtCurrentThread(), ExecAdmin, 0, 0, 0);
		}
		break;
	}

	return TRUE;
}