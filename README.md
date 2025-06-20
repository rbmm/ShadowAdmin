# ShadowAdmin

based on https://specterops.io/blog/2025/06/18/administrator-protection/

samlib.dll (client dll to samsrv.dll) now export 2 new API

```
EXTERN_C_START

NTSYSCALLAPI
NTSTATUS
NTAPI
SamiFindOrCreateShadowAdminAccount(_In_ PSID UserSid, _Out_ PWSTR* AdminName, _Out_ PSID ShadowSid);

NTSYSCALLAPI
NTSTATUS
NTAPI
SamiIsShadowAdminAccount(_In_ PSID ShadowSid, _Out_ PBOOLEAN pbShadow, _Out_ PWSTR* AdminName, _Out_ PSID UserSid);

EXTERN_C_END
```

( AdminName, and UserSid on return , need free with SamFreeMemory api)

demo usage is 

```
EXTERN_C_START

PVOID __imp_SamiIsShadowAdminAccount = 0, __imp_SamiFindOrCreateShadowAdminAccount = 0;

EXTERN_C_END

#define GetApi(hmod, name) (__imp_##name = GetProcAddress(hmod, #name))

void TestNewApi(PSID UserSid)
{
	PSID ShadowSid;
	PWSTR AdminName;
	BOOLEAN bShadow;
	NTSTATUS status = SamiFindOrCreateShadowAdminAccount(UserSid, &AdminName, &ShadowSid);
	if (0 <= status)
	{
		DbgPrint("AdminName=\"%ws\"\n", AdminName);
		SamFreeMemory(AdminName);
		status = SamiIsShadowAdminAccount(ShadowSid, &bShadow, &AdminName, &UserSid);
		SamFreeMemory(ShadowSid);
		if (0 <= status && bShadow)
		{
			DbgPrint("AdminName=\"%ws\"\n", AdminName);
			SamFreeMemory(AdminName);
			SamFreeMemory(UserSid);
		}
	}
}

BOOLEAN IsShadowAdminApiPresent()
{
	if (HMODULE hmod = GetModuleHandleW(L"samlib.dll"))
	{
		if (GetApi(hmod, SamiFindOrCreateShadowAdminAccount) && GetApi(hmod, SamiIsShadowAdminAccount))
		{
			return TRUE;
		}
	}

	return FALSE;
}
```

## How Do Users Get a Shadow Account Token?

consent.exe call
```
ULONG CuipGetElevatedToken(_Out_ PHANDLE phToken);
```

which internal simply call `NtQueryInformationToken` with `TokenLinkedToken`

during this call, in kernel called `SepLogonSystemManagedAdmin` (in `ntoskrnl.exe`) and it call `KsecLogonSystemManagedAdmin` in `ksecdd.sys`
it do RPC (via ALPC) call to lsass.exe - `SspirLogonSystemManagedAdmin` (in `SspiSrv.dll` )

![stack](pa7.png)

```
NTSTATUS SspiExLogonSystemManagedAdmin(_In_ PLSA_CLIENT_REQUEST ClientRequest, _In_ PCLIENT_ID cid, _In_ LUID Luid, _Out_ PHANDLE phToken);
```

this function call 

```
NTSTATUS LsapAuApiDispatchLogonSystemManagedAdmin( _In_ LUID Luid, _Out_ PHANDLE phToken);
```

inside lsasrv.dll

and here called `SamiFindOrCreateShadowAdminAccount(,&AdminName, )` and `LogonUserExExW(AdminName, L".", L"", ...)`

( user Sid is taken from token associated with Luid )

if user logon ( by auth package) is ok, lsasrv call `LsapIsShadowAdminUser` (exist 2 variants of this api, which take user SID or name)
and if yes, `LsapCanLogonShadowAdmin` called, which check some conditions, in particular `LsapIsProcessOnShadowAdminAllowList`
this function check that caller process name is consent.exe or lsass.exe ( in our concrete case, this is lsass.exe )

![LsapCanLogonShadowAdmin](pa9.png)

really this is very weak check, because no problem exec by self new consent.exe or lsass.exe and inject to it self code, which call `LogonUserExExW` or `LsaLogonUser`

as demo, SAU project - start consent.exe, inject to it own dll and call LsaLogonUser, if found Shadow admin account. it token get - then start cmd and in it whoami

of course we need from begin have elevated admin or local system token. so this is not privilege escalation - we already have all at begin. this is only show that no sense check caller process name

run [demo.bat](https://github.com/rbmm/ShadowAdmin/blob/main/x64/Release/demo.bat) for test

the complete trace of [SspiExLogonSystemManagedAdmin](https://github.com/rbmm/TVI/blob/main/DEMO/SspirLogonSystemManagedAdmin.tvi)
it can be looked with [tvi.exe](https://github.com/rbmm/TVI/blob/main/X64/tvi.exe) tool