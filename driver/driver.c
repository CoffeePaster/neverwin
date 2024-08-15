#include "ntos.h"
#include "pe.h"

#define DEVICE_NAME L"neverw1n"
#define DATA_MAGIC  (*(uintptr_t*)"N3V3RW1N")

#define REQUEST_READ  1
#define REQUEST_WRITE 2
#define REQUEST_PEB   3

struct rw_request {
	uintptr_t magic;
	int request;
	HANDLE pid;
	PVOID addr;
	PVOID pbuf;
	SIZE_T size;
};

struct rw_request data_buffer;

__int64(__fastcall* xKdEnumerateDebuggingDevices_original)(__int64 a1, __int64* a2, __int64* a3);

PEPROCESS get_eprocess(HANDLE pid) {
	PEPROCESS process;
	if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
		return process;
	return 0;
}

ULONG copy_virtual_memory(PEPROCESS src_proc, PVOID src_addr, PEPROCESS dst_proc, PVOID dst_addr, SIZE_T size) {
	PSIZE_T bytes;
	return NT_SUCCESS(MmCopyVirtualMemory(src_proc, src_addr, dst_proc, dst_addr, size, KernelMode, &bytes));
}

bool probe_user_addr(uintptr_t addr, uintptr_t size, uintptr_t align) {
	return !(addr & (align - 1)) && (addr + size <= MmUserProbeAddress);
}

bool copy_data_buffer(uintptr_t src) {
	PEPROCESS current = PsGetCurrentProcess();
	return copy_virtual_memory(current, src, current, &data_buffer, sizeof(data_buffer));
}

__int64 __fastcall xKdEnumerateDebuggingDevices_hook(__int64 a1, __int64* a2, __int64* a3) {
	if (ExGetPreviousMode() == UserMode
		&& a1
		&& probe_user_addr(a1, sizeof(data_buffer), sizeof(DWORD))
		&& copy_data_buffer(a1)
		&& data_buffer.magic == DATA_MAGIC) {

		PEPROCESS process, current;
		PVOID addr;

		//DbgPrintEx(0, 0, "xKdEnumerateDebuggingDevices_hook: Mode => %d\n", data_buffer.request);

		switch (data_buffer.request) {
		case REQUEST_READ:
			current = PsGetCurrentProcess();
			process = get_eprocess(data_buffer.pid);
			if (process)
				return copy_virtual_memory(process, data_buffer.addr, current, data_buffer.pbuf, data_buffer.size);
			break;
		case REQUEST_WRITE:
			current = PsGetCurrentProcess();
			process = get_eprocess(data_buffer.pid);
			if (process)
				return copy_virtual_memory(current, data_buffer.pbuf, process, data_buffer.addr, data_buffer.size);
			break;
		case REQUEST_PEB:
			process = get_eprocess(data_buffer.pid);
			if (process) {
				current = PsGetCurrentProcess();
				addr    = PsGetProcessPeb(process);
				return copy_virtual_memory(current, &addr, current, data_buffer.pbuf, sizeof(addr));
			}
			break;
		default:
			break;
		}
		return 0;
	}

	return xKdEnumerateDebuggingDevices_original(a1, a2, a3);
}

uintptr_t rva(uintptr_t base, uintptr_t offset) {
	if (!base) return 0;
	uintptr_t rel = base + offset;
	return rel + *(int*)(rel - 4);
}

uintptr_t scan_code_section(uintptr_t pe_base, char* pattern, char* mask) {
	struct DOSHeader* dos = (struct DOSHeader*)pe_base;
	struct NTHeaders64* nt = (struct NTHeaders64*)(pe_base + dos->e_lfanew);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	struct SectionHeader* sections = (struct SectionHeader*)(nt + 1);
	ULONG mask_len = strlen(mask);

	for (ULONG i = 0; i < nt->NumberOfSections; i++) {
		struct SectionHeader* sect = &sections[i];

		if (sect->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			char* scan_base = pe_base + sect->VirtualAddress;

			for (ULONG j = 0; j < sect->Misc.VirtualSize; j++) {
				char* current = &scan_base[j];
				bool found = true;

				for (ULONG k = 0; k < mask_len; k++) {
					if (mask[k] == 'x' && current[k] != pattern[k]) {
						found = false;
						break;
					}
				}

				if (found)
					return (uintptr_t)current;
			}
		}
	}
	return 0;
}

uintptr_t get_ntoskrnl_base() {
	PVOID ntos_base = 0;
	RtlPcToFileHeader(RtlPcToFileHeader, &ntos_base);
	return (uintptr_t)ntos_base;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj, PUNICODE_STRING reg_path) {
	DbgPrintEx(0, 0, "Driver load\n");

	uintptr_t ntos_base = get_ntoskrnl_base();

	if (ntos_base) {
		uintptr_t xKdEnumerateDebuggingDevices = rva(scan_code_section(ntos_base, "\x48\x8B\x05\x00\x00\x00\x00\x75\x07\x48\x8B\x05\x00\x00\x00\x00\xE8", "xxx????xxxxx????x"), 7);

		if (xKdEnumerateDebuggingDevices)
			xKdEnumerateDebuggingDevices_original = InterlockedExchangePointer(xKdEnumerateDebuggingDevices, xKdEnumerateDebuggingDevices_hook);
		else
			DbgPrintEx(0, 0, "Failed: hook\n");
	}
	else
		DbgPrintEx(0, 0, "Failed: ntoskrnl base\n");

	return STATUS_SUCCESS;
}