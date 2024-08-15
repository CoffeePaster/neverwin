#include "driver.h"
#include "peb.h"
#include <tlhelp32.h>
#include <string>
#include <cstdio>

#define CGAMERULES_OFFSET 0x181e048

HANDLE find_process(std::wstring_view name) {
	HANDLE pid = 0;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(entry);

		if (Process32First(snap, &entry)) {
			do {
				if (std::wstring_view(entry.szExeFile) == name) {
					pid = (HANDLE)entry.th32ProcessID;
					break;
				}
			} while (Process32Next(snap, &entry));
		}
		CloseHandle(snap);
	}
	return pid;
}

uintptr_t get_module_base_address(drv_class drv, HANDLE pid, const wchar_t* module_name) {
	uintptr_t peb = drv.get_process_peb(pid);

	if (!peb)
		return 0;

	uintptr_t ldr = drv.read_virtual_memory<uintptr_t>(pid, peb + offsetof(PEB64, ldr_data));

	if (!ldr)
		return 0;

	uintptr_t first = drv.read_virtual_memory<uintptr_t>(pid, ldr + offsetof(PEBLDRData64, entry_order_load));
	uintptr_t current = first;

	while (current) {
		LDRDataTableEntry64 data;
		if (!drv.read_virtual_memory(pid, current, &data, sizeof(data)))
			break;

		if (!data.base_address)
			break;

		wchar_t curname[256] = { 0 };
		if (!drv.read_virtual_memory(pid, (uintptr_t)data.name.buffer, curname, sizeof(curname) - 1))
			break;

		if (wcscmp(module_name, curname) == 0)
			return (uintptr_t)data.base_address;

		if ((uintptr_t)data.next == first)
			break;

		current = (uintptr_t)data.next;
	}
	return 0;
}

int main() {
	drv_class drv;
	if (!drv.init())
		return 0;

retry:
	printf("waiting for CS2...\n");

	HANDLE pid = find_process(L"cs2.exe");
	while (!pid) {
		Sleep(5000);
		pid = find_process(L"cs2.exe");
	}

	printf("CS2 pid -> %lld\n", (uintptr_t)pid);

	uintptr_t client = get_module_base_address(drv, pid, L"client.dll");
	while (!client) {
		Sleep(5000);
		client = get_module_base_address(drv, pid, L"client.dll");
	}

	printf("client -> 0x%016llx\n", client);

	uintptr_t game_rules = 0, prev_game_rules = 0;
	bool is_waiting = false;

	while (true) {
		if (!drv.read_virtual_memory(pid, client + CGAMERULES_OFFSET, &game_rules, sizeof(game_rules))) {
			printf("retrying...\n");
			Sleep(5000);
			goto retry;
		}

		if (!game_rules) {
			if (!is_waiting) {
				printf("waiting for game_rules...\n");
				is_waiting = true;
			}
			Sleep(5000);
			continue;
		}

		is_waiting = false;

		if (game_rules != prev_game_rules) {
			printf("game_rules -> 0x%016llx\n", game_rules);
			prev_game_rules = game_rules;
		}

#pragma pack(push, 1)
		struct pack_t {
			bool m_bIsQueuedMatchmaking; // 0x90	
			int m_nQueuedMatchmakingMode; // 0x94	
			bool m_bIsValveDS; // 0x98
		};
#pragma pack(pop)

		pack_t pack, zero = { 0 };

		if (drv.read_virtual_memory(pid, game_rules + 0x90, &pack, sizeof(pack))) {
			if (pack.m_bIsValveDS || pack.m_bIsQueuedMatchmaking || pack.m_nQueuedMatchmakingMode) {
				printf("%d %d %d, ",
					(int)pack.m_bIsValveDS,
					(int)pack.m_bIsQueuedMatchmaking,
					pack.m_nQueuedMatchmakingMode);

				if (drv.write_virtual_memory(pid, game_rules + 0x90, &zero, sizeof(zero)))
					printf("rule applied!\n");
			}
		}

		Sleep(5000);
	}

    return 0;
}

