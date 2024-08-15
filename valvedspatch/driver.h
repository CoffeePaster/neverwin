#pragma once

#include <Windows.h>
#include <cstdio>

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

	rw_request(int request, HANDLE pid, PVOID addr, PVOID pbuf, SIZE_T size)
	: magic(DATA_MAGIC),
	  request(request),
	  pid(pid),
	  addr(addr),
	  pbuf(pbuf),
	  size(size)
	{}
};

class drv_class
{
public:
	drv_class() {}

	bool init() {
		HMODULE ntdll = LoadLibraryA("ntdll.dll");
		if (!ntdll)
			return false;

		*(PVOID*)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter = GetProcAddress(ntdll, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
		return NtConvertBetweenAuxiliaryCounterAndPerformanceCounter != 0;
	}

	bool call_drv(PVOID pdata) {
		PVOID dum;
		return NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, &pdata, &dum, &dum);
	}

	bool read_virtual_memory(HANDLE pid, uintptr_t addr, PVOID buffer, SIZE_T size) {
		rw_request data(REQUEST_READ, pid, (PVOID)addr, buffer, size);
		return call_drv(&data);
	}

	bool write_virtual_memory(HANDLE pid, uintptr_t addr, PVOID buffer, SIZE_T size) {
		rw_request data(REQUEST_WRITE, pid, (PVOID)addr, buffer, size);
		return call_drv(&data);
	}

	template <typename T> T read_virtual_memory(HANDLE pid, uintptr_t addr) {
		T data = 0;
		read_virtual_memory(pid, addr, &data, sizeof(data));
		return data;
	}

	template <typename T> bool write_virtual_memory(HANDLE pid, uintptr_t addr, T value) {
		return write_virtual_memory(pid, addr, &value, sizeof(value));
	}

	uintptr_t get_process_peb(HANDLE pid) {
		PVOID peb_addr = 0;
		rw_request data(REQUEST_PEB, pid, 0, &peb_addr, 0);

		call_drv(&data);
		return (uintptr_t)peb_addr;
	}

private:
	HANDLE drv;
	__int64(__fastcall* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(char a1, PVOID* a2, PVOID* a3, PVOID* a4);
};