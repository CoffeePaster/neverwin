#pragma once

#include <cstddef>

typedef char               i8;
typedef short              i16;
typedef int                i32;
typedef long long          i64;

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

static_assert(sizeof(i8) == 1,  "Basic type i8 has wrong size");
static_assert(sizeof(i16) == 2, "Basic type i16 has wrong size");
static_assert(sizeof(i32) == 4, "Basic type i32 has wrong size");
static_assert(sizeof(i64) == 8, "Basic type i64 has wrong size");

static_assert(sizeof(u8) == 1,  "Basic type u8 has wrong size");
static_assert(sizeof(u16) == 2, "Basic type u16 has wrong size");
static_assert(sizeof(u32) == 4, "Basic type u32 has wrong size");
static_assert(sizeof(u64) == 8, "Basic type u64 has wrong size");

struct WinUnicodeString {
  u16 length;
  u16 maxlen;
  wchar_t* buffer;
};

#pragma pack(push, 1)

struct LDRDataTableEntry64 {
  LDRDataTableEntry64* next;
  u8                   _pad0[40];
  u8*                  base_address;
  u8                   _pad1[8];
  u64                  size;
  const WinUnicodeString name_full;
  const WinUnicodeString name;
};
static_assert(offsetof(LDRDataTableEntry64, next)         == 0x00, "");
static_assert(offsetof(LDRDataTableEntry64, base_address) == 0x30, "");
static_assert(offsetof(LDRDataTableEntry64, size)         == 0x40, "");
static_assert(offsetof(LDRDataTableEntry64, name_full)    == 0x48, "");

struct PEBLDRData64 {
  u8 _pad0[16];
  LDRDataTableEntry64* entry_order_load;
  u8 _pad1[8];
  LDRDataTableEntry64* entry_order_mem;
};
static_assert(offsetof(PEBLDRData64, entry_order_load) == 0x10, "");
static_assert(offsetof(PEBLDRData64, entry_order_mem)  == 0x20, "");

struct PEB64 {
  u8        _pad0[2];
  bool      being_debugged;
  u8        _pad1[21];
  PEBLDRData64* ldr_data;
  u8        _pad2[156];
  u32       nt_global_flag;
};
static_assert(offsetof(PEB64, being_debugged) == 0x02, "");
static_assert(offsetof(PEB64, ldr_data)       == 0x18, "");

#pragma pack(pop)