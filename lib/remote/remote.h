#pragma once

#ifndef _REMOTE_PROCESS_H
#define _REMOTE_PROCESS_H

#include <string>
#include <vector>
#include <optional>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <functional>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

#define check_status() if (GetLastError()) {\
\
printf("Error occured 0x%p\n in %s", GetLastError( ), __FUNCTION__ );\
throw std::runtime_error("Exception occured!");\
getchar( );\
__fastfail(0); }\

#include "../pattern.h"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

#pragma optimize( "", off )

using procaddress_t = DWORD( __stdcall * )(HMODULE, LPCSTR);
using loadlibrary_t = HMODULE( __stdcall * )(LPCSTR);
using dll_main_fn = bool( __stdcall * )(void *base, std::size_t reason, void *data);

namespace bruiser::detail {
	// allocated at the BASE of our DLL
	struct _mm_data {
		std::intptr_t base;
		procaddress_t	proc;
		loadlibrary_t	load;
	};
}

__declspec(dllexport) void __stdcall shellcode( bruiser::detail::_mm_data *data ) {

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(data->base);

	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(data->base + dos->e_lfanew);

	dll_main_fn main = reinterpret_cast<dll_main_fn>(data->base + nt->OptionalHeader.AddressOfEntryPoint);

	BYTE *pBase = (BYTE *)data->base;

	auto pOptionalHeader = &nt->OptionalHeader;

	BYTE *LocationDelta = pBase - pOptionalHeader->ImageBase;
	if ( LocationDelta )
	{
		if ( !pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size )
		{
			data->base = (std::int32_t) main;
			return;
		}
			
		auto *pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while ( pRelocData->VirtualAddress )
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( WORD );
			WORD *pRelativeInfo = reinterpret_cast<WORD *>(pRelocData + 1);

			for ( UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo )
			{
				if ( RELOC_FLAG32( *pRelativeInfo ) )
				{
					UINT_PTR *pPatch = reinterpret_cast<UINT_PTR *>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if ( nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size )
	{
		auto *pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(pBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while ( pImportDescr->Name )
		{
			char *szMod = reinterpret_cast<char *>(pBase + pImportDescr->Name);
			HINSTANCE hDll = data->load( szMod );

			ULONG_PTR *pThunkRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR *pFuncRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDescr->FirstThunk);

			if ( !pThunkRef )
				pThunkRef = pFuncRef;

			for ( ; *pThunkRef; ++pThunkRef, ++pFuncRef )
			{
				if ( IMAGE_SNAP_BY_ORDINAL( *pThunkRef ) )
				{
					*pFuncRef = data->proc( hDll, reinterpret_cast<char *>(*pThunkRef & 0xFFFF) );
				}
				else
				{
					auto *pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(pBase + (*pThunkRef));
					*pFuncRef = data->proc( hDll, pImport->Name );
				}
			}
			++pImportDescr;
		}
	}

	if ( nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size )
	{
		auto *pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY *>(pBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto *pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		for ( ; pCallback && *pCallback; ++pCallback )
			(*pCallback)((void *)pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	main( (void *)pBase, DLL_PROCESS_ATTACH, data );
}

#pragma optimize( "", on )

namespace bruiser {

	namespace detail {

		using procaddress_t = DWORD( __stdcall * )(HMODULE, LPCSTR);
		using loadlibrary_t = HMODULE( __stdcall * )(LPCSTR);

		struct _module_info {
			char			_name[256];
			std::intptr_t	_base;
			std::size_t		_size;
		};


		struct _remote_memory_region {
			std::intptr_t	base;
			std::size_t		size;
			std::intptr_t	parent_base;
			char			parent_name[256];
		};

	}

	class c_remote_process {
	private:
		std::uintptr_t _pid;
		std::intptr_t  _handle;

		std::vector<detail::_module_info> _module_cache;
	public:

		// does what it do
		static auto find_process_by_name( const std::string &process ) -> std::optional<std::uint32_t> {
			auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

			if ( !snapshot )
				return std::nullopt;

			PROCESSENTRY32 pe = { 0 };
			pe.dwSize = sizeof PROCESSENTRY32;

			for ( Process32First( snapshot, &pe ); Process32Next( snapshot, &pe ); )
			{
				if ( std::strstr( pe.szExeFile, process.c_str( ) ) )
				{
					CloseHandle( snapshot );
					return pe.th32ProcessID;
				}
			}

			CloseHandle( snapshot );
			return std::nullopt;
		}

		auto inject_loadable_ntdetour( bruiser::c_loadable &loadable ) -> bool {

			// payload
			std::uint8_t hook[] = { 
				0x55,											// 0:  55                      push   ebp
				0x89, 0xE5,										// 1:  89 e5                   mov    ebp,esp
				0x68, 0xFF, 0xFF, 0xFF, 0x7F,					// 3:  68 ff ff ff 7f          push   0x7fffffff					; base
				0xB9, 0xFF, 0xFF, 0xFF, 0x7F,					// 8:  b9 ff ff ff 7f          mov    ecx,0x7fffffff				; shellcode
				0xFF, 0xD1,										// d:  ff d1                   call   ecx
				0x8B, 0x4D, 0x04,								// f:  8b 4d 04                mov    ecx,DWORD PTR [ebp+0x4]
				0x8B, 0x51, 0xFC,								// 12: 8b 51 fc                mov    edx,DWORD PTR [ecx-0x4]
				0xC7, 0x02, 0xFF, 0xFF, 0xFF, 0x7F,				// 15: c7 02 ff ff ff 7f       mov    DWORD PTR [edx],0x7fffffff	; original_present
				0x8B, 0x4D, 0x0C,								// 1b: 8b 4d 0c                mov    ecx,DWORD PTR [ebp+0xc]
				0x51,											// 1e: 51                      push   ecx
				0x8B, 0x4D, 0x08,								// 1f: 8b 4d 08                mov    ecx,DWORD PTR [ebp+0x8]
				0x51,											// 22: 51                      push   ecx
				0xBA, 0xFF, 0xFF, 0xFF, 0x7F,					// 23: ba ff ff ff 7f          mov    edx,0x7fffffff				; original_present
				0xFF, 0xD2,										// 28: ff d2                   call   edx
				0x5D,											// 2a: 5d                      pop    ebp
				0xC2, 0x08, 0x00								// 2b: c2 08 00                ret    0x8
			};

			if ( !loadable.is_valid_dll( ) )
				return false;

			// allocate memory in other process for our DLL
			auto _headers = loadable.get_nt_headers( );

			if ( !_headers )
				return false;

			auto nt = _headers.value( );

			auto addresses = find_targetable_regions( nt->OptionalHeader.SizeOfImage + 0x500 );

			if ( !addresses )
				return false;

			auto address = addresses.value( )[4].base;

			// allocate the memory for our buffer (and shellcode)
			auto remote = allocate( address, nt->OptionalHeader.SizeOfImage + 0x500 );

			if ( remote != address )
			{
				free( remote );
				return false;
			}

			if ( !remote )
				return false;

			auto remote_discord = find_remote_module( "DiscordHook" );

			if ( !remote_discord )
				return false;

			// find pointer to IDXGISwapChain::Present
			const auto find_present_function = [&] ( ) -> std::intptr_t
			{
				return read<std::intptr_t>( remote_discord.value( )._base + 0x179F3 + 2 );
			};

			std::intptr_t target_data_ptr = 0;
			if ( !(target_data_ptr = find_present_function( )) )
				return false;

			// read the original
			auto original_function = read<std::intptr_t>( target_data_ptr );

			// it isn't being used...
			if ( !original_function )
				return false;

			// write headers to remote
			write( remote, loadable.get_buffer( ), nt->OptionalHeader.SizeOfHeaders );

			// write sections to remote 
			PIMAGE_SECTION_HEADER cSectionHeader = IMAGE_FIRST_SECTION( nt );
			int i = 0;
			for (; i < nt->FileHeader.NumberOfSections; ++i, ++cSectionHeader )
				if ( cSectionHeader->SizeOfRawData )
					write( remote + cSectionHeader->VirtualAddress, (loadable.get_buffer() + cSectionHeader->PointerToRawData), cSectionHeader->SizeOfRawData );

			// address of our shellcode function
			auto shellcode_fn = remote + nt->OptionalHeader.SizeOfImage + 5 + sizeof hook + 1;

			// write our shellcode function
			write( remote + nt->OptionalHeader.SizeOfImage + 5 + sizeof hook + 1, (std::uint8_t *)shellcode, 0x400 );

			// write correct payload
			std::memcpy( &hook[0x4], &remote, 4 );
			std::memcpy( &hook[0x9], &shellcode_fn, 4 );
			std::memcpy( &hook[0x17], &original_function, 4 );
			std::memcpy( &hook[0x24], &original_function, 4 );

			// write our hook function
			write( remote + nt->OptionalHeader.SizeOfImage + 5, hook, sizeof hook );

			// write manual map data
			detail::_mm_data data { 0 };
			data.base = remote;
			data.load = LoadLibraryA;
			data.proc = reinterpret_cast<detail::procaddress_t>(GetProcAddress);	
			write<detail::_mm_data>( remote, data );

			// hook
			auto target_address = (std::intptr_t)(remote + nt->OptionalHeader.SizeOfImage + 5);
			write<std::intptr_t>( target_data_ptr, target_address );

			int h = 0;
			for ( ;; )
			{
				std::uintptr_t b;
				b = read<std::uintptr_t>( target_data_ptr );

				if ( b && b == original_function )
					break;

				std::this_thread::sleep_for( 1ms );
				++h;
			}

			printf( " done! (%d)\n", h );
		}

		// this doesn't work and I don't know why... gotta figure it out
		auto sigscan_remote( detail::_module_info &mod, const std::string& pattern ) -> std::optional<std::uintptr_t> {
			std::optional<std::uintptr_t> res = std::nullopt;

			// allocate memory for buffer
			auto buffer = VirtualAlloc( nullptr, mod._size, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

			if ( !buffer )
				return res;

			std::size_t old;
			protect( mod._base, mod._size, PAGE_EXECUTE_READWRITE, old );

			// read the entire module
			ReadProcessMemory( get_handle( ), (void*)mod._base, buffer, mod._size, nullptr );

			// sigscan
			auto addy = bruiser::sigscan( (std::intptr_t)buffer, pattern.c_str() );

			// revert protection
			protect( mod._base, mod._size, old, old );

			res = addy ? std::make_optional<std::uintptr_t>(addy) : std::nullopt;

			// free memory and return result
			VirtualFree( (void*)buffer, mod._size, MEM_RELEASE );
			return res;
		}

		// does what is do
		auto find_remote_module( const std::string &name ) -> std::optional<detail::_module_info> {

			if ( !_module_cache.size( ) )
				cache_modules( );

			for ( const auto &mod : _module_cache )
			{
				if ( ::strstr( mod._name, name.c_str( ) ) )
					return std::make_optional<detail::_module_info>( mod );
			}
			return std::nullopt;
		}

		// does what it do
		auto cache_modules( ) -> void {
			// check if it's already populated
			if ( _module_cache.size( ) != 0 )
				return;

			auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, _pid );

			if ( !snapshot )
				__fastfail( 0 );

			MODULEENTRY32 me = { 0 };
			me.dwSize = sizeof MODULEENTRY32;

			for ( Module32First( snapshot, &me ); Module32Next( snapshot, &me ); )
			{
				detail::_module_info info = { 0 };
				info._base = (std::intptr_t)me.modBaseAddr;
				info._size = me.dwSize;
				strcpy_s( info._name, me.szModule );

				_module_cache.push_back( info );
			}

			CloseHandle( snapshot );
		}

		auto get_handle( ) -> HANDLE {
			return reinterpret_cast<HANDLE>(_handle);
		}

		auto query( std::intptr_t address ) -> std::shared_ptr<MEMORY_BASIC_INFORMATION> {

			MEMORY_BASIC_INFORMATION mbi = { 0 };
			VirtualQueryEx( get_handle( ), (LPCVOID)address, &mbi, sizeof mbi );

			check_status( );

			return std::make_shared<MEMORY_BASIC_INFORMATION>( mbi );
		}

		auto query_memory( std::intptr_t address ) -> std::shared_ptr<MEMORY_BASIC_INFORMATION> {

			MEMORY_BASIC_INFORMATION mbi = { 0 };
			VirtualQueryEx( get_handle( ), (LPCVOID)address, &mbi, sizeof mbi );

			check_status( );

			return std::make_shared<MEMORY_BASIC_INFORMATION>( mbi );
		}

		auto free( std::intptr_t base ) -> void {
			VirtualFreeEx( get_handle( ), (LPVOID)base, 0, MEM_RELEASE );
			check_status( );
		}

		auto is_valid_address( std::intptr_t address ) const {
			return address > 0 && address < (std::numeric_limits<std::intptr_t>::max)();
		}

		auto find_targetable_regions( std::size_t targetable_size = 0x1AFB ) -> std::optional<std::vector<detail::_remote_memory_region>> {
			std::vector<detail::_remote_memory_region> addies;

			for ( const auto &mod : _module_cache )
			{
				if ( !is_valid_address( mod._base ) )
					continue;

				auto size = mod._size;
				auto base = mod._base;

				auto res = do_protected( base, 0x1000, PAGE_READWRITE, [&]
				{
					IMAGE_DOS_HEADER dos = read<IMAGE_DOS_HEADER>( base );
					IMAGE_NT_HEADERS32 nt = read<IMAGE_NT_HEADERS32>( base + dos.e_lfanew );

					auto end = base + nt.OptionalHeader.SizeOfImage;
					auto allocation_address = end;

					while ( allocation_address % 0x10000 != 0 )
						allocation_address += 0x1;

					auto bytes_skipped = allocation_address - end;

					bool allocated = false;
					for ( auto i = 0; i <= (targetable_size / 0x1000); ++i )
					{
						auto mbi = query_memory( allocation_address + i * 0x1000 );
						if ( mbi->AllocationBase )
						{
							allocated = true;
							break;
						}
					}

					if ( allocated )
						return;

					detail::_remote_memory_region region = { 0 };
					region.parent_base = base;
					region.base = allocation_address;
					region.size = nt.OptionalHeader.SizeOfImage + bytes_skipped + targetable_size;
					std::copy( std::begin( mod._name ), std::end( mod._name ), std::begin( region.parent_name ) );

					addies.push_back( region );
				} );
			}

			if ( addies.size( ) == 0 )
				return std::nullopt;

			return addies;
		}

		auto allocate( std::intptr_t base, std::size_t size ) -> std::intptr_t {
			auto res = VirtualAllocEx( get_handle( ), (LPVOID)base, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

			// invalid address, seems as though we can just ignore this, lol!
			if ( GetLastError( ) == 0x000001E7 )
			{
				Sleep( 5000 );
				SetLastError( 0 );
				auto info = query_memory( base );
				if ( info->AllocationProtect == PAGE_EXECUTE_READWRITE )
					printf( "Region still allocated!\n" );
				else
					printf( " Region not allocated!\n" );
			}
			else
			{
				check_status( );
			}

			return (std::intptr_t)res;
		}

		auto protect( std::intptr_t address, std::size_t size, std::size_t protection, std::size_t &old ) -> bool {
			return VirtualProtectEx( get_handle( ), (LPVOID)address, size, protection, (PDWORD)&old );
		}

		auto do_protected( std::intptr_t address, std::size_t size, std::intptr_t protection, std::function<void( )> lambda ) -> bool {
			std::size_t old_protection = 0;

			if ( !protect( address, size, protection, old_protection ) )
				return false;

			if ( GetLastError( ) )
			{
				SetLastError( 0 );
				return false;
			}

			lambda( );

			if ( !protect( address, size, old_protection, old_protection ) )
				return false;

			check_status( );
			return true;
		}

		template <typename T>
		auto read( std::intptr_t address ) -> T {
			T buf = { 0 };
			 
			ReadProcessMemory( get_handle(), (void*)address, &buf, sizeof T, nullptr );

			// Same here, we can ignore these issues because they get written anyway, lol.
			auto last_error = GetLastError( );
			if ( last_error == 0x12B || last_error == 0x00000012 )
				SetLastError( 0 );

			check_status( );

			return buf;
		}

		auto write( std::intptr_t address, std::uint8_t *buffer, std::size_t length ) -> void {
			WriteProcessMemory( get_handle( ), (LPVOID)address, buffer, length, nullptr );

			auto last_error = GetLastError( );
			if ( last_error == 0x12B || last_error == 0x00000012 )
				SetLastError( 0 );

			check_status( );
		}

		 
		template <typename T>
		auto write( std::intptr_t address, T& buffer ) -> void {
			WriteProcessMemory( get_handle( ), (void*)address, &buffer, sizeof T, nullptr );

			auto last_error = GetLastError( );
			if ( last_error == 0x12B || last_error == 0x00000012 )
				SetLastError( 0 );

			check_status( );
		}

		// read to buffer
		auto read_buffer( std::intptr_t buffer, std::intptr_t address, std::size_t size ) -> void {
			ReadProcessMemory( get_handle(), (void*)address, (void*)buffer, size, nullptr );

			check_status( );
		}

		c_remote_process( std::uintptr_t pid = 0) : _pid( pid ) { 
			_handle = 0;
			_module_cache = {};

			if ( pid == 0 )
				__fastfail( 0 );

			cache_modules( );

			_handle = (std::intptr_t)OpenProcess( PROCESS_ALL_ACCESS, false, pid );
		}

		~c_remote_process( ) {
			if ( _handle )
				CloseHandle( (HANDLE)_handle );
		}

		c_remote_process( const std::string &name ) : c_remote_process( find_process_by_name( name ).value_or( 0 ) ) { }
	};

}

#endif