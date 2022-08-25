#pragma once

#ifndef _LOADABLE
#define _LOADABLE

#include <fstream>
#include <string>
#include <memory>
#include <utility>
#include <algorithm>
#include <vector>
#include <optional>
#include <assert.h>
#include <iostream>

#include <Windows.h>

namespace bruiser {

	// class that holds information on loadable DLLs
	class c_loadable {
	private:

		inline static std::vector<std::pair<std::string, std::uint32_t>> _exports = {};

		std::uint8_t *_buffer;
		std::size_t _size;

		std::string _path;

	public:
		c_loadable( ) {
			_buffer = nullptr;
			_size = 0;
			_path = {};
		}

		auto get_buffer( ) {
			return _buffer;
		}

		auto get_size_buffer( ) {
			return _size;
		}

		c_loadable( const std::string &filepath ) : c_loadable( ) {
			_path = filepath;

			if ( std::mismatch( std::rbegin( ".dll" ), std::rend( ".dll" ), filepath.rbegin( ) ).first == std::rend( ".dll" ) )
			{
				printf( "File isn't a dll!\n" );
				return;
			}

			// open stream to file (at the end)
			std::ifstream stream( filepath, std::ios::binary | std::ios::ate );

			if ( !stream.is_open( ) )
			{
				printf( "Couldn't open stream!\n" );
				return;
			}

			if ( stream.fail( ) )
			{
				printf( " Fail! " );
				stream.close( );
				return;
			}

			// parse size
			auto filesize = stream.tellg( );

			_buffer = new std::uint8_t[static_cast<UINT_PTR>(filesize)];

			if ( !_buffer )
			{
				printf( " Couldn't allocate buffer...\n" );
				stream.close( );
				return;
			}

			// go back to start, allocate a buffer and read to it
			stream.seekg( 0, std::ios::beg );

			stream.read( reinterpret_cast<char *>(_buffer), filesize );

			_size = filesize;

			// close stream
			stream.close( );
		}

		~c_loadable( ) { 
			delete[] _buffer;
		}

		auto get_nt_headers( ) -> std::optional<PIMAGE_NT_HEADERS> {
			auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(_buffer);

			if ( !dos )
			{
				printf( "Couldn't get dos headers (0x%p)\n", _buffer );
				return std::nullopt;
			}

			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(_buffer + dos->e_lfanew);

			if ( !nt )
			{
				printf( "Couldn't get nt headers s (0x%x)\n", dos->e_lfanew );
				return std::nullopt;
			}

			return nt;
		}

		auto is_valid_dll( ) -> const bool {
			auto nt = get_nt_headers( );

			return nt ? nt.value( )->FileHeader.Characteristics & IMAGE_FILE_DLL : false;
		}

		auto find_export( const std::string &name ) -> std::optional<std::pair<std::string, std::uint32_t>> {

			if ( _exports.size( ) == 0 )
				get_exports( );

			if ( _exports.size( ) == 0 )
				return std::nullopt;

			auto it = std::find_if( std::begin( _exports ), std::end( _exports ), [name] ( std::pair<std::string, std::uint32_t> it )
			{
				return std::strstr(it.first.c_str(), name.c_str());
			});

			if ( it != std::end( _exports ) )
				return std::make_optional<std::pair<std::string, std::uint32_t>>(*it);

			return std::nullopt;
		}

		// returns a list of all DLL exports
		auto get_exports( ) -> std::vector<std::pair<std::string, std::uint32_t>> {

			if ( !is_valid_dll( ) )
				return {};

			if ( _exports.size( ) != 0 )
				return _exports;

			// to get exports we need to map a view of the file
			const auto get_image = [&] ( ) -> std::intptr_t
			{
				HANDLE file = CreateFileA( _path.c_str( ), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL );

				if ( file == INVALID_HANDLE_VALUE )
					return 0;

				HANDLE map = CreateFileMappingA( file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, "bb-map" );

				if ( map == INVALID_HANDLE_VALUE || !map)
					return 0;

				auto image = MapViewOfFile( map, FILE_MAP_READ, 0, 0, 0 );

				CloseHandle( file );
				CloseHandle( map );

				return (std::intptr_t)image;
			};


			// get image
			auto image = get_image( );

			if ( !image )
				return {};

			auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(image + dos->e_lfanew);

			if ( !nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size )
				return {};

			// yadadadada
			auto dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(image + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			DWORD *functions = (DWORD *)(image + dir->AddressOfFunctions);
			WORD *ordinals = (WORD *)(image + dir->AddressOfNameOrdinals);
			DWORD *names = (DWORD *)(image + dir->AddressOfNames);

			std::vector<std::pair<std::string, std::uint32_t>> res;

			for ( auto i = 0; i < dir->NumberOfNames; ++i )			
				res.push_back( std::make_pair( std::string( (char *)(image + names[i]) ), functions[ordinals[i]] ) );

			// unmap
			UnmapViewOfFile( (void *)image );

			_exports = res;
			return _exports;
		}
	};
}

#endif