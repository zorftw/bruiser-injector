#pragma once

#ifndef PATTERN_H
#define PATTERN_H

#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

namespace bruiser {
    inline uintptr_t sigscan( std::intptr_t module, const char *pattern, std::size_t size = 0 ) {
        uintptr_t moduleAdress = module;

        static auto patternToByte = [] ( const char *pattern )
        {
            auto       bytes = std::vector<int> {};
            const auto start = const_cast<char *>(pattern);
            const auto end = const_cast<char *>(pattern) + strlen( pattern );

            for ( auto current = start; current < end; ++current )
            {
                if ( *current == '?' )
                {
                    ++current;
                    if ( *current == '?' )
                        ++current;
                    bytes.push_back( -1 );
                }
                else
                {
                    bytes.push_back( strtoul( current, &current, 16 ) );
                }
            }
            return bytes;
        };

        auto sizeOfImage = size;
        if ( !size )
        {
            const auto dosHeader = (PIMAGE_DOS_HEADER)moduleAdress;
            const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t *)moduleAdress + dosHeader->e_lfanew);

            sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        }
        
        auto       patternBytes = patternToByte( pattern );
        const auto scanBytes = reinterpret_cast<std::uint8_t *>(moduleAdress);

        const auto s = patternBytes.size( );
        const auto d = patternBytes.data( );

        for ( auto i = 0ul; i < sizeOfImage - s; ++i )
        {
            bool found = true;
            for ( auto j = 0ul; j < s; ++j )
            {
                if ( scanBytes[i + j] != d[j] && d[j] != -1 )
                {
                    found = false;
                    break;
                }
            }
            if ( found )
            {
                return reinterpret_cast<uintptr_t>(&scanBytes[i]);
            }
        }
        return NULL;
    }
}

#endif