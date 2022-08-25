#include "../lib/loadable/loadable.hpp"
#include "../lib/remote/remote.h"


#include <iostream>

//constexpr auto PATH_TO_DLL = "C:\\Users\\Zor\\source\\repos\\bruiser-rewrite\\Release\\bruiser-dll.dll";
constexpr auto PATH_TO_DLL = "C:\\Users\\Zor\\source\\repos\\bb\\Release\\bb.dll";

int main( ) {

	auto dll = bruiser::c_loadable( PATH_TO_DLL );
	if(!dll.is_valid_dll() )
	{
		printf( "Target file doesn't seem to be a dll!\n" );
		return -1;
	}

	auto league = bruiser::c_remote_process( "League of Legends" );
	if ( !league.inject_loadable_ntdetour( dll ) )
	{
		printf( "Injection failed...\n" );
		return -1;
	}


	return 0;
}