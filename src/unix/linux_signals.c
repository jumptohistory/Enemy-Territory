/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company. 

This file is part of the Wolfenstein: Enemy Territory GPL Source Code (Wolf ET Source Code).  

Wolf ET Source Code is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Wolf ET Source Code is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wolf ET Source Code.  If not, see <http://www.gnu.org/licenses/>.

In addition, the Wolf: ET Source Code is also subject to certain additional terms. You should have received a copy of these additional terms immediately following the terms and conditions of the GNU General Public License which accompanied the Wolf ET Source Code.  If not, please request a copy in writing from id Software at the address below.

If you have questions concerning this license or the applicable additional terms, you may contact in writing id Software LLC, c/o ZeniMax Media Inc., Suite 120, Rockville, Maryland 20850 USA.

===========================================================================
*/

#include <signal.h>

#include "../game/q_shared.h"
#include "../qcommon/qcommon.h"
#ifndef DEDICATED
#include "../renderer/tr_local.h"
#endif

// rain - don't bother building this in debug builds now, since we
// aren't calling the signal handler at all
#ifndef _DEBUG
static qboolean signalcaught = qfalse;;

void Sys_Exit( int ); // bk010104 - abstraction

static void signal_handler( int sig ) { // bk010104 - replace this... (NOTE TTimo huh?)
	static int lastTime = -1;
	int currentTime = Sys_Milliseconds();

	if ( signalcaught ) {
		printf( "DOUBLE SIGNAL FAULT: Received signal %d, exiting...\n", sig );
		Sys_Exit( 1 ); // bk010104 - abstraction
	}

	if ( lastTime == -1 || currentTime - lastTime > 1000 ) {
		lastTime = currentTime;
		if ( currentTime >= 0 ) {
			printf( "Received signal %d\n", sig );
			return;
		}
	}
	
	signalcaught = qtrue;
	printf( "Received signal %d, exiting...\n", sig );
#ifndef DEDICATED
	GLimp_Shutdown(); // bk010104 - shouldn't this be CL_Shutdown
#endif
	Sys_Exit( 0 ); // bk010104 - abstraction NOTE TTimo send a 0 to avoid DOUBLE SIGNAL FAULT
}
static void error_signal_handler( int sig ) {
	printf( "Received signal %d, exiting...\n", sig );
	Sys_Exit( 1 );
}
#endif

void InitSig( void ) {
//bani - allows debug builds to core...
#ifndef _DEBUG
	signal( SIGHUP, signal_handler );
	signal( SIGINT, signal_handler );
	signal( SIGQUIT, signal_handler );
	signal( SIGILL, error_signal_handler );
	signal( SIGTRAP, signal_handler );
	signal( SIGIOT, signal_handler );
	signal( SIGBUS, error_signal_handler );
	signal( SIGFPE, signal_handler );
	signal( SIGKILL, signal_handler );
	signal( SIGSEGV, error_signal_handler );
	signal( SIGTERM, signal_handler );
	signal( SIGTSTP, SIG_IGN );
#endif
}
