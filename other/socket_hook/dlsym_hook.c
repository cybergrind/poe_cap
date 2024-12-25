/* This definition is required to get dlvsym(). */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static void * (*dlsym_real)( void * handle, const char * symbol ) = NULL;
// if x32

#ifdef __x86_64__
static const char* prefix = "lib64";
#else
static const char* prefix = "lib32";
#endif


void * dlsym( void * handle, const char * symbol )
{
    if (!dlsym_real) {
        // objdump -T  /usr/lib/libdl.so.2
        // it will be the latest
        #ifdef __x86_64__
        dlsym_real = dlvsym ( RTLD_DEFAULT, "dlsym", "GLIBC_2.2.5" );
        #else
        dlsym_real = dlvsym ( RTLD_DEFAULT, "dlsym", "GLIBC_2.0" );
        #endif
    }

    FILE *fd = fopen("/tmp/dlsym.log", "a");
    fprintf(fd, "%s:dlsym() called %s\n", prefix, symbol);

    if( !strcmp( symbol, "open"))
        fprintf(fd, "open() called\n");

    return dlsym_real( handle, symbol );
}
