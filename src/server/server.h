#include <stdio.h>
#include <string.h>

typedef struct {
    const char *arg1;   //Interface
    int arg2;   //Port
    const char *arg3; //File
    int flags;
} Arguments;

#define ARG_INTERFACE (1 << 0)
#define ARG_PORT (1 << 1)
#define ARG_FILE (1 << 2)