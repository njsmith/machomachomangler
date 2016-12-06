#include <stdio.h>

extern int native_int;
extern int native_func();

int pymodule_entrypoint()
{
    printf("native_int == %i\n", native_int);
    printf("native_func() == %i\n", native_func());
    return (native_int == 13 && native_func() == 14);
}
