/* This main program simulates an executable which is linked directly against
 * a pynativelib library, and which requires DYLD_LIBRARY_PATH to be set
 * in order to run.
 */

#include <stdio.h>

extern int native_int;
extern int native_func();

int main(int argc, char** argv)
{
    printf("main-envvar started w/ sizeof(void*) = %lu\n", sizeof(void*));
    printf("native_int == %i\n", native_int);
    printf("native_func() == %i\n", native_func());
    return !(native_int == 13 && native_func() == 14);
}
