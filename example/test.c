#include <stdio.h>

__declspec(dllimport)
const char * dll_function();

int main(int argc, char** argv)
{
    printf("dll_function says: %s\n", dll_function());
}
