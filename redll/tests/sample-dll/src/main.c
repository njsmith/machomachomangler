/* If you modify this, re-run rebuild.py */

#include <stdio.h>
#include <string.h>

__declspec(dllimport)
extern const int sample_dll_function();

__declspec(dllimport)
extern const int sample_dll_data;

int main(int argc, char** argv)
{
    printf("Calling sample_dll_function...");
    if (sample_dll_function() != 11) {
        printf("FAILED!\n");
        return 1;
    } else {
        printf("success!\n");
    }

    printf("Checking sample_dll_data...");
    if (sample_dll_data != 12) {
        printf("FAILED!\n");
        return 1;
    } else {
        printf("success!\n");
    }

    return 0;
}
