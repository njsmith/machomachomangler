/* This main program simulates a Python interpreter that dlopen's a Python
 * module, where that module is in turn linked against a pynativelib
 * library.
 *
 * It tests the strategy of using dlopen to "preload" the pynativelib library
 * inside the interpreter before importing the module.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void dlcheck(char const* op, void* ptr)
{
    if (!ptr) {
        printf("%s failed: %s\n", op, dlerror());
        exit(1);
    }
}

int main(int argc, char** argv)
{
    printf("main-dlopen started with sizeof(void*) = %lu\n", sizeof(void*));

    printf("preloading mangled native lib\n");
    void* preload = dlopen("./mangled-native-lib.dylib", RTLD_LAZY);
    dlcheck("preload dlopen", preload);

    printf("loading fake python module\n");
    void* module = dlopen("./mangled-fake-pymodule.dylib", RTLD_LAZY);
    dlcheck("module dlopen", module);
    printf("fetching entry point\n");
    void* sym = dlsym(module, "pymodule_entrypoint");
    dlcheck("dlsym", sym);
    int (*pymodule_entrypoint)() = sym;

    printf("calling entry point\n");
    return !pymodule_entrypoint();
}
