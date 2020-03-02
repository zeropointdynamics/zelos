//
// Loads the DLL specified on the command line. Used for testing Zemu's ability
// to load various DLLs and successfully execute their DLLMain.
//
// All DLLs in a directory can be tested as follows:
//   find zemu/lib/windows/filesystems/win7x86/Windows/System32/ -type f -iname *.dll -exec sh -c 'DLL=$(basename {}); echo Trying to reach NtTerminateProcess with load of $DLL; python3 zemu-exec.py --patched --winnative --disable_export_hooks --timeout=30 --cmdline_args="$DLL" demo/loaddll.exe' _ {} \; 2>&1 | tee loaddll_test.txt
//   cat loaddll_test.txt | grep NtTerminateProcess
//
// Originally built in the VC++ 2008 32-bit command prompt with command:
//   cl loaddll.c

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[], char *envp[]) {
	HINSTANCE hinstLib;

	if (argc < 2) {
		return 1;
	}

    hinstLib = LoadLibrary(TEXT(argv[1]));

    if (hinstLib == NULL) {
		return 1;
	}

	printf("OK\n");

	FreeLibrary(hinstLib);
    return 0;
}
