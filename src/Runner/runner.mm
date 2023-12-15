#include <cassert>
#include <cstdint>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <unistd.h>

#include <mach-o/dyld.h>

#include <filesystem>
#include <string>
#include <vector>

#include "inject.h"
#include "runner.h"
#include "uikitsystem_patch.h"
#include <thread>

#define PLATFORM_IOS 2

#if __cplusplus
extern "C" {
#endif
extern char **environ;
extern int posix_spawnattr_setcpumonitor(posix_spawnattr_t *__restrict attr,
                                         uint64_t percent, uint64_t interval);
extern int posix_spawnattr_setjetsam_ext(posix_spawnattr_t *__restrict attr,
                                         short flags, int priority,
                                         int memlimit_active,
                                         int memlimit_inactive);

extern int posix_spawnattr_set_platform_np(posix_spawnattr_t *, int, int);
/* extern int */
/* posix_spawnattr_disable_ptr_auth_a_keys_np(posix_spawnattr_t *attr,
uint32_t
 * flags); */
extern int posix_spawnattr_disable_ptr_auth_a_keys_np(posix_spawnattr_t *attr);
int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t attrs,
                                          int disclaim);
#if __cplusplus
}
#endif

// tmp
std::filesystem::path getExecPath() {
  char szPath[PATH_MAX];
  uint32_t bufsize = PATH_MAX;
  if (!_NSGetExecutablePath(szPath, &bufsize))
    return std::filesystem::path{szPath}.parent_path() /
           ""; // to finish the folder path with (back)slash
  return {};   // some error
}

void instrument(pid_t pid) {
  std::string library = getExecPath() += "interpose.dylib";
  inject(pid, library);
  printf("[*] Patched amfi_check_dyld_policy_self.\n");
  printf("[*] Inserted %s into pid: %i.\n", library.c_str(), pid);
}

int run(char *argv[], RunnerOptions options) {
  std::vector<char *> newEnv(environ,
                             environ + sizeof(environ) / sizeof environ[0]);
  // newEnv.insert(
  //     newEnv.end(),
  //     {(char *)"COMMAND_MODE=unix2003",
  //      (char *)"CFFIXED_USER_HOME=./Library/Containers/UUID/Data",
  //      (char *)"HOME=./Library/Containers/UUID/Data",
  //      (char *)"LOGNAME=administrator", (char *)"MallocSpaceEfficient=1",
  //      (char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin", (char
  //      *)"SHELL=/bin/bash", (char
  //      *)"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.RANDOM/Listeners",
  //      (char
  //      *)"TMPDIR=/Users/administrator/Library/Containers/UUID/Data/tmp",
  //      (char *)"USER=administrator", (char *)"XPC_FLAGS=1",
  //      (char *)"_DYLD_CLOSURE_HOME=/Users/administrator/Library/Containers/"
  //              "UUID/Data",
  //      (char *)"__CFBundleIdentifier=com.toyopagroup.picaboo",
  //      (char *)"__CF_USER_TEXT_ENCODING=0x1F5:0x0:0x0", 0});

  //  (char *)"XPC_SERVICE_NAME=application.com..blankapp",
  //      (char *)"DYLD_PRINT_LIBRARIES=1", (char *)"DYLD_PRINT_APIS=1",

  pid_t pid;
  int rv;
  posix_spawn_file_actions_t action;
  posix_spawn_file_actions_init(&action);

  // Redirect child output to /dev/null
  // posix_spawn_file_actions_addopen(&action, 0, "/dev/null", 0x20000, 0x1B6);
  // posix_spawn_file_actions_addopen(&action, 1, "/dev/null", 0x20002, 0x1B6);
  // posix_spawn_file_actions_addopen(&action, 2, "/dev/null", 0x20002, 0x1B6);

  posix_spawnattr_t attr;
  rv = posix_spawnattr_init(&attr);
  if (rv != 0) {
    perror("posix_spawnattr_init");
    return -1;
  }
  posix_spawnattr_setcpumonitor(&attr, 0xfe, 0);
  posix_spawnattr_setjetsam_ext(&attr, 0xc, 0x3, 0x4000, 0x4000);
  posix_spawnattr_disable_ptr_auth_a_keys_np(&attr);
  responsibility_spawnattrs_setdisclaim(&attr, 1);
  assert(posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED) == 0);
  assert(posix_spawnattr_set_platform_np(&attr, PLATFORM_IOS, 0) == 0);
  assert(posix_spawn(&pid, argv[0], &action, &attr, argv, &newEnv[0]) == 0);
  printf("[+] Child process created with pid: %i\n", pid);
  instrument(pid);

  printf("[*] Patching UIKitSystem\n");
  std::thread frida_thread(patch_uikitsystem);
  frida_thread.detach();
  printf("[*] Process %d started. Attach now, and click enter.\n", pid);
  getchar();
  printf("[*] Sending SIGCONT to continue child\n");
  kill(pid, SIGCONT);
  int status;
  assert(waitpid(pid, &status, 0) != -1);
  printf("[*] Child exited with status %i\n", status);
  posix_spawnattr_destroy(&attr);
  posix_spawn_file_actions_destroy(&action);
  return 0;
}
