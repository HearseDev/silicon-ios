#include <cstdint>
#include <dlfcn.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <EndpointSecurity/EndpointSecurity.h>
#include <algorithm>
#include <array>
#include <bsm/libbsm.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dispatch/dispatch.h>
#include <functional>
#include <iostream>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/arm/thread_state.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <filesystem>
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <vector>

__asm__(".globl _patch_start\n"
        ".globl _patch_end\n"
        "_patch_start:\n"
        "\tmov x2, #0x5f\n"
        "\tstr x2, [x1]\n"
        "\tmov x0, #0\n"
        "\tret\n"
        "_patch_end:\n");

extern char patch_start;
extern char patch_end;

#define ensure(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      throw std::runtime_error(std::string("") + "Check \"" +                  \
                               #condition "\" failed at " + __FILE__ + ":" +   \
                               std::to_string(__LINE__) + " in function " +    \
                               __FUNCTION__);                                  \
    }                                                                          \
  } while (0)

#define page_align(addr)                                                       \
  (vm_address_t)((uintptr_t)(addr) & (~(vm_page_size - 1)))
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
/* posix_spawnattr_disable_ptr_auth_a_keys_np(posix_spawnattr_t *attr, uint32_t
 * flags); */
extern int posix_spawnattr_disable_ptr_auth_a_keys_np(posix_spawnattr_t *attr);
int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t attrs,
                                          int disclaim);
#if __cplusplus
}
#endif

template <typename T> T scan(task_port_t task, std::uintptr_t &address) {
  T t;
  vm_size_t count;
  ensure(vm_read_overwrite(task, address, sizeof(t),
                           reinterpret_cast<pointer_t>(&t),
                           &count) == KERN_SUCCESS &&
         count == sizeof(t));
  address += sizeof(t);
  return t;
}

std::vector<std::uintptr_t> read_string_array(task_port_t task,
                                              std::uintptr_t &base) {
  auto strings = std::vector<std::uintptr_t>{};
  std::uintptr_t string;
  do {
    string = scan<std::uintptr_t>(task, base);
    strings.push_back(string);
  } while (string);
  strings.pop_back();
  return strings;
}

std::string read_string(task_port_t task, std::uintptr_t address) {
  auto string = std::string{};
  char c;
  do {
    c = scan<char>(task, address);
    string.push_back(c);
  } while (c);
  string.pop_back();
  return string;
}

std::uintptr_t rearrange_stack(task_port_t task, const std::string &library,
                               std::uintptr_t sp) {
  auto loadAddress = scan<std::uintptr_t>(task, sp);
  auto argc = scan<std::uintptr_t>(task, sp);

  auto argvAddresses = read_string_array(task, sp);
  auto envpAddresses = read_string_array(task, sp);
  auto appleAddresses = read_string_array(task, sp);

  auto stringReader = std::bind(read_string, task, std::placeholders::_1);
  auto argv = std::vector<std::string>{};
  std::transform(argvAddresses.begin(), argvAddresses.end(),
                 std::back_inserter(argv), stringReader);
  auto envp = std::vector<std::string>{};
  std::transform(envpAddresses.begin(), envpAddresses.end(),
                 std::back_inserter(envp), stringReader);
  auto apple = std::vector<std::string>{};
  std::transform(appleAddresses.begin(), appleAddresses.end(),
                 std::back_inserter(apple), stringReader);

  auto dyld_insert_libraries =
      std::find_if(envp.begin(), envp.end(), [](const auto &string) {
        return string.starts_with("DYLD_INSERT_LIBRARIES=");
      });
  if (dyld_insert_libraries != envp.end()) {
    *dyld_insert_libraries += ":" + library;
  } else {
    auto variable = "DYLD_INSERT_LIBRARIES=" + library;
    envp.push_back(variable);
  }
  envp.push_back("DYLD_SHARED_REGION=foobar");

  argvAddresses.clear();
  envpAddresses.clear();
  appleAddresses.clear();

  auto strings = std::vector<char>{};
  auto arrayGenerator = [&strings](auto &addresses, const auto &string) {
    addresses.push_back(strings.size());
    std::copy(string.begin(), string.end(), std::back_inserter(strings));
    strings.push_back('\0');
  };
  std::for_each(argv.begin(), argv.end(),
                std::bind(arrayGenerator, std::ref(argvAddresses),
                          std::placeholders::_1));
  std::for_each(envp.begin(), envp.end(),
                std::bind(arrayGenerator, std::ref(envpAddresses),
                          std::placeholders::_1));
  std::for_each(apple.begin(), apple.end(),
                std::bind(arrayGenerator, std::ref(appleAddresses),
                          std::placeholders::_1));

  sp -= strings.size();
  sp = sp / sizeof(std::uintptr_t) * sizeof(std::uintptr_t);
  ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(strings.data()),
                  strings.size()) == KERN_SUCCESS);

  auto rebaser = [sp](auto &&address) { address += sp; };
  std::for_each(argvAddresses.begin(), argvAddresses.end(), rebaser);
  std::for_each(envpAddresses.begin(), envpAddresses.end(), rebaser);
  std::for_each(appleAddresses.begin(), appleAddresses.end(), rebaser);

  auto addresses = std::vector<std::uintptr_t>{};
  std::copy(argvAddresses.begin(), argvAddresses.end(),
            std::back_inserter(addresses));
  addresses.push_back(0);
  std::copy(envpAddresses.begin(), envpAddresses.end(),
            std::back_inserter(addresses));
  addresses.push_back(0);
  std::copy(appleAddresses.begin(), appleAddresses.end(),
            std::back_inserter(addresses));
  addresses.push_back(0);

  sp -= addresses.size() * sizeof(std::uintptr_t);
  ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(addresses.data()),
                  addresses.size() * sizeof(std::uintptr_t)) == KERN_SUCCESS);
  sp -= sizeof(std::uintptr_t);
  ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(&argc),
                  sizeof(std::uintptr_t)) == KERN_SUCCESS);
  sp -= sizeof(std::uintptr_t);
  ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(&loadAddress),
                  sizeof(std::uintptr_t)) == KERN_SUCCESS);
  return sp;
}

void write_patch(task_t task, std::uintptr_t address) {
  ensure(vm_protect(task, address / PAGE_SIZE * PAGE_SIZE, PAGE_SIZE, false,
                    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) ==
         KERN_SUCCESS);
  ensure(vm_write(task, address, reinterpret_cast<vm_offset_t>(&patch_start),
                  &patch_end - &patch_start) == KERN_SUCCESS);
  ensure(vm_protect(task, address / PAGE_SIZE * PAGE_SIZE, PAGE_SIZE, false,
                    VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS);
}

void patch_restrictions(task_t task, std::uintptr_t pc) {
  task_dyld_info_data_t dyldInfo;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  ensure(task_info(mach_task_self(), TASK_DYLD_INFO,
                   reinterpret_cast<task_info_t>(&dyldInfo),
                   &count) == KERN_SUCCESS);
  auto all_image_infos =
      reinterpret_cast<dyld_all_image_infos *>(dyldInfo.all_image_info_addr);
  const auto header = reinterpret_cast<const mach_header_64 *>(
      all_image_infos->dyldImageLoadAddress);
  auto location = reinterpret_cast<std::uintptr_t>(header + 1);
  auto base = reinterpret_cast<std::uintptr_t>(header);
  for (unsigned i = 0; i < header->ncmds; ++i) {
    auto command = reinterpret_cast<load_command *>(location);
    if (command->cmd == LC_SYMTAB) {
      auto command = reinterpret_cast<symtab_command *>(location);
      auto symbols = std::span{
          reinterpret_cast<nlist_64 *>(base + command->symoff), command->nsyms};
      auto _dyld_start = std::find_if(
          symbols.begin(), symbols.end(), [base, command](const auto &symbol) {
            return !std::strcmp(
                reinterpret_cast<char *>(base + command->stroff) +
                    symbol.n_un.n_strx,
                "__dyld_start");
          });
      auto amfi_check_dyld_policy_self = std::find_if(
          symbols.begin(), symbols.end(), [base, command](const auto &symbol) {
            return !std::strcmp(
                reinterpret_cast<char *>(base + command->stroff) +
                    symbol.n_un.n_strx,
                "_amfi_check_dyld_policy_self");
          });
      write_patch(task, pc + amfi_check_dyld_policy_self->n_value -
                            _dyld_start->n_value);
      return;
    }
    location += command->cmdsize;
  }
  ensure(false);
}

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
  task_port_t task;
  ensure(task_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS);
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  ensure(task_threads(task, &threads, &count) == KERN_SUCCESS);
  ensure(count == 1);

  arm_thread_state64_t state;
  count = ARM_THREAD_STATE64_COUNT;
  thread_state_flavor_t flavor = ARM_THREAD_STATE64;
  ensure(thread_get_state(*threads, flavor,
                          reinterpret_cast<thread_state_t>(&state),
                          &count) == KERN_SUCCESS);
  ensure(thread_convert_thread_state(
             *threads, THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor,
             reinterpret_cast<thread_state_t>(&state), count,
             reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
  ensure(thread_convert_thread_state(
             *threads, THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor,
             reinterpret_cast<thread_state_t>(&state), count,
             reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
  std::string library = getExecPath();
  library += "interpose.dylib";
  auto sp = rearrange_stack(task, library, arm_thread_state64_get_sp(state));
  printf("[*] Inserted %s into pid: %i and rearranged stack.\n",
         library.c_str(), pid);
  arm_thread_state64_set_sp(state, sp);
  patch_restrictions(task, arm_thread_state64_get_pc(state));
  ensure(thread_convert_thread_state(
             *threads, THREAD_CONVERT_THREAD_STATE_FROM_SELF, flavor,
             reinterpret_cast<thread_state_t>(&state), count,
             reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
  ensure(thread_set_state(*threads, flavor,
                          reinterpret_cast<thread_state_t>(&state),
                          count) == KERN_SUCCESS);
  printf("[*] Patched amfi_check_dyld_policy_self.\n");
}
int run(char *argv[]) {

  std::vector<char *> newEnv(environ,
                             environ + sizeof(environ) / sizeof environ[0]);
  // newEnv.insert(
  //     newEnv.end(),
  //     {(char *)"COMMAND_MODE=unix2003",
  //      //"CFFIXED_USER_HOME=~/Library/Containers/UUID/Data",
  //      //"HOME=~/Library/Containers/UUID/Data",
  //      (char *)"LOGNAME=dev", (char *)"MallocSpaceEfficient=1",
  //      (char *)"PATH=/usr/bin:/bin:/usr/sbin:/sbin", (char
  //      *)"SHELL=/bin/bash",
  //      //"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.RANDOM/Listeners",
  //      //"TMPDIR=/Users/mickey/Library/Containers/UUID/Data/tmp",
  //      (char *)"USER=dev", (char *)"XPC_FLAGS=1",
  //      (char *)"DYLD_PRINT_LIBRARIES=1", (char *)"DYLD_PRINT_APIS=1",
  //      //"XPC_SERVICE_NAME=application.com.xxxapp.iOS",
  //      //"_DYLD_CLOSURE_HOME=/Users/mickey/Library/Containers/UUID/Data",
  //      //"__CFBundleIdentifier=com.xxxapp.iOS",
  //      (char *)"__CF_USER_TEXT_ENCODING=0x1F5:0x0:0x0", 0});

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
  printf("[*] Sending SIGCONT to continue child\n");
  kill(pid, SIGCONT);
  int status;
  assert(waitpid(pid, &status, 0) != -1);
  printf("[*] Child exited with status %i\n", status);
  posix_spawnattr_destroy(&attr);
  posix_spawn_file_actions_destroy(&action);
  return 0;
}
int main(int argc, char *argv[]) {
  if (argc <= 1) {
    printf("Usage: %s path/to/ios_binary\n", argv[0]);
    return 0;
  }
  printf("[*] Preparing to execute iOS binary %s\n", argv[1]);
  return run(argv + 1);
}
