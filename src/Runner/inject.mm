// To compile: clang++ -arch x86_64 -arch arm64 -std=c++20 library_injector.cpp
// -lbsm -lEndpointSecurity -o library_injector, then codesign with
// com.apple.developer.endpoint-security.client and run the program as root.

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
#include <mach/mach.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <regex>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <vector>

#define ensure(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      throw std::runtime_error(std::string("") + "Check \"" +                  \
                               #condition "\" failed at " + __FILE__ + ":" +   \
                               std::to_string(__LINE__) + " in function " +    \
                               __FUNCTION__);                                  \
    }                                                                          \
  } while (0)

#define CS_OPS_STATUS 0
#define CS_ENFORCEMENT 0x00001000

extern "C" {
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
};

auto is_translated(pid_t pid) {
  auto name = std::array{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
  kinfo_proc proc;
  size_t size = sizeof(proc);
  ensure(!sysctl(name.data(), name.size(), &proc, &size, nullptr, 0) &&
         size == sizeof(proc));
  return !!(proc.kp_proc.p_flag & P_TRANSLATED);
}

auto is_cs_enforced(pid_t pid) {
  int flags;
  ensure(!csops(pid, CS_OPS_STATUS, &flags, sizeof(flags)));
  return !!(flags & CS_ENFORCEMENT);
}

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
  // INFO: Change made here by me, without this change, the binary will not
  // output to stdout correctly, we need this.
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

void inject(pid_t pid, const std::string &library) {
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
  auto sp = rearrange_stack(task, library, arm_thread_state64_get_sp(state));
  arm_thread_state64_set_sp(state, sp);
  patch_restrictions(task, arm_thread_state64_get_pc(state));
  ensure(thread_convert_thread_state(
             *threads, THREAD_CONVERT_THREAD_STATE_FROM_SELF, flavor,
             reinterpret_cast<thread_state_t>(&state), count,
             reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
  ensure(thread_set_state(*threads, flavor,
                          reinterpret_cast<thread_state_t>(&state),
                          count) == KERN_SUCCESS);
}

// int main(int argc, char **argv, char **envp) {
//   if (!getenv("DYLD_SHARED_REGION")) {
//     uint32_t length = 0;
//     std::string path;
//     _NSGetExecutablePath(path.data(), &length);
//     path = std::string('0', length);
//     ensure(!_NSGetExecutablePath(path.data(), &length));
//     std::vector<const char *> environment;
//     while (*envp) {
//       environment.push_back(*envp++);
//     }
//     // This happens to disable dyld-in-cache.
//     environment.push_back("DYLD_SHARED_REGION=foobar");
//     environment.push_back(nullptr);
//     execve(path.c_str(), argv, const_cast<char **>(environment.data()));
//     ensure(false);
//   }

//   if (argc < 3) {
//     std::cerr << "Usage: " << *argv << " <library to inject> <process
//     paths...>"
//               << std::endl;
//     std::exit(EXIT_FAILURE);
//   }

//   auto library = *++argv;
//   std::vector<std::regex> processes;
//   for (auto process : std::span(++argv, argc - 2)) {
//     processes.push_back(std::regex(process));
//   }

//   es_client_t *client = NULL;
//   ensure(
//       es_new_client(&client, ^(es_client_t *client,
//                                const es_message_t *message) {
//         switch (message->event_type) {
//         case ES_EVENT_TYPE_AUTH_EXEC: {
//           const char *name =
//           message->event.exec.target->executable->path.data; for (const auto
//           &process : processes) {
//             pid_t pid = audit_token_to_pid(message->process->audit_token);
//             if (std::regex_search(name, process) &&
//                 is_translated(getpid()) == is_translated(pid)) {
//               if (is_cs_enforced(pid)) {
//                 ensure(!ptrace(PT_ATTACHEXC, pid, nullptr, 0));
//                 // Work around FB9786809
//                 dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
//                 1'000'000'000),
//                                dispatch_get_main_queue(), ^{
//                                  ensure(!ptrace(PT_DETACH, pid, nullptr, 0));
//                                });
//               }
//               inject(pid, library);
//             }
//           }
//           es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW,
//           false); break;
//         }
//         default:
//           ensure(false && "Unexpected event type!");
//         }
//       }) == ES_NEW_CLIENT_RESULT_SUCCESS);
//   es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
//   ensure(es_subscribe(client, events, sizeof(events) / sizeof(*events)) ==
//          ES_RETURN_SUCCESS);
//   dispatch_main();
// }