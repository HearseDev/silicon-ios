#include "runner.h"
#include <stdio.h>
int main(int argc, char **argv, char **envp) {
  // if (!getenv("DYLD_SHARED_REGION")) {
  //   printf(
  //       "[!] No DYLD_SHARED_REGION specified. Specifying DYLD_SHARED_REGION
  //       by " "default.\n");
  //   uint32_t length = 0;
  //   std::string path;
  //   assert(_NSGetExecutablePath(path.data(), &length) == -1);
  //   path = std::string('0', length);
  //   assert(_NSGetExecutablePath(path.data(), &length) == 0);
  //   std::vector<const char *> environment;
  //   while (*envp) {
  //     environment.push_back(*envp++);
  //   }
  //   // This happens to disable dyld-in-cache.
  //   environment.push_back("DYLD_SHARED_REGION=foobar");
  //   environment.push_back(nullptr);
  //   execve(path.c_str(), argv, const_cast<char **>(environment.data()));
  // }

  if (argc <= 1) {
    printf("Usage: %s path/to/ios_binary\n", argv[0]);
    return 0;
  }

  printf("[*] Preparing to execute iOS binary %s\n", argv[1]);
  RunnerOptions options{};
  return run(argv + 1, options);
}