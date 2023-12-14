#include <stdio.h>
#include <unistd.h>

// From
// https://opensource.apple.com/source/dyld/dyld-97.1/include/mach-o/dyld-interposing.h.auto.html

#if __cplusplus
extern "C" {
#endif
typedef void *xpc_object_t;
extern xpc_object_t xpc_dictionary_create(void *, void *, int);
extern void xpc_dictionary_set_value(xpc_object_t, const char *, xpc_object_t);
extern xpc_object_t xpc_bool_create(int);
extern xpc_object_t xpc_copy_entitlements_for_self();
#if __cplusplus
}
#endif

#define DYLD_INTERPOSE(_replacment, _replacee)                                 \
  __attribute__((used)) static struct {                                        \
    const void *replacment;                                                    \
    const void *replacee;                                                      \
  } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {  \
      (const void *)(unsigned long)&_replacment,                               \
      (const void *)(unsigned long)&_replacee};