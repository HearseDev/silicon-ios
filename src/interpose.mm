#include <stdio.h>
#include <unistd.h>
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

// From
// https://opensource.apple.com/source/dyld/dyld-97.1/include/mach-o/dyld-interposing.h.auto.html

xpc_object_t my_xpc_copy_entitlements_for_self() {
  printf("[*] Faking com.apple.private.security.no-sandbox entitlement in "
         "interposed xpc_copy_entitlements_for_self\n");
  xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_value(dict, "com.apple.private.security.no-sandbox",
                           xpc_bool_create(1));
  return dict;
}
DYLD_INTERPOSE(my_xpc_copy_entitlements_for_self,
               xpc_copy_entitlements_for_self);
