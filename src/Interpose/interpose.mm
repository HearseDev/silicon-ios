#include "interpose.h"

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