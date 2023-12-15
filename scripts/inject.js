// This is the script that will be injected into the target process, this file is just here for testing purposes.
// The script is already loaded by uikitsystem_patch.mm
function getOCMethodName(className, funcName) {
  var hook = eval("ObjC.classes." + className + '["' + funcName + '"]');
  return hook;
}

function returnTrueOrFalse(type, targetClass, targetMethod, ret) {
  const targetMethodAddress = getOCMethodName(
    targetClass,
    `${type} ${targetMethod}`
  );
  if (targetMethodAddress !== null) {
    console.log(
      "[*] Found address of " +
        targetClass +
        " " +
        targetMethod +
        ": " +
        targetMethodAddress
    );

    // Interceptor to hook the method
    Interceptor.attach(targetMethodAddress.implementation, {
      onEnter: function (args) {
        console.log("Hooked -[" + targetClass + " " + targetMethod + "]");
        // Add your custom logic here
        // You can access method arguments using args[0], args[1], etc.
      },
      onLeave: function (retval) {
        // Add your custom logic here
        // Modify the return value to true
        retval.replace(ret); // 1 corresponds to true for boolean values
      },
    });
  } else {
    console.error(
      "Could not find the address of " + targetClass + " " + targetMethod
    );
  }
}

returnTrueOrFalse("-", "RBSProcessIdentity", "isApplication", 1);
returnTrueOrFalse("-", "FBProcess", "isApplicationProcess", 1);
