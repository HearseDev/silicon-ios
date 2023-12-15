# silicon-ios

**Requires SIP to be disabled**

You need ldid to build
`brew install ldid`

You also need to get frida 16.1.8 devkit, macos-arm64e
https://github.com/frida/frida/releases/download/16.1.8/frida-core-devkit-16.1.8-macos-arm64e.tar.xz

move libfrida-core.a to lib

This is needed for frida to hook UIKitSystem (i think)
`sudo nvram boot-args="-arm64e_preview_abi"`

You can run `make clean run_ios_hello_world` or `make clean run_blankapp` to quickly test functionality.

To run:

1. `make clean all`
2. `DYLD_SHARED_REGION=1 ./build/runner /path/to/app.app/app`

# Credits

**This would not be possible without the respective efforts of:**

- [Samuel Groß](https://github.com/saelo), Project Zero: [fuzzing-ios-code-on-macos-at-native](https://googleprojectzero.blogspot.com/2021/05/fuzzing-ios-code-on-macos-at-native.html)
- [Mickey Jin/jhftss](https://github.com/jhftss): [Debug-any-iOS-Apps-on-M1-Mac](https://jhftss.github.io/Debug-any-iOS-Apps-on-M1-Mac/)
- [saagarjha](https://gist.github.com/saagarjha): [Load a library into newly spawned processes](https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f)
- [Cryptiiiic](https://github.com/Cryptiiiic): For advice/expertise.
- [Frida](https://github.com/frida)
