# silicon-ios
**Requires SIP to be disabled**


THIS CODE IS A POC AND VERY DIRTY ATM AND WILL BE CLEANED IN THE FUTURE

This is needed for frida
`sudo nvram boot-args="-arm64e_preview_abi"`

If you want to test:
1. `frida -l inject.js UIKitSystem` (This patch is needed for GUI)
2. `make clean all`
3. `DYLD_SHARED_REGION=1 ./build/runner app.app/app`

# Credits
**This would not be possible without the respective efforts of:**
* [Samuel Groß](https://github.com/saelo), Project Zero: [fuzzing-ios-code-on-macos-at-native](https://googleprojectzero.blogspot.com/2021/05/fuzzing-ios-code-on-macos-at-native.html)
* [Mickey Jin/jhftss](https://github.com/jhftss): [Debug-any-iOS-Apps-on-M1-Mac](https://jhftss.github.io/Debug-any-iOS-Apps-on-M1-Mac/)
* [saagarjha](https://gist.github.com/saagarjha): [Load a library into newly spawned processes](https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f)
* [Cryptiiiic](https://github.com/Cryptiiiic): For advice/expertise.
