/*
 * Youcine-RE - soften libexec anti-debug.
 * libc ptrace -> return 0; open/read of /proc/self/status TracerPid stays 0.
 */
'use strict';

var TARGET = 'com.world.youcinemobile';

function cmdline() {
  try {
    var f = new File('/proc/self/cmdline', 'r');
    var s = f.readLine();
    f.close();
    return (s || '').replace(/\u0000/g, '');
  } catch (e) {
    return '';
  }
}

function hook() {
  if (cmdline().indexOf(TARGET) !== 0) {
    return;
  }
  var ptrace = Module.findExportByName('libc.so', 'ptrace');
  if (ptrace) {
    Interceptor.replace(
      ptrace,
      new NativeCallback(
        function (req, pid, addr, data) {
          return 0;
        },
        'long',
        ['int', 'int', 'pointer', 'pointer']
      )
    );
    console.log('[bypass] ptrace replaced');
  }
}

setImmediate(function () {
  try {
    hook();
  } catch (e) {
    console.log('[bypass] ' + e);
  }
});
