/*
 * Youcine-RE - best-effort TrustManager unpin for portal/H5 traffic analysis.
 * Only activates in the target package.
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

function unpin() {
  if (cmdline().indexOf(TARGET) !== 0) {
    return;
  }
  Java.perform(function () {
    try {
      var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TrustManagerImpl.verifyChain.implementation = function (untrusted, tc, host, client, ocsp, tls) {
        return untrusted;
      };
      console.log('[unpin] TrustManagerImpl.verifyChain');
    } catch (e) {
      console.log('[unpin] ' + e);
    }
  });
}

setImmediate(unpin);
