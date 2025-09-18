// block_exit.js
// Frida script to neutralize exit/abort/kill/raise and UIApplication termination attempts.
// Usage examples:
// 1) Attach to running process: frida -U -n <process_name> -l block_exit.js
// 2) Spawn & inject: frida -U -f <bundle.identifier> -l block_exit.js --no-pause

'use strict';

rpc.exports = {}; // (선택) 필요하면 외부에서 RPC 호출 가능

function safeLog() {
    try {
        console.log.apply(console, arguments);
    } catch (e) {}
}

function replaceLibcVoidInt(name) {
    var ptr = Module.findExportByName(null, name);
    if (ptr) {
        safeLog("[frida] found " + name + " @ " + ptr);
        Interceptor.replace(ptr, new NativeCallback(function (status) {
            safeLog("[frida] " + name + "(" + status + ") intercepted — blocked");
            // no-op: do nothing, so process does not exit
        }, 'void', ['int']));
    } else {
        safeLog("[frida] " + name + " not found");
    }
}

function replaceLibcVoidNoArgs(name) {
    var ptr = Module.findExportByName(null, name);
    if (ptr) {
        safeLog("[frida] found " + name + " @ " + ptr);
        Interceptor.replace(ptr, new NativeCallback(function () {
            safeLog("[frida] " + name + "() intercepted — blocked");
            // no-op
        }, 'void', []));
    } else {
        safeLog("[frida] " + name + " not found");
    }
}

function replaceLibcIntTwoInts(name) {
    var ptr = Module.findExportByName(null, name);
    if (ptr) {
        safeLog("[frida] found " + name + " @ " + ptr);
        Interceptor.replace(ptr, new NativeCallback(function (pid, sig) {
            safeLog("[frida] " + name + "(" + pid + ", " + sig + ") intercepted — returning 0");
            return 0; // pretend success but do not actually kill
        }, 'int', ['int', 'int']));
    } else {
        safeLog("[frida] " + name + " not found");
    }
}

function replaceLibcIntOneInt(name) {
    var ptr = Module.findExportByName(null, name);
    if (ptr) {
        safeLog("[frida] found " + name + " @ " + ptr);
        Interceptor.replace(ptr, new NativeCallback(function (sig) {
            safeLog("[frida] " + name + "(" + sig + ") intercepted — returning 0");
            return 0;
        }, 'int', ['int']));
    } else {
        safeLog("[frida] " + name + " not found");
    }
}

function hookObjCTerminateMethods() {
    if (ObjC.available) {
        try {
            var UIApplication = ObjC.classes.UIApplication;
            if (UIApplication) {
                // -terminateWithSuccess (private API) — 존재하면 훅
                try {
                    var sel1 = ObjC.selector('terminateWithSuccess');
                    if (UIApplication.prototype.hasOwnProperty('-terminateWithSuccess') || UIApplication.instancesRespondToSelector_(sel1)) {
                        var orig_imp1 = UIApplication['-terminateWithSuccess'].implementation;
                        UIApplication['-terminateWithSuccess'].implementation = ObjC.implement(UIApplication['-terminateWithSuccess'], function (handle, sel) {
                            safeLog("[frida][objc] -[UIApplication terminateWithSuccess] called — blocked");
                            // no-op
                        });
                        safeLog("[frida][objc] hooked -terminateWithSuccess");
                    }
                } catch (e) {
                    // some runtimes might throw; ignore
                }

                // -terminate (older/private) — 훅 시도
                try {
                    var sel2 = ObjC.selector('terminate');
                    if (UIApplication.prototype.hasOwnProperty('-terminate') || UIApplication.instancesRespondToSelector_(sel2)) {
                        UIApplication['-terminate'].implementation = ObjC.implement(UIApplication['-terminate'], function (handle, sel) {
                            safeLog("[frida][objc] -[UIApplication terminate] called — blocked");
                        });
                        safeLog("[frida][objc] hooked -terminate");
                    }
                } catch (e) {
                    // ignore
                }
            } else {
                safeLog("[frida][objc] UIApplication class not available");
            }
        } catch (e) {
            safeLog("[frida][objc] error while hooking UIApplication methods: " + e);
        }
    } else {
        safeLog("[frida] ObjC runtime not available");
    }
}

function hookCommon() {
    // exit(int)
    replaceLibcVoidInt('exit');
    // _exit(int)
    replaceLibcVoidInt('_exit');
    // abort(void)
    replaceLibcVoidNoArgs('abort');
    // raise(int)
    replaceLibcIntOneInt('raise');
    // kill(pid_t, sig)
    replaceLibcIntTwoInts('kill');
    // killpg might be used in some libs
    replaceLibcIntTwoInts('killpg');
    // If other libc functions are used, add them similarly
}

function tryAttachInterceptors() {
    try {
        hookCommon();
        hookObjCTerminateMethods();

        // Optional: attach to objc_msgSend to observe calls that may lead to termination.
        // WARNING: heavy — 주석 처리된 상태로 둠. 필요하면 활성화.
        /*
        var objcMsg = Module.findExportByName(null, "objc_msgSend");
        if (objcMsg) {
            Interceptor.attach(objcMsg, {
                onEnter: function (args) {
                    try {
                        // args[1] is SEL
                        var sel = ObjC.selectorAsString(args[1]);
                        if (sel && (sel.indexOf("terminate") !== -1 || sel.indexOf("exit") !== -1)) {
                            safeLog("[frida][objc_msgSend] selector: " + sel);
                        }
                    } catch (e) {}
                }
            });
        }
        */

        safeLog("[frida] hooks installed");
    } catch (e) {
        safeLog("[frida] error installing hooks: " + e);
    }
}

// Delay hook until modules are loaded (특히 spawn 모드에서)
setTimeout(tryAttachInterceptors, 200);