/**************************************************************************************************
 *
 * Emulator / VM, debugger and Frida detection bypass.
 *
 * Complements android-disable-root-detection.js, which only covers su binaries and
 * root manager packages. Apps that survive that often still refuse to run once they
 * notice they are on an emulator, being traced, or being instrumented.
 *
 * Everything is wrapped defensively: the scripts are concatenated into one Frida
 * script, so an uncaught throw here would take the whole bypass chain down with it.
 *
 * Honest limits: this defeats *client-side* checks only. Server-verified attestation
 * (Play Integrity / SafetyNet with a backend check) is not bypassable from here — the
 * verdict is signed by Google and validated off-device.
 *
 *************************************************************************************************/

(function () {
    const LOG = (typeof DEBUG_MODE !== 'undefined') && DEBUG_MODE;
    const say = (m) => { if (LOG) console.log('[anti-detect] ' + m); };

    // A plausible physical Samsung S24 Ultra. Values must be internally consistent —
    // apps cross-check FINGERPRINT against MODEL/BRAND/DEVICE and flag mismatches.
    const FAKE = {
        FINGERPRINT: 'samsung/e3qksxx/e3q:14/UP1A.231005.007/S928BXXU1AXBA:user/release-keys',
        MODEL: 'SM-S928B',
        MANUFACTURER: 'samsung',
        BRAND: 'samsung',
        DEVICE: 'e3q',
        PRODUCT: 'e3qksxx',
        BOARD: 'e3q',
        HARDWARE: 'qcom',
        HOST: 'SWDH8123',
        DISPLAY: 'UP1A.231005.007.S928BXXU1AXBA',
        ID: 'UP1A.231005.007',
        TAGS: 'release-keys',
        TYPE: 'user',
        SERIAL: 'unknown',
        BOOTLOADER: 'S928BXXU1AXBA'
    };

    // Substrings that give away an emulator when they appear in system properties.
    const PROP_TELLS = /goldfish|ranchu|qemu|vbox|genymotion|nox|bluestacks|mumu|nemu|andy|droid4x|ttvm|x86|sdk_gphone|emulator|generic/i;

    // Properties whose mere presence indicates emulation - answer empty.
    const PROP_HIDE = [
        'ro.kernel.qemu', 'ro.kernel.qemu.gles', 'ro.boot.qemu', 'qemu.hw.mainkeys',
        'qemu.sf.fake_camera', 'ro.bootmode', 'init.svc.qemud', 'init.svc.goldfish-logcat',
        'ro.hardware.audio.primary', 'ro.boot.hardware', 'ro.product.vbox'
    ];

    // Files that betray an emulator, Frida, or root. File.exists() must say no.
    const FILE_TELLS = [
        '/dev/socket/qemud', '/dev/qemu_pipe', '/dev/goldfish_pipe', '/dev/socket/genyd',
        '/dev/socket/baseband_genyd', '/system/lib/libc_malloc_debug_qemu.so',
        '/sys/qemu_trace', '/system/bin/qemu-props', '/dev/vboxguest', '/dev/vboxuser',
        '/system/bin/androVM-prop', '/system/bin/microvirtd', '/system/bin/nox-prop',
        '/system/lib/libnoxspeedup.so', '/data/local/tmp/frida-server',
        '/data/local/tmp/re.frida.server', '/system/bin/busybox', '/system/xbin/busybox',
        '/data/adb/magisk', '/sbin/.magisk', '/data/adb/modules', '/cache/magisk.log',
        '/system/addon.d/99-magisk.sh', '/init.magisk.rc', '/system/bin/.ext'
    ];

    // Set ANTI_DETECT_ONLY (in config.js) to a list of module names to enable just
    // those - used to bisect which hook a defensive app reacts badly to.
    const ONLY = (typeof ANTI_DETECT_ONLY !== 'undefined') ? ANTI_DETECT_ONLY : null;
    const SKIP = (typeof ANTI_DETECT_SKIP !== 'undefined') ? ANTI_DETECT_SKIP : [];

    function hookOnce(fn, label) {
        if (ONLY && ONLY.indexOf(label) === -1) { console.log('[anti-detect] disabled: ' + label); return; }
        if (SKIP.indexOf(label) !== -1) { console.log('[anti-detect] skipped: ' + label); return; }
        try { fn(); console.log('[anti-detect] ok: ' + label); }
        catch (e) { console.log('[anti-detect] FAILED ' + label + ': ' + e); }
    }

    Java.perform(function () {

        // ---------------------------------------------------------------- Build fields
        hookOnce(function () {
            const Build = Java.use('android.os.Build');
            let n = 0;
            Object.keys(FAKE).forEach(function (k) {
                try { Build[k].value = FAKE[k]; n++; } catch (e) { /* field absent on this API level */ }
            });
            say('spoofed ' + n + ' android.os.Build fields -> ' + FAKE.MODEL);
        }, 'Build');

        hookOnce(function () {
            const V = Java.use('android.os.Build$VERSION');
            // MuMu reports a stock Android 12; keep it, only ensure no "-eng"/"userdebug" tell.
            try { if (('' + V.CODENAME.value) !== 'REL') V.CODENAME.value = 'REL'; } catch (e) {}
        }, 'Build.VERSION');

        // ---------------------------------------------------------------- system properties
        hookOnce(function () {
            const SP = Java.use('android.os.SystemProperties');
            const clean = function (key, real) {
                if (PROP_HIDE.indexOf(key) !== -1) { say('prop hidden: ' + key); return ''; }
                if (key.indexOf('ro.product.') === 0 || key.indexOf('ro.build.') === 0) {
                    const map = {
                        'ro.product.model': FAKE.MODEL, 'ro.product.brand': FAKE.BRAND,
                        'ro.product.name': FAKE.PRODUCT, 'ro.product.device': FAKE.DEVICE,
                        'ro.product.manufacturer': FAKE.MANUFACTURER, 'ro.product.board': FAKE.BOARD,
                        'ro.build.fingerprint': FAKE.FINGERPRINT, 'ro.build.tags': FAKE.TAGS,
                        'ro.build.type': FAKE.TYPE, 'ro.build.host': FAKE.HOST,
                        'ro.build.display.id': FAKE.DISPLAY, 'ro.build.id': FAKE.ID
                    };
                    if (map[key] !== undefined) return map[key];
                }
                if (real && PROP_TELLS.test('' + real)) { say('prop scrubbed: ' + key + '=' + real); return ''; }
                return real;
            };
            SP.get.overload('java.lang.String').implementation = function (k) {
                return clean(k, this.get(k));
            };
            SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
                return clean(k, this.get(k, d));
            };
            say('SystemProperties.get filtered');
        }, 'SystemProperties');

        // ---------------------------------------------------------------- file tells
        hookOnce(function () {
            const F = Java.use('java.io.File');
            F.exists.implementation = function () {
                let p = '';
                try { p = '' + this.getAbsolutePath(); } catch (e) { return this.exists(); }
                for (let i = 0; i < FILE_TELLS.length; i++) {
                    if (p === FILE_TELLS[i] || p.indexOf(FILE_TELLS[i]) === 0) {
                        say('hid file: ' + p);
                        return false;
                    }
                }
                if (/frida|xposed|substrate|magisk|supersu/i.test(p)) {
                    say('hid file: ' + p);
                    return false;
                }
                return this.exists();
            };
            say('File.exists filtered');
        }, 'File.exists');

        // ---------------------------------------------------------------- debugger
        hookOnce(function () {
            const D = Java.use('android.os.Debug');
            D.isDebuggerConnected.implementation = function () { return false; };
            try { D.waitingForDebugger.implementation = function () { return false; }; } catch (e) {}
            say('debugger checks -> false');
        }, 'Debug');

        // ---------------------------------------------------------------- /proc reads
        // TracerPid != 0 means something is attached; /proc/self/maps names the
        // injected agent. Rewrite both as they are read line by line.
        hookOnce(function () {
            const BR = Java.use('java.io.BufferedReader');
            BR.readLine.overload().implementation = function () {
                const line = this.readLine();
                if (line === null) return line;
                const s = '' + line;
                if (s.indexOf('TracerPid:') === 0) { say('TracerPid masked'); return 'TracerPid:\t0'; }
                if (/frida|gum-js-loop|gmain|linjector|re\.frida|xposed|substrate/i.test(s)) {
                    return '';   // drop the line rather than reveal the agent
                }
                return line;
            };
            say('/proc line reads filtered');
        }, 'BufferedReader');

        // ---------------------------------------------------------------- exec()
        hookOnce(function () {
            const RT = Java.use('java.lang.Runtime');
            const blocked = /\bsu\b|which\s+su|busybox|magisk|getprop\s+ro\.kernel\.qemu|mount|pm\s+list/i;
            RT.exec.overload('java.lang.String').implementation = function (cmd) {
                if (blocked.test('' + cmd)) { say('blocked exec: ' + cmd); throw Java.use('java.io.IOException').$new('error=2, No such file or directory'); }
                return this.exec(cmd);
            };
            RT.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
                try {
                    const joined = Java.use('java.util.Arrays').toString(arr);
                    if (blocked.test('' + joined)) { say('blocked exec: ' + joined); throw Java.use('java.io.IOException').$new('error=2, No such file or directory'); }
                } catch (e) {}
                return this.exec(arr);
            };
            say('Runtime.exec filtered');
        }, 'Runtime.exec');

        // ---------------------------------------------------------------- telephony
        hookOnce(function () {
            const TM = Java.use('android.telephony.TelephonyManager');
            const set = function (name, val) {
                try {
                    TM[name].overloads.forEach(function (o) {
                        o.implementation = function () { return val; };
                    });
                } catch (e) {}
            };
            // Emulators classically report "Android" / all-zero IMEI / 310260.
            set('getNetworkOperatorName', 'Zain IQ');
            set('getSimOperatorName', 'Zain IQ');
            set('getNetworkOperator', '41830');
            set('getSimOperator', '41830');
            set('getDeviceId', '354879104325678');
            set('getImei', '354879104325678');
            set('getSimSerialNumber', '8996411830123456789');
            set('getSubscriberId', '418300123456789');
            say('telephony identifiers spoofed');
        }, 'TelephonyManager');

        // ---------------------------------------------------------------- sensors
        // A device with zero sensors is a strong emulator tell.
        hookOnce(function () {
            const SM = Java.use('android.hardware.SensorManager');
            SM.getSensorList.implementation = function (type) {
                const list = this.getSensorList(type);
                try { if (list.size() === 0) say('empty sensor list for type ' + type + ' (emulator tell)'); } catch (e) {}
                return list;
            };
        }, 'SensorManager');

        say('anti-detection installed (emulator/VM, debugger, tracer, exec, telephony)');
    });

    console.log('== Emulator / debugger / Frida detection bypass installed ==');
})();
