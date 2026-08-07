/**************************************************************************************************
 *
 * This file defines various config parameters, used later within the other scripts.
 *
 * In all cases, you'll want to set CERT_PEM and likely PROXY_HOST and PROXY_PORT.
 *
 * Source available at https://github.com/httptoolkit/frida-interception-and-unpinning/
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: Tim Perry <tim@httptoolkit.com>
 *
 *************************************************************************************************/

// Put your CA certificate data here in PEM format:
const CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDNTCCAh2gAwIBAgIULtb7G51bXDjcCYTLtd96a9VE2MkwDQYJKoZIhvcNAQEL
BQAwKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAltaXRtcHJveHkwHhcN
MjYwNTIxMTcxMzA5WhcNMzYwNTE4MTcxMzA5WjAoMRIwEAYDVQQDDAltaXRtcHJv
eHkxEjAQBgNVBAoMCW1pdG1wcm94eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMAQY0RAx9KJceWscNsH+UJV8oxONXHZDynyy6wYaRFBFeAPAv4iqWRG
MEXde5QnWyOagjGW4ala8CgQIEq09AgwYL81tJ3B74Uec5Sy69xkIXR1joUYLm6I
ksEZcdF906hVnUxJG6poI9a1PsRmRxbWrS8ajpDWeD7reWhpem4H5AZUpZ6wdRO9
3n0sui2yeuTOTLeIvRcIovM8qUZ3Z1Q9YfmY8QPVe3GbQ/GDOVjLhrv90snKbrj/
LvEeoMGFk5hS7FcjqbVIXpYKq4WbOHBiMCDk51PlT5BUoDjQ6wsFSIc4pasgjEDB
HDU7wSHr4lue5313ac3VC21jbkousxECAwEAAaNXMFUwDwYDVR0TAQH/BAUwAwEB
/zATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FBqHOu+ODrDAQkINNu8pTrfFxNfRMA0GCSqGSIb3DQEBCwUAA4IBAQBhPKf5cAd0
4182Q9VhJDuf/Enkx96sF95ZyLRlSKr0bzvVqQ2lLqt2UPq60Rx9BAyQlj3Mj1US
ZAh6SAEDtKWHfVXfnOhSO5C+PV2Rqg9XmaWNynoIiMfZHQqm6y9eL1lo5qIOMTK+
ewuY73I8VNTt4HnABpSluKIjqocSwu24l4rr6YpzSLE3sLe914pRQSm1XAVkF1NH
ZqIGUq3E+8lIQs1u/2jsgrJ0BzpfeYhNu9w29KwZkmHtlurG9QYFGqPsOoW9y9im
Cl7vgV8hMfk1Ha5ifvRpR99WluNiizVzeBpQ6GXGFqydcFwsvDckrqJTUp+xxgbV
CH9pzwFxzY1+
-----END CERTIFICATE-----`;

// Put your intercepting proxy's address here:
const PROXY_HOST = '10.0.2.2';
const PROXY_PORT = 8080;

// If you like, set to to true to enable extra logging:
const DEBUG_MODE = true;
var ANTI_DETECT_ONLY = null;
var ANTI_DETECT_SKIP = [];

// If you find issues with non-HTTP traffic being captured (due to the
// native connect hook script) you can add ports here to exempt traffic
// on that port from being redirected. Note that this will only affect
// traffic captured by the raw connection hook - for apps using the
// system HTTP proxy settings, traffic on these ports will still be
// sent via the proxy and intercepted despite this setting.
const IGNORED_NON_HTTP_PORTS = [];

// As HTTP/3 is often not well supported by MitM proxies, by default it
// is blocked entirely, so all outgoing UDP connections to port 443
// will fail. If this is set to false, they will instead be left unintercepted.
const BLOCK_HTTP3 = true;

// Set this to true if your proxy supports SOCKS5 connections.
// This makes it possible for native-connect-hook to redirect
// non-HTTP traffic through your proxy (to view it raw, and
// avoid breaking non-HTTP traffic en route).
const PROXY_SUPPORTS_SOCKS5 = false;


// ----------------------------------------------------------------------------
// You don't need to modify any of the below, it just checks and applies some
// of the configuration that you've entered above.
// ----------------------------------------------------------------------------


if (DEBUG_MODE) {
    // Add logging just for clean output & to separate reloads:
    console.log('\n*** Starting scripts ***');
    if (globalThis.Java?.available) {
        Java.perform(() => {
            setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
            // (We assume that nothing else will take more than 5ms, but app startup
            // probably will, so this should separate script & runtime logs)
        });
    } else {
        setTimeout(() => console.log('*** Scripts completed ***\n'), 5);
        // (We assume that nothing else will take more than 5ms, but app startup
        // probably will, so this should separate script & runtime logs)
    }
} else {
    console.log(''); // Add just a single newline, for minimal clarity
}

// Check the certificate (without literally including the instruction phrasing
// here, as that can be confusing for some users):
if (CERT_PEM.match(/\[!!.* CA certificate data .* !!\]/)) {
    throw new Error('No certificate was provided' +
        '\n\n' +
        'You need to set CERT_PEM in the Frida config script ' +
        'to the contents of your CA certificate.'
    );
}



// ----------------------------------------------------------------------------
// Don't modify any of the below unless you know what you're doing!
// This section defines various utilities & calculates some constants which may
// be used by later scripts elsewhere in this project.
// ----------------------------------------------------------------------------



// As web atob & Node.js Buffer aren't available, we need to reimplement base64 decoding
// in pure JS. This is a quick rough implementation without much error handling etc!

// Base64 character set (plus padding character =) and lookup:
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const BASE64_LOOKUP = new Uint8Array(123);
for (let i = 0; i < BASE64_CHARS.length; i++) {
    BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}


/**
 * Take a base64 string, and return the raw bytes
 * @param {string} input
 * @returns Uint8Array
 */
function decodeBase64(input) {
    // Calculate the length of the output buffer based on padding:
    let outputLength = Math.floor((input.length * 3) / 4);
    if (input[input.length - 1] === '=') outputLength--;
    if (input[input.length - 2] === '=') outputLength--;

    const output = new Uint8Array(outputLength);
    let outputPos = 0;

    // Process each 4-character block:
    for (let i = 0; i < input.length; i += 4) {
        const a = BASE64_LOOKUP[input.charCodeAt(i)];
        const b = BASE64_LOOKUP[input.charCodeAt(i + 1)];
        const c = BASE64_LOOKUP[input.charCodeAt(i + 2)];
        const d = BASE64_LOOKUP[input.charCodeAt(i + 3)];

        // Assemble into 3 bytes:
        const chunk = (a << 18) | (b << 12) | (c << 6) | d;

        // Add each byte to the output buffer, unless it's padding:
        output[outputPos++] = (chunk >> 16) & 0xff;
        if (input.charCodeAt(i + 2) !== 61) output[outputPos++] = (chunk >> 8) & 0xff;
        if (input.charCodeAt(i + 3) !== 61) output[outputPos++] = chunk & 0xff;
    }

    return output;
}

/**
 * Take a single-certificate PEM string, and return the raw DER bytes
 * @param {string} input
 * @returns Uint8Array
 */
function pemToDer(input) {
    const pemLines = input.split('\n');
    if (
        pemLines[0] !== '-----BEGIN CERTIFICATE-----' ||
        pemLines[pemLines.length- 1] !== '-----END CERTIFICATE-----'
    ) {
        throw new Error(
            'Your certificate should be in PEM format, starting & ending ' +
            'with a BEGIN CERTIFICATE & END CERTIFICATE header/footer'
        );
    }

    const base64Data = pemLines.slice(1, -1).map(l => l.trim()).join('');
    if ([...base64Data].some(c => !BASE64_CHARS.includes(c))) {
        throw new Error(
            'Your certificate should be in PEM format, containing only ' +
            'base64 data between a BEGIN & END CERTIFICATE header/footer'
        );
    }

    return decodeBase64(base64Data);
}

const CERT_DER = pemToDer(CERT_PEM);

// Calls the callback with the Frida Module, either immediately if it's already loaded, or as
// soon as it is:
function waitForModule(moduleName, callback) {
    if (Array.isArray(moduleName)) {
        moduleName.forEach(module => waitForModule(module, callback));
    }

    try {
        const module = Process.getModuleByName(moduleName)
        module.ensureInitialized();
        callback(module);
        return;
    } catch (e) {
        try {
            const module = Module.load(moduleName);
            callback(module);
            return;
        } catch (e) {}
    }

    MODULE_LOAD_CALLBACKS[moduleName] = callback;
}

const getModuleName = (nameOrPath) => {
    const endOfPath = nameOrPath.lastIndexOf('/');
    return nameOrPath.slice(endOfPath + 1);
};

const MODULE_LOAD_CALLBACKS = {};

// Frida notifies us as libraries are loaded. We use this rather than hooking dlopen ourselves,
// because on Android 8 & older dlopen works out the calling library's linker namespace from its
// return address - which an inline hook necessarily changes, breaking library loading (and so
// the app) entirely. This also spots libraries loaded straight from an APK, which can't be
// looked up by name afterwards.
Process.attachModuleObserver({
    onAdded(module) {
        const moduleName = getModuleName(module.name || module.path || '');
        const callback = MODULE_LOAD_CALLBACKS[moduleName];
        if (!callback) return;

        delete MODULE_LOAD_CALLBACKS[moduleName];
        callback(module);
    }
});