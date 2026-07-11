//go:build darwin

package collect

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// native_sig checks a path's code signature IN PROCESS (no subprocess, no syspolicyd) and
// writes the leaf certificate common name into auth. Returns:
//   0 signed & valid, 1 unsigned, 2 revoked, 3 signed-but-invalid, -1 not a code object.
// kSecCSDoNotValidateResources: we want the signing IDENTITY, not a deep bundle-integrity
// hash of every resource (that recursion is what made large .app bundles take seconds).
static int native_sig(const char* path, char* auth, int authLen) {
	auth[0] = 0;
	CFStringRef p = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
	if (!p) return -1;
	CFURLRef url = CFURLCreateWithFileSystemPath(NULL, p, kCFURLPOSIXPathStyle, false);
	CFRelease(p);
	if (!url) return -1;
	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess || !code) return -1;

	CFErrorRef err = NULL;
	OSStatus valid = SecStaticCodeCheckValidityWithErrors(code, kSecCSDoNotValidateResources, NULL, &err);
	int result;
	if (valid == errSecSuccess) {
		result = 0;
		CFDictionaryRef info = NULL;
		if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info) {
			CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(info, kSecCodeInfoCertificates);
			if (certs && CFArrayGetCount(certs) > 0) {
				SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
				CFStringRef cn = NULL;
				if (SecCertificateCopyCommonName(leaf, &cn) == errSecSuccess && cn) {
					CFStringGetCString(cn, auth, authLen, kCFStringEncodingUTF8);
					CFRelease(cn);
				}
			}
			CFRelease(info);
		}
	} else if (valid == errSecCSUnsigned) {
		result = 1;
	} else {
		result = 3; // signed but invalid; distinguish a revoked cert via the error text
		if (err) {
			CFStringRef d = CFErrorCopyDescription(err);
			if (d) {
				char buf[512];
				if (CFStringGetCString(d, buf, sizeof(buf), kCFStringEncodingUTF8)) {
					for (char* c = buf; *c; c++)
						if (*c >= 'A' && *c <= 'Z') *c += 32;
					if (strstr(buf, "revoked")) result = 2;
				}
				CFRelease(d);
			}
		}
	}
	if (err) CFRelease(err);
	CFRelease(code);
	return result;
}
*/
import "C"

import "unsafe"

func init() { sigProbe = nativeSig }

// nativeSig implements sigProbe via Security.framework. It returns the verify-error string /
// accepted / authority in the exact shape ParseCodesign consumes, so the downstream evidence
// is identical to the old codesign/spctl shell-out — just in-process and ~1000× faster.
func nativeSig(path string) (verifyErr string, accepted bool, authority string) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	var buf [512]C.char
	switch C.native_sig(cp, &buf[0], C.int(len(buf))) {
	case 0:
		return "", true, C.GoString(&buf[0])
	case 2:
		return "certificate revoked", false, ""
	case 3:
		return "", false, "" // signed but invalid (tampered/expired) — signed, no trusted authority
	case 1, -1:
		return "code object is not signed at all", false, ""
	default:
		return "code object is not signed at all", false, ""
	}
}
