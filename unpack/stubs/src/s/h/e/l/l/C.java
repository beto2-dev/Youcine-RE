package s.h.e.l.l;

/**
 * No-op replacement for the packer's kill-switch trampoline.
 *
 * The decrypted dexes carry injected <clinit> instrumentation: exactly one
 * class ref (Ls/h/e/l/l/C;) per dex (dex_01/02/05), and the original stub
 * declares "public static native void i(int)" - a native trampoline whose
 * native side (files/libijmDataEncryption.so) was only extracted by the
 * packer Application we removed (run 34135095450: crash at
 * FacebookInitProvider.<clinit> -> ClassNotFoundException: s.h.e.l.l.C,
 * then UnsatisfiedLinkError). A plain-Java no-op makes every injected
 * call harmless; no app-code modification is needed.
 */
public class C {
    public static void i(int i) {}
}
