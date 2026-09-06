# Stub sources

Jadx 1.5.6 decompilation of the 14 KiB iJiami `classes.dex`.

These four classes are packer glue, not application logic:

- `S.java` - Application shell, ABI extract of `libexec.so`
- `A.java` - AppComponentFactory, hard-coded origin
  `com.mobile.brasiltv.app.App`
- `N.java` - JNI to `libexec` (`al`, `l`, `r`, `ra`, `b2b`, `m`, `sa`)
- `C.java` - native `i(int)`

Control-flow noise (`new Object(); hashCode();`) is typical iJiami
bogus-code insertion, not a JADX failure.
