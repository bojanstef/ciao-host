//! Typed Security/CoreFoundation boundary. No display parser and no skip-validation flags.
use super::CodeHash;
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::c_void,
    path::{Path, PathBuf},
    ptr,
};
type Ref = *const c_void;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFGetTypeID(value: Ref) -> usize;
    fn CFDataGetTypeID() -> usize;
    fn CFDataGetLength(value: Ref) -> isize;
    fn CFDataGetBytePtr(value: Ref) -> *const u8;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(value: Ref) -> isize;
    fn CFArrayGetValueAtIndex(value: Ref, index: isize) -> Ref;
    fn CFStringGetTypeID() -> usize;
    fn CFStringCreateWithBytes(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: bool,
    ) -> Ref;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: Ref,
        bytes: *const u8,
        length: isize,
        directory: bool,
    ) -> Ref;
    fn CFURLGetFileSystemRepresentation(
        url: Ref,
        resolve: bool,
        buffer: *mut u8,
        size: isize,
    ) -> bool;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
    fn CFDictionaryCreate(
        allocator: Ref,
        keys: *const Ref,
        values: *const Ref,
        count: isize,
        key_callbacks: Ref,
        value_callbacks: Ref,
    ) -> Ref;
    fn CFNumberCreate(allocator: Ref, kind: isize, value: *const c_void) -> Ref;
}
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: Ref;
    static kSecCodeInfoUnique: Ref;
    static kSecCodeInfoCdHashes: Ref;
    static kSecCodeInfoIdentifier: Ref;
    static kSecCodeInfoPList: Ref;
    fn SecStaticCodeCreateWithPath(path: Ref, flags: u32, out: *mut Ref) -> i32;
    fn SecCodeCopyPath(code: Ref, flags: u32, out: *mut Ref) -> i32;
    fn SecCodeCopySigningInformation(code: Ref, flags: u32, out: *mut Ref) -> i32;
    fn SecRequirementCreateWithString(text: Ref, flags: u32, out: *mut Ref) -> i32;
    fn SecStaticCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    fn SecCodeCopyGuestWithAttributes(host: Ref, attributes: Ref, flags: u32, out: *mut Ref)
    -> i32;
    fn SecCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
}
struct Owned(Ref);
impl Owned {
    fn new(value: Ref) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
    fn call(f: impl FnOnce(*mut Ref) -> i32) -> Option<Self> {
        let mut value = ptr::null();
        let status = f(&mut value);
        let result = Self::new(value);
        if status == 0 { result } else { None }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: one release for a non-null retained CF object from a Create/Copy function.
        unsafe { CFRelease(self.0) }
    }
}
fn static_code(path: &Path) -> Option<Owned> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= 4096 || bytes.contains(&0) {
        return None;
    }
    // SAFETY: bytes stays alive for the call. Returned objects are checked and owned.
    unsafe {
        let url = Owned::new(CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            bytes.as_ptr(),
            bytes.len() as isize,
            false,
        ))?;
        let code = Owned::call(|out| SecStaticCodeCreateWithPath(url.0, 0, out))?;
        let actual = Owned::call(|out| SecCodeCopyPath(code.0, 0, out))?;
        let mut buffer = [0u8; 4096];
        if !CFURLGetFileSystemRepresentation(
            actual.0,
            false,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
        ) {
            return None;
        }
        let end = buffer.iter().position(|b| *b == 0)?;
        // Refuse Security's bundle association rather than flattening a bundle silently.
        if &buffer[..end] != bytes {
            return None;
        }
        Some(code)
    }
}
fn requirement(hash: &CodeHash) -> Option<Owned> {
    CodeHash::parse(hash.as_str())?;
    let text = format!("cdhash H\"{}\"", hash.as_str());
    // SAFETY: fixed ASCII grammar from a validated, exactly 20-byte hex digest.
    unsafe {
        let text = Owned::new(CFStringCreateWithBytes(
            ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            0x0600,
            false,
        ))?;
        Owned::call(|out| SecRequirementCreateWithString(text.0, 0, out))
    }
}
fn data_hash(data: Ref) -> Option<CodeHash> {
    // SAFETY: borrowed dictionary/array value remains alive; type and size checked before access.
    unsafe {
        if data.is_null() || CFGetTypeID(data) != CFDataGetTypeID() || CFDataGetLength(data) != 20 {
            return None;
        }
        let bytes = CFDataGetBytePtr(data);
        if bytes.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(bytes, 20);
        CodeHash::parse(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
    }
}
/// This is candidate data ONLY. Both static and dynamic validity must subsequently succeed.
pub(super) fn candidate_hash(path: &Path) -> Option<CodeHash> {
    let code = static_code(path)?;
    // SAFETY: all API values are non-null, owned for their use, and type checked.
    unsafe {
        let info = Owned::call(|out| SecCodeCopySigningInformation(code.0, 2, out))?;
        if CFGetTypeID(info.0) != CFDictionaryGetTypeID() {
            return None;
        }
        let identifier = CFDictionaryGetValue(info.0, kSecCodeInfoIdentifier);
        if identifier.is_null()
            || CFGetTypeID(identifier) != CFStringGetTypeID()
            || !CFDictionaryGetValue(info.0, kSecCodeInfoPList).is_null()
        {
            return None;
        }
        let hash = data_hash(CFDictionaryGetValue(info.0, kSecCodeInfoUnique))?;
        let hashes = CFDictionaryGetValue(info.0, kSecCodeInfoCdHashes);
        if hashes.is_null()
            || CFGetTypeID(hashes) != CFArrayGetTypeID()
            || CFArrayGetCount(hashes) != 1
        {
            return None;
        }
        (data_hash(CFArrayGetValueAtIndex(hashes, 0))? == hash).then_some(hash)
    }
}
pub(super) fn validate_copy(path: &Path, hash: &CodeHash) -> Option<()> {
    let code = static_code(path)?;
    let requirement = requirement(hash)?;
    // SAFETY: retained code and requirement, DEFAULT validates all sealed components.
    (unsafe { SecStaticCodeCheckValidity(code.0, 0, requirement.0) } == 0).then_some(())
}
pub(super) fn dynamic(pid: u32, hash: &CodeHash) -> Option<()> {
    let pid = i32::try_from(pid).ok()?;
    if pid <= 0 {
        return None;
    }
    let requirement = requirement(hash)?;
    // SAFETY: dictionary has one borrowed key/value kept alive through guest lookup. CFNumber
    // kCFNumberIntType=9 reads the initialized i32; no object escapes its lifetime.
    unsafe {
        let number = Owned::new(CFNumberCreate(ptr::null(), 9, ptr::from_ref(&pid).cast()))?;
        let keys = [kSecGuestAttributePid];
        let values = [number.0];
        let attrs = Owned::new(CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        ))?;
        let code = Owned::call(|out| SecCodeCopyGuestWithAttributes(ptr::null(), attrs.0, 0, out))?;
        (SecCodeCheckValidity(code.0, 0, requirement.0) == 0).then_some(())
    }
}
pub(super) fn candidate_path(pid: u32) -> Option<PathBuf> {
    let pid = i32::try_from(pid).ok()?;
    let mut bytes = [0u8; 4096];
    // SAFETY: bounded writable buffer, kernel retains no pointer.
    let size =
        unsafe { nix::libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if size <= 0 {
        return None;
    }
    let end = bytes.iter().position(|b| *b == 0)?;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]));
    if !path.is_absolute()
        || path.components().any(|c| {
            let text = c.as_os_str().as_bytes().to_ascii_lowercase();
            [
                b".app".as_slice(),
                b".bundle",
                b".framework",
                b".xpc",
                b".appex",
                b".plugin",
                b".kext",
            ]
            .iter()
            .any(|suffix| text.ends_with(suffix))
        })
    {
        return None;
    }
    Some(path)
}
pub(super) fn native_arm64(pid: u32) -> bool {
    if !cfg!(target_arch = "aarch64") {
        return false;
    }
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    let mut arch = [0i32; 2];
    // SAFETY: PROC_PIDARCHINFO=19 writes two native 32-bit cpu type/subtype fields.
    let size = unsafe { nix::libc::proc_pidinfo(pid, 19, 0, arch.as_mut_ptr().cast(), 8) };
    size == 8 && arch == [0x0100000c, 0]
}
