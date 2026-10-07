//! The JNI surface of `pith-video`: the entry points the Java SDK
//! (`sdk/java`) bind through after `System.load`ing this cdylib.
//!
//! The names follow the JVM's resolve convention for
//! `package hash.pith` + `class PithVideo`: `Java_hash_pith_PithVideo_<method>`.
//! The existing C ABI in [`crate::ffi`] is untouched — this module only
//! adds `Java_*` symbols and routes through the same safe cores.
//!
//! # The JNIEnv function table
//!
//! Every JNI call goes through the table `env` points at. The suite
//! carries no third-party crates, so the needed prefix of
//! `struct JNINativeInterface_` is declared here: every slot is one
//! pointer wide, unused runs ride as opaque gap arrays, and the slot
//! indices are the JNI standard order verified against OpenJDK's
//! `include/jni.h` (FindClass = 6, Throw = 13, ThrowNew = 14,
//! NewObjectA = 30, GetMethodID = 33, NewStringUTF = 167,
//! GetArrayLength = 171, NewByteArray = 176, GetByteArrayRegion = 200,
//! SetByteArrayRegion = 208). [`new_object_a`] is used — not the
//! varargs `NewObject` — so no call site depends on a varargs ABI.
//!
//! # Error convention
//!
//! Refusals never unwind into the JVM: the export throws
//! `hash.pith.PithFfiException(status, message)` (status codes as in
//! [`crate::ffi`]: `-1` invalid argument, `-2` core refusal) and
//! returns a Java `null`; if the exception class cannot be resolved,
//! a plain `java.lang.RuntimeException` is thrown via `ThrowNew`.

#![allow(unsafe_code)]

use alloc::ffi::CString;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};

use crate::ffi::{PITH_E_INVALID, fingerprint_and_serialize};

/// An opaque JVM object handle (`jobject` and friends in `jni.h`).
#[repr(C)]
pub struct JObject {
    _opaque: [u8; 0],
}

/// `jobject`.
pub type Jobject = *mut JObject;
/// `jclass` / `jarray` / `jstring` / `jbyteArray` — all object handles.
pub type JClass = Jobject;
/// See [`JClass`].
pub type Jarray = Jobject;
/// See [`JClass`].
pub type Jstring = Jobject;
/// See [`JClass`].
pub type JbyteArray = Jobject;
/// `jmethodID` — an opaque method handle.
pub type JmethodID = *mut JObject;
/// `jbyte`.
type Jbyte = i8;
/// `jint` / `jsize`.
type Jint = i32;

/// The `jvalue` argument union (`jni.h`): a slot in `NewObjectA`'s
/// argument vector. Only the two members the exception constructor
/// needs are named.
#[repr(C)]
#[derive(Clone, Copy)]
union JValue {
    /// The `jint` view (the exception status).
    int_value: Jint,
    /// The object view (the exception message).
    object_value: Jobject,
}

/// The used prefix of `struct JNINativeInterface_`: every slot is one
/// pointer wide, so the unused runs between the named slots (with
/// their JNI-standard indices in the comments) are pointer arrays and
/// the layout stays exact.
#[repr(C)]
pub struct JnInterface {
    // Slots 0-3 are reserved and always null; plain raw pointers — an
    // `Option<*mut c_void>` here would be 16 bytes (raw pointers have
    // no null niche) and would shift every later slot by four.
    reserved: [*mut c_void; 4],
    // Slots 4-5: GetVersion, DefineClass.
    gap_a: [Option<unsafe extern "system" fn()>; 2],
    find_class: Option<unsafe extern "system" fn(*mut JNIEnv, *const c_char) -> JClass>,
    // Slots 7-12: FromReflectedMethod .. ToReflectedField.
    gap_b: [Option<unsafe extern "system" fn()>; 6],
    throw_fn: Option<unsafe extern "system" fn(*mut JNIEnv, Jobject) -> Jint>,
    throw_new: Option<unsafe extern "system" fn(*mut JNIEnv, JClass, *const c_char) -> Jint>,
    // Slots 15-29: ExceptionOccurred .. EnsureLocalCapacity, AllocObject.
    gap_c: [Option<unsafe extern "system" fn()>; 15],
    new_object_a:
        Option<unsafe extern "system" fn(*mut JNIEnv, JClass, JmethodID, *const JValue) -> Jobject>,
    // Slots 31-32: GetObjectClass, IsInstanceOf.
    gap_d: [Option<unsafe extern "system" fn()>; 2],
    get_method_id: Option<
        unsafe extern "system" fn(*mut JNIEnv, JClass, *const c_char, *const c_char) -> JmethodID,
    >,
    // Slots 34-166: reflected/field/string/ops up to GetStringUTFLength.
    gap_e: [Option<unsafe extern "system" fn()>; 133],
    new_string_utf: Option<unsafe extern "system" fn(*mut JNIEnv, *const c_char) -> Jstring>,
    // Slots 168-170: GetStringLength, GetStringChars, ReleaseStringChars.
    gap_f: [Option<unsafe extern "system" fn()>; 3],
    get_array_length: Option<unsafe extern "system" fn(*mut JNIEnv, Jarray) -> Jint>,
    // Slots 172-175: NewObjectArray .. NewBooleanArray.
    gap_g: [Option<unsafe extern "system" fn()>; 4],
    new_byte_array: Option<unsafe extern "system" fn(*mut JNIEnv, Jint) -> JbyteArray>,
    // Slots 177-199: New/Get/Set region slots for the other array kinds.
    gap_h: [Option<unsafe extern "system" fn()>; 23],
    get_byte_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JbyteArray, Jint, Jint, *mut Jbyte)>,
    // Slots 201-207: Get/Set regions for char..double.
    gap_i: [Option<unsafe extern "system" fn()>; 7],
    set_byte_array_region:
        Option<unsafe extern "system" fn(*mut JNIEnv, JbyteArray, Jint, Jint, *const Jbyte)>,
}

/// `JNIEnv` is itself a pointer to the function table (`typedef const
/// struct JNINativeInterface *JNIEnv;`).
pub type JNIEnv = *const JnInterface;

/// JNI binding of
/// [`pith_video_fingerprint`](crate::ffi::pith_video_fingerprint) for
/// `PithVideo.fingerprint(byte[])`: decodes the whole ISO-BMFF input
/// and hands back the canonical stream (`byte[]`) the `reference.json`
/// vectors are defined over. A null input array or a null `env` is a
/// thrown `-1`; every decode refusal is a thrown `-2`.
///
/// # Safety
///
/// `env` must be the `JNIEnv*` the JVM passed in (or null, which is
/// reported as `-1`); `input` must be a `jbyteArray` handle (or null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_hash_pith_PithVideo_fingerprint(
    env: *mut JNIEnv,
    _class: JClass,
    input: JbyteArray,
) -> JbyteArray {
    match unsafe { read_byte_array(env, input) } {
        Some(bytes) => unsafe {
            byte_array(
                env,
                "pith_video_fingerprint",
                fingerprint_and_serialize(&bytes),
            )
        },
        None => {
            unsafe { throw_status(env, "pith_video_fingerprint", PITH_E_INVALID) };
            core::ptr::null_mut()
        }
    }
}

/// Reads a Java `byte[]` through `env` into a native buffer. `None`
/// for a null `env` or a null array — the caller maps that to `-1`.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null; `array` must be a
/// `jbyteArray` handle owned by the caller or null.
unsafe fn read_byte_array(env: *mut JNIEnv, array: JbyteArray) -> Option<Vec<u8>> {
    if env.is_null() || array.is_null() {
        return None;
    }
    let table = unsafe { &*(*env) };
    let len = unsafe { (table.get_array_length.expect("GetArrayLength slot"))(env, array) };
    let mut bytes = alloc::vec![0u8; len as usize];
    unsafe {
        (table
            .get_byte_array_region
            .expect("GetByteArrayRegion slot"))(
            env, array, 0, len, bytes.as_mut_ptr().cast()
        )
    };
    Some(bytes)
}

/// Copies a safe-core result into a fresh Java `byte[]`; a refusal
/// throws and returns null. A failed `NewByteArray` (the JVM has a
/// pending `OutOfMemoryError`) returns null without throwing.
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn byte_array(env: *mut JNIEnv, op: &str, result: Result<Vec<u8>, i32>) -> JbyteArray {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(status) => {
            unsafe { throw_status(env, op, status) };
            return core::ptr::null_mut();
        }
    };
    let table = unsafe { &*(*env) };
    let array =
        unsafe { (table.new_byte_array.expect("NewByteArray slot"))(env, bytes.len() as Jint) };
    if array.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        (table
            .set_byte_array_region
            .expect("SetByteArrayRegion slot"))(
            env,
            array,
            0,
            bytes.len() as Jint,
            bytes.as_ptr().cast(),
        )
    };
    array
}

/// Throws `hash.pith.PithFfiException(status, "<op> failed with
/// status <status>")`; every resolution failure on the way falls back
/// to `ThrowNew(java.lang.RuntimeException)`. A null `env` has no JVM
/// to throw into and returns quietly (the Java caller sees `null`).
///
/// # Safety
///
/// `env` must be a valid JVM environment or null.
unsafe fn throw_status(env: *mut JNIEnv, op: &str, status: i32) {
    if env.is_null() {
        return;
    }
    let table = unsafe { &*(*env) };
    let Ok(text) = CString::new(alloc::format!("{op} failed with status {status}")) else {
        return;
    };
    let class = unsafe {
        (table.find_class.expect("FindClass slot"))(env, c"hash/pith/PithFfiException".as_ptr())
    };
    if class.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let ctor = unsafe {
        (table.get_method_id.expect("GetMethodID slot"))(
            env,
            class,
            c"<init>".as_ptr(),
            c"(Ljava/lang/String;I)V".as_ptr(),
        )
    };
    if ctor.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let message = unsafe { (table.new_string_utf.expect("NewStringUTF slot"))(env, text.as_ptr()) };
    if message.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    let args = [
        JValue {
            object_value: message,
        },
        JValue { int_value: status },
    ];
    let thrown =
        unsafe { (table.new_object_a.expect("NewObjectA slot"))(env, class, ctor, args.as_ptr()) };
    if thrown.is_null() {
        unsafe { throw_runtime(env, table, &text) };
        return;
    }
    unsafe { (table.throw_fn.expect("Throw slot"))(env, thrown) };
}

/// The `ThrowNew(java.lang.RuntimeException, msg)` fallback for when
/// the typed exception cannot be constructed.
///
/// # Safety
///
/// `env` must be a valid JVM environment; `table` must be the table
/// `env` points at; `text` must be a valid C string.
unsafe fn throw_runtime(env: *mut JNIEnv, table: &JnInterface, text: &CString) {
    let class = unsafe {
        (table.find_class.expect("FindClass slot"))(env, c"java/lang/RuntimeException".as_ptr())
    };
    if !class.is_null() {
        unsafe { (table.throw_new.expect("ThrowNew slot"))(env, class, text.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::path::Path;

    thread_local! {
        static JVM: Jvm = Jvm::default();
    }

    /// The fake JVM state the fake slots operate on: canned array
    /// storage plus failure masks that drive every defensive arm.
    #[derive(Default)]
    struct Jvm {
        /// Fails only the FIRST FindClass (the typed exception), so
        /// the RuntimeException fallback lookup still succeeds.
        fail_first_find_class: Cell<bool>,
        find_class_calls: Cell<u32>,
        fail_method_id: Cell<bool>,
        fail_string: Cell<bool>,
        fail_new_object: Cell<bool>,
        fail_new_byte_array: Cell<bool>,
        /// The status argument the last `NewObjectA` saw (0 = none).
        pending_status: Cell<i32>,
        /// Whether the fake `Throw` ran.
        threw: Cell<bool>,
        /// How many times the `ThrowNew` fallback ran.
        throw_new_calls: Cell<u32>,
        /// Array handles are `(index + 1)` cast to a pointer.
        arrays: std::cell::RefCell<Vec<Vec<u8>>>,
    }

    fn reset() {
        JVM.with(|j| {
            j.fail_first_find_class.set(false);
            j.find_class_calls.set(0);
            j.fail_method_id.set(false);
            j.fail_string.set(false);
            j.fail_new_object.set(false);
            j.fail_new_byte_array.set(false);
            j.pending_status.set(0);
            j.threw.set(false);
            j.throw_new_calls.set(0);
            j.arrays.borrow_mut().clear();
        });
    }

    fn push_array(bytes: &[u8]) -> JbyteArray {
        JVM.with(|j| {
            j.arrays.borrow_mut().push(bytes.to_vec());
            (j.arrays.borrow().len()) as JbyteArray
        })
    }

    fn array_bytes(handle: JbyteArray) -> Vec<u8> {
        JVM.with(|j| j.arrays.borrow()[(handle as usize) - 1].clone())
    }

    unsafe extern "system" fn fake_find_class(_env: *mut JNIEnv, _name: *const c_char) -> JClass {
        JVM.with(|j| {
            let call = j.find_class_calls.get();
            j.find_class_calls.set(call + 1);
            if call == 0 && j.fail_first_find_class.get() {
                core::ptr::null_mut()
            } else {
                0x10usize as JClass
            }
        })
    }

    unsafe extern "system" fn fake_throw_fn(_env: *mut JNIEnv, _obj: Jobject) -> Jint {
        JVM.with(|j| j.threw.set(true));
        0
    }

    unsafe extern "system" fn fake_throw_new(
        _env: *mut JNIEnv,
        _class: JClass,
        _msg: *const c_char,
    ) -> Jint {
        JVM.with(|j| j.throw_new_calls.set(j.throw_new_calls.get() + 1));
        0
    }

    unsafe extern "system" fn fake_new_object_a(
        _env: *mut JNIEnv,
        _class: JClass,
        _method: JmethodID,
        args: *const JValue,
    ) -> Jobject {
        JVM.with(|j| {
            if j.fail_new_object.get() {
                core::ptr::null_mut()
            } else {
                j.pending_status.set(unsafe { (*args.add(1)).int_value });
                0x40usize as Jobject
            }
        })
    }

    unsafe extern "system" fn fake_get_method_id(
        _env: *mut JNIEnv,
        _class: JClass,
        _name: *const c_char,
        _sig: *const c_char,
    ) -> JmethodID {
        JVM.with(|j| {
            if j.fail_method_id.get() {
                core::ptr::null_mut()
            } else {
                0x20usize as JmethodID
            }
        })
    }

    unsafe extern "system" fn fake_new_string_utf(
        _env: *mut JNIEnv,
        _text: *const c_char,
    ) -> Jstring {
        JVM.with(|j| {
            if j.fail_string.get() {
                core::ptr::null_mut()
            } else {
                0x30usize as Jstring
            }
        })
    }

    unsafe extern "system" fn fake_get_array_length(_env: *mut JNIEnv, array: Jarray) -> Jint {
        JVM.with(|j| j.arrays.borrow()[(array as usize) - 1].len() as Jint)
    }

    unsafe extern "system" fn fake_new_byte_array(_env: *mut JNIEnv, len: Jint) -> JbyteArray {
        JVM.with(|j| {
            if j.fail_new_byte_array.get() {
                core::ptr::null_mut()
            } else {
                j.arrays.borrow_mut().push(alloc::vec![0u8; len as usize]);
                (j.arrays.borrow().len()) as JbyteArray
            }
        })
    }

    unsafe extern "system" fn fake_get_byte_array_region(
        _env: *mut JNIEnv,
        array: JbyteArray,
        start: Jint,
        len: Jint,
        out: *mut Jbyte,
    ) {
        let src = JVM.with(|j| {
            j.arrays.borrow()[(array as usize) - 1][start as usize..(start + len) as usize].to_vec()
        });
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().cast(), out, src.len()) };
    }

    unsafe extern "system" fn fake_set_byte_array_region(
        _env: *mut JNIEnv,
        array: JbyteArray,
        start: Jint,
        len: Jint,
        data: *const Jbyte,
    ) {
        JVM.with(|j| {
            let mut arrays = j.arrays.borrow_mut();
            let dst = &mut arrays[(array as usize) - 1][start as usize..(start + len) as usize];
            unsafe { core::ptr::copy_nonoverlapping(data.cast(), dst.as_mut_ptr(), len as usize) };
        });
    }

    fn fake_table() -> JnInterface {
        JnInterface {
            reserved: [core::ptr::null_mut(); 4],
            gap_a: [None; 2],
            find_class: Some(fake_find_class),
            gap_b: [None; 6],
            throw_fn: Some(fake_throw_fn),
            throw_new: Some(fake_throw_new),
            gap_c: [None; 15],
            new_object_a: Some(fake_new_object_a),
            gap_d: [None; 2],
            get_method_id: Some(fake_get_method_id),
            gap_e: [None; 133],
            new_string_utf: Some(fake_new_string_utf),
            gap_f: [None; 3],
            get_array_length: Some(fake_get_array_length),
            gap_g: [None; 4],
            new_byte_array: Some(fake_new_byte_array),
            gap_h: [None; 23],
            get_byte_array_region: Some(fake_get_byte_array_region),
            gap_i: [None; 7],
            set_byte_array_region: Some(fake_set_byte_array_region),
        }
    }

    /// A `*mut JNIEnv` pointing at a leaked-then-dropped fake table.
    struct EnvGuard(*mut JNIEnv);

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                drop(Box::from_raw(*self.0 as *mut JnInterface));
                drop(Box::from_raw(self.0));
            }
        }
    }

    fn fake_env() -> EnvGuard {
        let table: JNIEnv = Box::into_raw(Box::new(fake_table()));
        EnvGuard(Box::into_raw(Box::new(table)))
    }

    fn fixture(name: &str) -> Vec<u8> {
        let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        std::fs::read(Path::new(&root).join("tests").join("fixtures").join(name)).expect("fixture")
    }

    #[test]
    fn struct_layout_matches_the_jni_slot_order() {
        assert_eq!(std::mem::size_of::<JnInterface>(), 209 * 8);
        let slot = |i: usize| i * 8;
        assert_eq!(std::mem::offset_of!(JnInterface, find_class), slot(6));
        assert_eq!(std::mem::offset_of!(JnInterface, throw_fn), slot(13));
        assert_eq!(std::mem::offset_of!(JnInterface, throw_new), slot(14));
        assert_eq!(std::mem::offset_of!(JnInterface, new_object_a), slot(30));
        assert_eq!(std::mem::offset_of!(JnInterface, get_method_id), slot(33));
        assert_eq!(std::mem::offset_of!(JnInterface, new_string_utf), slot(167));
        assert_eq!(
            std::mem::offset_of!(JnInterface, get_array_length),
            slot(171)
        );
        assert_eq!(std::mem::offset_of!(JnInterface, new_byte_array), slot(176));
        assert_eq!(
            std::mem::offset_of!(JnInterface, get_byte_array_region),
            slot(200)
        );
        assert_eq!(
            std::mem::offset_of!(JnInterface, set_byte_array_region),
            slot(208)
        );
    }

    #[test]
    fn happy_path_returns_the_canonical_stream() {
        reset();
        let env = fake_env();
        let input = fixture("a_64x48.mp4");
        let handle = push_array(&input);
        let out =
            unsafe { Java_hash_pith_PithVideo_fingerprint(env.0, core::ptr::null_mut(), handle) };
        assert!(!out.is_null());
        assert_eq!(array_bytes(out), fingerprint_and_serialize(&input).unwrap());
        let jvm = JVM.with(|j| {
            (
                j.pending_status.get(),
                j.threw.get(),
                j.throw_new_calls.get(),
            )
        });
        assert_eq!(jvm, (0, false, 0));
    }

    #[test]
    fn wire_header_is_big_endian_64x48_eight_frames() {
        reset();
        let env = fake_env();
        let input = fixture("a_64x48.mp4");
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(env.0, core::ptr::null_mut(), push_array(&input))
        };
        let raw = array_bytes(out);
        // width=64, height=48, sampled_frames=8, big-endian.
        assert_eq!(&raw[..12], &[0, 0, 0, 64, 0, 0, 0, 48, 0, 0, 0, 8]);
        // 28-byte header + 8 frame hashes + 128 minhash words + digest.
        assert_eq!(raw.len(), 28 + 8 * 8 + 1024 + 32);
    }

    #[test]
    fn garbage_input_throws_rejected() {
        reset();
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                push_array(b"definitely not an mp4"),
            )
        };
        assert!(out.is_null());
        assert_eq!(
            JVM.with(|j| (j.pending_status.get(), j.threw.get())),
            (-2, true)
        );
    }

    #[test]
    fn empty_input_throws_rejected() {
        reset();
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(env.0, core::ptr::null_mut(), push_array(&[]))
        };
        assert!(out.is_null());
        assert_eq!(JVM.with(|j| j.pending_status.get()), -2);
    }

    #[test]
    fn null_input_array_throws_invalid() {
        reset();
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(out.is_null());
        assert_eq!(JVM.with(|j| j.pending_status.get()), -1);
    }

    #[test]
    fn null_env_is_null_without_panicking() {
        reset();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(out.is_null());
        assert!(!JVM.with(|j| j.threw.get()));
    }

    #[test]
    fn unresolvable_exception_class_falls_back_to_throw_new() {
        reset();
        JVM.with(|j| j.fail_first_find_class.set(true));
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                push_array(b"garbage"),
            )
        };
        assert!(out.is_null());
        let jvm = JVM.with(|j| {
            (
                j.pending_status.get(),
                j.threw.get(),
                j.throw_new_calls.get(),
            )
        });
        assert_eq!(jvm, (0, false, 1));
    }

    #[test]
    fn unresolvable_ctor_falls_back_to_throw_new() {
        reset();
        JVM.with(|j| j.fail_method_id.set(true));
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                push_array(b"garbage"),
            )
        };
        assert!(out.is_null());
        assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
    }

    #[test]
    fn failed_message_string_falls_back_to_throw_new() {
        reset();
        JVM.with(|j| j.fail_string.set(true));
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                push_array(b"garbage"),
            )
        };
        assert!(out.is_null());
        assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
    }

    #[test]
    fn failed_exception_object_falls_back_to_throw_new() {
        reset();
        JVM.with(|j| j.fail_new_object.set(true));
        let env = fake_env();
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(
                env.0,
                core::ptr::null_mut(),
                push_array(b"garbage"),
            )
        };
        assert!(out.is_null());
        assert_eq!(JVM.with(|j| j.throw_new_calls.get()), 1);
    }

    #[test]
    fn failed_new_byte_array_returns_null_without_throwing() {
        reset();
        JVM.with(|j| j.fail_new_byte_array.set(true));
        let env = fake_env();
        let input = fixture("a_64x48.mp4");
        let out = unsafe {
            Java_hash_pith_PithVideo_fingerprint(env.0, core::ptr::null_mut(), push_array(&input))
        };
        assert!(out.is_null());
        let jvm = JVM.with(|j| {
            (
                j.pending_status.get(),
                j.threw.get(),
                j.throw_new_calls.get(),
            )
        });
        assert_eq!(jvm, (0, false, 0));
    }
}
