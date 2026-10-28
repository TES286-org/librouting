//! OSPF SR / SRv6 database FFI — `lr_ospf_sr_db_*` / `lr_ospf_srv6_db_*`.
//!
//! Mirrors the public Rust API of `lr_ospf::srdb::SrDatabase` (RFC 8665
//! reception) and `lr_ospf::srv6db::Srv6Database` (RFC 9513 reception)
//! so an embedder can drive Segment Routing lookups from C without
//! going through the router instance.
//!
//! # Surface
//!
//! SrDatabase:
//! - `lr_ospf_sr_db_new` — `SrDatabase::from_lsdb(lsdb)` projection.
//! - `lr_ospf_sr_db_free` — drop the boxed SrDatabase.
//!
//! Srv6Database:
//! - `lr_ospf_srv6_db_new` — `Srv6Database::from_lsdb(lsdb)` projection.
//! - `lr_ospf_srv6_db_free` — drop the boxed Srv6Database.
//!
//! The `label_for` (SrDatabase) and `node` / `end_sids` (Srv6Database)
//! methods take SpfResult references or return trait iterators that
//! do not cross the C ABI cleanly; those surfaces stay on the Rust
//! side for now. The opaque handles here let an embedder pre-compute
//! the databases once per SPF run and pass them back to Rust-side
//! helpers (e.g. a `RouterInstance` extension) for the actual lookups.
//!
//! Every entry point runs inside the crate's `catch_unwind` barrier.

#![allow(unused_unsafe)]

use lr_ospf::lsdb::Lsdb;
use lr_ospf::srdb::SrDatabase;
use lr_ospf::srv6db::Srv6Database;

use crate::error::set_last_error;
use crate::guarded;

// ---- SrDatabase ----

/// Opaque `SrDatabase` handle.
#[repr(C)]
pub struct OpaqueOspfSrDb {
    _private: [u8; 0],
}
pub type lr_ospf_sr_db_t = *mut OpaqueOspfSrDb;

fn box_sr_db(db: SrDatabase) -> lr_ospf_sr_db_t {
    Box::into_raw(Box::new(db)) as lr_ospf_sr_db_t
}
unsafe fn unbox_sr_db(db: lr_ospf_sr_db_t) -> Option<Box<SrDatabase>> {
    if db.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(db as *mut SrDatabase) })
}

/// Construct an `SrDatabase` by projecting from `lsdb`. The LSDB is
/// borrowed for the duration of the call only — the projection is
/// deep (the database owns its own copy of the relevant LSAs).
///
/// # Safety
/// `lsdb` must be a live `lr_ospf_lsdb_t` handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_sr_db_new(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
) -> lr_ospf_sr_db_t {
    guarded(
        || unsafe {
            let lsdb_ptr = lsdb as *const Lsdb;
            if lsdb_ptr.is_null() {
                set_last_error("lr_ospf_sr_db_new: lsdb is NULL".into());
                return std::ptr::null_mut();
            }
            let lsdb_ref: &Lsdb = unsafe { &*lsdb_ptr };
            box_sr_db(SrDatabase::from_lsdb(lsdb_ref))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `SrDatabase`. Safe to call with NULL.
///
/// # Safety
/// `db` must have been produced by [`lr_ospf_sr_db_new`] and must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_sr_db_free(db: lr_ospf_sr_db_t) {
    guarded(
        || unsafe {
            drop(unbox_sr_db(db));
        },
        (),
    )
}

// ---- Srv6Database ----

/// Opaque `Srv6Database` handle.
#[repr(C)]
pub struct OpaqueOspfSrv6Db {
    _private: [u8; 0],
}
pub type lr_ospf_srv6_db_t = *mut OpaqueOspfSrv6Db;

fn box_srv6_db(db: Srv6Database) -> lr_ospf_srv6_db_t {
    Box::into_raw(Box::new(db)) as lr_ospf_srv6_db_t
}
unsafe fn unbox_srv6_db(db: lr_ospf_srv6_db_t) -> Option<Box<Srv6Database>> {
    if db.is_null() {
        return None;
    }
    Some(unsafe { Box::from_raw(db as *mut Srv6Database) })
}

/// Construct an `Srv6Database` by projecting from `lsdb`.
///
/// # Safety
/// `lsdb` must be a live `lr_ospf_lsdb_t` handle.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_srv6_db_new(
    lsdb: crate::ospf_lsdb::lr_ospf_lsdb_t,
) -> lr_ospf_srv6_db_t {
    guarded(
        || unsafe {
            let lsdb_ptr = lsdb as *const Lsdb;
            if lsdb_ptr.is_null() {
                set_last_error("lr_ospf_srv6_db_new: lsdb is NULL".into());
                return std::ptr::null_mut();
            }
            let lsdb_ref: &Lsdb = unsafe { &*lsdb_ptr };
            box_srv6_db(Srv6Database::from_lsdb(lsdb_ref))
        },
        std::ptr::null_mut(),
    )
}

/// Drop a boxed `Srv6Database`. Safe to call with NULL.
///
/// # Safety
/// `db` must have been produced by [`lr_ospf_srv6_db_new`] and must
/// not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn lr_ospf_srv6_db_free(db: lr_ospf_srv6_db_t) {
    guarded(
        || unsafe {
            drop(unbox_srv6_db(db));
        },
        (),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_sr_db_free_handles_null() {
        unsafe { lr_ospf_sr_db_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_srv6_db_free_handles_null() {
        unsafe { lr_ospf_srv6_db_free(std::ptr::null_mut()) };
    }

    #[test]
    fn ffi_sr_db_new_rejects_null_lsdb() {
        let db = unsafe { lr_ospf_sr_db_new(std::ptr::null_mut()) };
        assert!(db.is_null());
    }

    #[test]
    fn ffi_srv6_db_new_rejects_null_lsdb() {
        let db = unsafe { lr_ospf_srv6_db_new(std::ptr::null_mut()) };
        assert!(db.is_null());
    }

    #[test]
    fn ffi_sr_db_new_from_empty_lsdb() {
        let lsdb = crate::ospf_lsdb::lr_ospf_lsdb_new();
        assert!(!lsdb.is_null());
        let db = unsafe { lr_ospf_sr_db_new(lsdb) };
        assert!(!db.is_null(), "SrDatabase::from_lsdb(empty) should succeed");
        unsafe {
            lr_ospf_sr_db_free(db);
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }

    #[test]
    fn ffi_srv6_db_new_from_empty_lsdb() {
        let lsdb = crate::ospf_lsdb::lr_ospf_lsdb_new();
        assert!(!lsdb.is_null());
        let db = unsafe { lr_ospf_srv6_db_new(lsdb) };
        assert!(
            !db.is_null(),
            "Srv6Database::from_lsdb(empty) should succeed"
        );
        unsafe {
            lr_ospf_srv6_db_free(db);
            crate::ospf_lsdb::lr_ospf_lsdb_free(lsdb);
        }
    }
}
