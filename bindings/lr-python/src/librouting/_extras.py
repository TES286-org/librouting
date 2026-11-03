"""Auto-generated idiomatic wrappers for C ABI methods not covered
by the hand-written Python classes.

Produced by ``scripts/gen_methods_extras.py`` from ``include/lr_ffi.h``.
Re-run: ``python3 scripts/gen_methods_extras.py``.

Each function patches the corresponding hand-written class via
``setattr`` at import time. The generator is conservative — methods
with callback parameters, opaque output arrays, or value-struct
returns are skipped (a human can hand-write them).
"""

from __future__ import annotations

from ._ffi import ffi, get_lib, last_error
from .router import LrError
from . import bgp_path as _import_bgp_path
from . import ospf as _import_ospf
from . import policy as _import_policy
from . import roa as _import_roa
from . import router as _import_router


# ---- BgpAsPath (handle: lr_bgp_as_path_t, module: bgp_path) ----

def _impl_bgpaspath_length(self):
    """Auto-generated wrapper for ``lr_bgp_as_path_length``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_length(self._ptr)
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "length", _impl_bgpaspath_length)

def _impl_bgpaspath_length_with_confed(self):
    """Auto-generated wrapper for ``lr_bgp_as_path_length_with_confed``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_length_with_confed(self._ptr)
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "length_with_confed", _impl_bgpaspath_length_with_confed)

def _impl_bgpaspath_segment_count(self):
    """Auto-generated wrapper for ``lr_bgp_as_path_segment_count``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_segment_count(self._ptr)
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "segment_count", _impl_bgpaspath_segment_count)

def _impl_bgpaspath_segment_at(self, index):
    """Auto-generated wrapper for ``lr_bgp_as_path_segment_at``. See ``include/lr_ffi.h``."""
    _out2 = ffi.new("uint8_t *")
    _out3 = ffi.new("uintptr_t *")
    rc = get_lib().lr_bgp_as_path_segment_at(self._ptr, index, _out2, _out3)
    if rc < 0:
        raise LrError(f"lr_bgp_as_path_segment_at failed (rc={rc}): {last_error()}")
    return (int(_out2[0]), int(_out3[0]))

setattr(_import_bgp_path.BgpAsPath, "segment_at", _impl_bgpaspath_segment_at)

def _impl_bgpaspath_prepend(self, as_):
    """Auto-generated wrapper for ``lr_bgp_as_path_prepend``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_prepend(self._ptr, as_)
    if rc < 0:
        raise LrError(f"lr_bgp_as_path_prepend failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "prepend", _impl_bgpaspath_prepend)

def _impl_bgpaspath_prepend_confed(self, as_):
    """Auto-generated wrapper for ``lr_bgp_as_path_prepend_confed``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_prepend_confed(self._ptr, as_)
    if rc < 0:
        raise LrError(f"lr_bgp_as_path_prepend_confed failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "prepend_confed", _impl_bgpaspath_prepend_confed)

def _impl_bgpaspath_strip_confed(self):
    """Auto-generated wrapper for ``lr_bgp_as_path_strip_confed``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_strip_confed(self._ptr)
    if rc < 0:
        raise LrError(f"lr_bgp_as_path_strip_confed failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "strip_confed", _impl_bgpaspath_strip_confed)

def _impl_bgpaspath_has_confed(self):
    """Auto-generated wrapper for ``lr_bgp_as_path_has_confed``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_has_confed(self._ptr)
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "has_confed", _impl_bgpaspath_has_confed)

def _impl_bgpaspath_loop_check(self, my_as):
    """Auto-generated wrapper for ``lr_bgp_as_path_loop_check``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_bgp_as_path_loop_check(self._ptr, my_as)
    return int(rc)

setattr(_import_bgp_path.BgpAsPath, "loop_check", _impl_bgpaspath_loop_check)

# ---- OspfExternalDest (handle: lr_ospf_external_dest_t, module: ospf) ----

def _impl_ospfexternaldest_prefix(self):
    """Auto-generated wrapper for ``lr_ospf_external_dest_prefix``. See ``include/lr_ffi.h``."""
    _out1 = ffi.new("uint8_t *")
    _out2 = ffi.new("uint8_t *")
    rc = get_lib().lr_ospf_external_dest_prefix(self._ptr, _out1, _out2)
    if rc < 0:
        raise LrError(f"lr_ospf_external_dest_prefix failed (rc={rc}): {last_error()}")
    return (int(_out1[0]), int(_out2[0]))

setattr(_import_ospf.OspfExternalDest, "prefix", _impl_ospfexternaldest_prefix)

# ---- OspfLsdb (handle: lr_ospf_lsdb_t, module: ospf) ----

def _impl_ospflsdb_ospf_is_elected_translator(self, router_id):
    """Auto-generated wrapper for ``lr_ospf_is_elected_translator``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_ospf_is_elected_translator(self._ptr, router_id)
    return int(rc)

setattr(_import_ospf.OspfLsdb, "ospf_is_elected_translator", _impl_ospflsdb_ospf_is_elected_translator)

# ---- Resolver (handle: lr_resolver_t, module: policy) ----

def _impl_resolver_list_id(self, kind, name: str):
    """Auto-generated wrapper for ``lr_resolver_list_id``. See ``include/lr_ffi.h``."""
    _b2 = name.encode('utf-8') if isinstance(name, str) else name
    rc = get_lib().lr_resolver_list_id(self._ptr, kind, _b2)
    if rc < 0:
        raise LrError(f"lr_resolver_list_id failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_policy.Resolver, "list_id", _impl_resolver_list_id)

def _impl_resolver_route_map_count(self):
    """Auto-generated wrapper for ``lr_resolver_route_map_count``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_resolver_route_map_count(self._ptr)
    return int(rc)

setattr(_import_policy.Resolver, "route_map_count", _impl_resolver_route_map_count)

def _impl_resolver_policy_set_bind_import(self, session, map_name: str):
    """Auto-generated wrapper for ``lr_policy_set_bind_import``. See ``include/lr_ffi.h``."""
    _b2 = map_name.encode('utf-8') if isinstance(map_name, str) else map_name
    rc = get_lib().lr_policy_set_bind_import(self._ptr, session, _b2)
    if rc < 0:
        raise LrError(f"lr_policy_set_bind_import failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_policy.Resolver, "policy_set_bind_import", _impl_resolver_policy_set_bind_import)

def _impl_resolver_policy_set_bind_export(self, session, map_name: str):
    """Auto-generated wrapper for ``lr_policy_set_bind_export``. See ``include/lr_ffi.h``."""
    _b2 = map_name.encode('utf-8') if isinstance(map_name, str) else map_name
    rc = get_lib().lr_policy_set_bind_export(self._ptr, session, _b2)
    if rc < 0:
        raise LrError(f"lr_policy_set_bind_export failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_policy.Resolver, "policy_set_bind_export", _impl_resolver_policy_set_bind_export)

def _impl_resolver_policy_set_validate(self):
    """Auto-generated wrapper for ``lr_policy_set_validate``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_policy_set_validate(self._ptr)
    if rc < 0:
        raise LrError(f"lr_policy_set_validate failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_policy.Resolver, "policy_set_validate", _impl_resolver_policy_set_validate)

# ---- RoaStore (handle: lr_roa_store_t, module: roa) ----

def _impl_roastore_static_len(self):
    """Auto-generated wrapper for ``lr_roa_store_static_len``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_roa_store_static_len(self._ptr)
    return int(rc)

setattr(_import_roa.RoaStore, "static_len", _impl_roastore_static_len)

def _impl_roastore_rtr_len(self):
    """Auto-generated wrapper for ``lr_roa_store_rtr_len``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_roa_store_rtr_len(self._ptr)
    return int(rc)

setattr(_import_roa.RoaStore, "rtr_len", _impl_roastore_rtr_len)

# ---- Route (handle: lr_route_t, module: policy) ----

def _impl_route_apply_set_checked(self, set_kind, arg1, arg2, arg3):
    """Auto-generated wrapper for ``lr_apply_set_checked``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_apply_set_checked(self._ptr, set_kind, arg1, arg2, arg3)
    return int(rc)

setattr(_import_policy.Route, "apply_set_checked", _impl_route_apply_set_checked)

# ---- Router (handle: lr_router_t, module: router) ----

def _impl_router_close_session(self, session):
    """Auto-generated wrapper for ``lr_router_close_session``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_close_session(self._ptr, session)
    if rc < 0:
        raise LrError(f"lr_router_close_session failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "close_session", _impl_router_close_session)

def _impl_router_shutdown_session(self, session):
    """Auto-generated wrapper for ``lr_router_shutdown_session``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_shutdown_session(self._ptr, session)
    if rc < 0:
        raise LrError(f"lr_router_shutdown_session failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "shutdown_session", _impl_router_shutdown_session)

def _impl_router_remove_redistribution_pipe(self, source, target):
    """Auto-generated wrapper for ``lr_router_remove_redistribution_pipe``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_remove_redistribution_pipe(self._ptr, source, target)
    if rc < 0:
        raise LrError(f"lr_router_remove_redistribution_pipe failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "remove_redistribution_pipe", _impl_router_remove_redistribution_pipe)

def _impl_router_set_ospf_sr_receive(self, on):
    """Auto-generated wrapper for ``lr_router_set_ospf_sr_receive``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_set_ospf_sr_receive(self._ptr, on)
    if rc < 0:
        raise LrError(f"lr_router_set_ospf_sr_receive failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "set_ospf_sr_receive", _impl_router_set_ospf_sr_receive)

def _impl_router_ospf_sr_receive(self):
    """Auto-generated wrapper for ``lr_router_ospf_sr_receive``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_ospf_sr_receive(self._ptr)
    return int(rc)

setattr(_import_router.Router, "ospf_sr_receive", _impl_router_ospf_sr_receive)

def _impl_router_set_ospf_srv6_receive(self, on):
    """Auto-generated wrapper for ``lr_router_set_ospf_srv6_receive``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_set_ospf_srv6_receive(self._ptr, on)
    if rc < 0:
        raise LrError(f"lr_router_set_ospf_srv6_receive failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "set_ospf_srv6_receive", _impl_router_set_ospf_srv6_receive)

def _impl_router_ospf_srv6_receive(self):
    """Auto-generated wrapper for ``lr_router_ospf_srv6_receive``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_ospf_srv6_receive(self._ptr)
    return int(rc)

setattr(_import_router.Router, "ospf_srv6_receive", _impl_router_ospf_srv6_receive)

def _impl_router_set_ospf_v3_extended_lsas(self, on):
    """Auto-generated wrapper for ``lr_router_set_ospf_v3_extended_lsas``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_set_ospf_v3_extended_lsas(self._ptr, on)
    if rc < 0:
        raise LrError(f"lr_router_set_ospf_v3_extended_lsas failed (rc={rc}): {last_error()}")
    return int(rc)

setattr(_import_router.Router, "set_ospf_v3_extended_lsas", _impl_router_set_ospf_v3_extended_lsas)

def _impl_router_ospf_v3_extended_lsas(self):
    """Auto-generated wrapper for ``lr_router_ospf_v3_extended_lsas``. See ``include/lr_ffi.h``."""
    rc = get_lib().lr_router_ospf_v3_extended_lsas(self._ptr)
    return int(rc)

setattr(_import_router.Router, "ospf_v3_extended_lsas", _impl_router_ospf_v3_extended_lsas)

