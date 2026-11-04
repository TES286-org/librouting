#!/usr/bin/env python3
"""Unit tests for scripts/abi_freeze_check.py."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import abi_freeze_check as m


def test_c_function_single_line():
    text = """
int32_t lr_foo(uint8_t x, uint8_t y);
const char *lr_bar(void);
void lr_baz(lr_router_t r, uint32_t count);
"""
    surf = m.extract_surface(text)
    assert 'lr_foo' in surf.functions, surf.functions
    assert 'lr_bar' in surf.functions, surf.functions
    assert 'lr_baz' in surf.functions, surf.functions


def test_c_function_multi_line():
    text = """
int32_t lr_long_func(uint8_t error_code,
                     uint8_t error_subcode,
                     const uint8_t *data,
                     uintptr_t len);
"""
    surf = m.extract_surface(text)
    assert 'lr_long_func' in surf.functions
    assert surf.functions['lr_long_func'] == \
        'int32_t lr_long_func(uint8_t error_code, uint8_t error_subcode, const uint8_t *data, uintptr_t len);'


def test_removed_function_is_detected():
    text1 = "int32_t lr_foo(uint8_t x, uint8_t y);"
    text2 = "const char *lr_bar(void);"
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('function', s1.functions, s2.functions)
    assert 'lr_foo' in removed, removed


def test_changed_function_signature_is_detected():
    text1 = "int32_t lr_foo(uint8_t x, uint8_t y);"
    text2 = "int32_t lr_foo(uint8_t x, uint8_t y, uint8_t z);"
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('function', s1.functions, s2.functions)
    assert changed, changed


def test_comment_reformat_does_not_false_positive():
    text1 = """/* This is a comment that was rewritten */
/* And another */
int32_t lr_foo(uint8_t x, uint8_t y);"""
    text2 = """/* Different comment text */
/* Yet another */
int32_t lr_foo(uint8_t x, uint8_t y);"""
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('function', s1.functions, s2.functions)
    assert not removed, removed
    assert not changed, changed


def test_macro_value_change_is_detected():
    text1 = "#define LR_FOO 5"
    text2 = "#define LR_FOO 6"
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('macro', s1.defines, s2.defines)
    assert changed, changed


def test_struct_field_change_is_detected():
    text1 = "struct lr_filter_context_t { int a; int b; };"
    text2 = "struct lr_filter_context_t { int a; };"
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('struct', s1.structs, s2.structs)
    assert changed, changed


def test_typedef_change_is_detected():
    text1 = "typedef int32_t lr_foo_t;"
    text2 = "typedef int64_t lr_foo_t;"
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('typedef', s1.typedefs, s2.typedefs)
    assert changed, changed


def test_cpp_class_with_base_is_extracted():
    text = """
class Error : public std::runtime_error {
public:
  explicit Error(std::string msg);
};
"""
    surf = m.extract_surface(text)
    assert 'class Error' in surf.structs, surf.structs


def test_cpp_inline_function_is_extracted():
    text = """
inline void check_rc(std::int32_t rc, const char* what) {
  if (rc != 0) {
    throw Error("bad");
  }
}
"""
    surf = m.extract_surface(text)
    assert 'check_rc' in surf.functions, surf.functions


def test_removed_cpp_inline_is_detected():
    text1 = """
inline void check_rc(std::int32_t rc, const char* what) {
  // body
}
inline int add(int a, int b) {
  return a + b;
}
"""
    text2 = """
inline int add(int a, int b) {
  return a + b;
}
"""
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('function', s1.functions, s2.functions)
    assert 'check_rc' in removed, removed


def test_changed_cpp_inline_signature_is_detected():
    text1 = """
inline void check_rc(std::int32_t rc, const char* what) {
  // body
}
"""
    text2 = """
inline void check_rc(std::int32_t rc, const char* what, std::string context) {
  // body
}
"""
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('function', s1.functions, s2.functions)
    assert changed, changed


def test_cpp_class_with_const_method_block_extracted():
    text = """
class Foo {
public:
  int32_t value() const { return v_; }
};
"""
    surf = m.extract_surface(text)
    assert 'class Foo' in surf.structs


def test_cpp_scoped_enum_class_is_extracted_with_name():
    text = """
enum class FilterVerdict : std::int32_t { Accept = 0, Reject = 1, Fallthrough = 2 };
"""
    surf = m.extract_surface(text)
    # `enum class NAME` must be keyed by NAME, not by the keyword `class`
    assert 'enum FilterVerdict' in surf.structs, surf.structs
    assert 'enum class' not in surf.structs, surf.structs


def test_cpp_scoped_enum_struct_is_extracted_with_name():
    text = """
enum struct Color : std::uint8_t { Red = 0, Green = 1, Blue = 2 };
"""
    surf = m.extract_surface(text)
    assert 'enum Color' in surf.structs, surf.structs
    assert 'enum struct' not in surf.structs, surf.structs


def test_removed_cpp_scoped_enum_is_detected():
    text1 = """
enum class FilterVerdict : std::int32_t { Accept = 0, Reject = 1, Fallthrough = 2 };
enum class BgpOrigin : std::uint8_t { Igp = 0, Egp = 1, Incomplete = 2 };
"""
    text2 = """
enum class BgpOrigin : std::uint8_t { Igp = 0, Egp = 1, Incomplete = 2 };
"""
    s1 = m.extract_surface(text1)
    s2 = m.extract_surface(text2)
    removed, changed = m.diff_surface('struct', s1.structs, s2.structs)
    assert 'enum FilterVerdict' in removed, removed


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
