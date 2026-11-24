"""Pytest coverage for the policy introspection surface.

The ``LR_VALUE_*`` / ``LR_BINARY_OP_*`` / ``LR_ROUTE_FIELD_*``
constants and the ``value_truthy`` / ``binary_op_precedence`` /
``route_field_is_settable`` wrappers in ``librouting.policy`` answer
kind-level questions about the filter DSL. The C entry points behind
them were silent placeholders before (they answered 0 regardless of
input); these tests pin the real contracts.
"""

from librouting import policy


def test_value_truthy_always_truthy_kinds():
    for kind in (
        policy.VALUE_IP,
        policy.VALUE_PREFIX,
        policy.VALUE_ASN,
        policy.VALUE_COMM_PATTERN,
        policy.VALUE_PROTOCOL,
        policy.VALUE_ROA_STATE,
    ):
        assert policy.value_truthy(kind) is True, f"kind {kind} is always truthy"


def test_value_truthy_content_dependent_kinds():
    for kind in (
        policy.VALUE_INT,
        policy.VALUE_BOOL,
        policy.VALUE_STR,
        policy.VALUE_AS_PATH,
        policy.VALUE_COMMUNITIES,
        policy.VALUE_LARGE_COMMUNITIES,
        policy.VALUE_EXT_COMMUNITIES,
        policy.VALUE_SET,
    ):
        assert policy.value_truthy(kind) is False, f"kind {kind} is content-dependent"


def test_value_truthy_unknown_kind():
    assert policy.value_truthy(99) is False
    assert policy.value_truthy(-1) is False


def test_binary_op_precedence_grammar_layering():
    # BIRD grammar: `||` < `&&` < equality < comparison < bitwise
    # < shifts < additive < multiplicative.
    assert policy.binary_op_precedence(policy.BINARY_OP_OR) == 1
    assert policy.binary_op_precedence(policy.BINARY_OP_AND) == 2
    assert policy.binary_op_precedence(policy.BINARY_OP_EQ) == 3
    assert policy.binary_op_precedence(policy.BINARY_OP_NE) == 3
    assert policy.binary_op_precedence(policy.BINARY_OP_LT) == 4
    assert policy.binary_op_precedence(policy.BINARY_OP_BIT_OR) == 5
    assert policy.binary_op_precedence(policy.BINARY_OP_BIT_XOR) == 6
    assert policy.binary_op_precedence(policy.BINARY_OP_BIT_AND) == 7
    assert policy.binary_op_precedence(policy.BINARY_OP_SHL) == 8
    assert policy.binary_op_precedence(policy.BINARY_OP_ADD) == 9
    assert policy.binary_op_precedence(policy.BINARY_OP_MUL) == 10


def test_binary_op_precedence_covers_every_operator():
    ops = [
        policy.BINARY_OP_AND,
        policy.BINARY_OP_OR,
        policy.BINARY_OP_EQ,
        policy.BINARY_OP_NE,
        policy.BINARY_OP_LT,
        policy.BINARY_OP_LE,
        policy.BINARY_OP_GT,
        policy.BINARY_OP_GE,
        policy.BINARY_OP_ADD,
        policy.BINARY_OP_SUB,
        policy.BINARY_OP_MUL,
        policy.BINARY_OP_DIV,
        policy.BINARY_OP_MOD,
        policy.BINARY_OP_BIT_AND,
        policy.BINARY_OP_BIT_OR,
        policy.BINARY_OP_BIT_XOR,
        policy.BINARY_OP_SHL,
        policy.BINARY_OP_SHR,
        policy.BINARY_OP_MATCH,
        policy.BINARY_OP_NOT_MATCH,
    ]
    # Every operator answers a nonzero precedence; the ids are unique.
    precedences = [policy.binary_op_precedence(op) for op in ops]
    assert all(p > 0 for p in precedences), precedences
    assert len(set(ops)) == 20
    # Unknown ids answer 0.
    assert policy.binary_op_precedence(0) == 0
    assert policy.binary_op_precedence(21) == 0


def test_route_field_is_settable_settable_set():
    for kind in (
        policy.ROUTE_FIELD_BGP_LOCAL_PREF,
        policy.ROUTE_FIELD_BGP_MED,
        policy.ROUTE_FIELD_BGP_NEXT_HOP,
        policy.ROUTE_FIELD_BGP_COMMUNITIES,
        policy.ROUTE_FIELD_BGP_EXT_COMMUNITIES,
        policy.ROUTE_FIELD_BGP_LARGE_COMMUNITIES,
    ):
        assert policy.route_field_is_settable(kind) is True, f"kind {kind} is settable"


def test_route_field_is_settable_read_only_fields():
    for kind in (
        policy.ROUTE_FIELD_NET,
        policy.ROUTE_FIELD_PROTO,
        policy.ROUTE_FIELD_SOURCE,
        policy.ROUTE_FIELD_BGP_AS_PATH,
        policy.ROUTE_FIELD_BGP_ORIGIN,
        policy.ROUTE_FIELD_ROA_STATE,
        policy.ROUTE_FIELD_LRXP_VERIFIED,
        policy.ROUTE_FIELD_BABEL_METRIC,
        policy.ROUTE_FIELD_OSPF_TAG,
    ):
        assert policy.route_field_is_settable(kind) is False, f"kind {kind} is read-only"


def test_route_field_is_settable_unknown_id():
    assert policy.route_field_is_settable(38) is False
    assert policy.route_field_is_settable(-1) is False


def test_route_field_constants_are_unique_and_dense():
    names = [n for n in dir(policy) if n.startswith("ROUTE_FIELD_")]
    values = [getattr(policy, n) for n in names]
    assert len(values) == 38
    assert sorted(values) == list(range(38))
