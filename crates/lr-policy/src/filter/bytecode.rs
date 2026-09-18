//! Bytecode compiler + stack VM for the filter DSL (ROADMAP-v3 D3.7).
//!
//! The tree-walking interpreter re-dispatches on the AST for every
//! import/export evaluation. BIRD compiles its filters to `f_line`
//! bytecode for the same reason this module exists: the hot path is a
//! flat `Vec<Instruction>` executed by a stack VM loop with
//! pre-lifted constants and direct jumps, which avoids the recursive
//! enum dispatch entirely for the common shapes.
//!
//! Design notes:
//!
//! * Compilation is *total* — every AST shape compiles. Shapes with
//!   dynamic behaviour that has no bytecode representation (non-constant
//!   match patterns, `defined()` over arbitrary expressions) compile to
//!   a fallback instruction that calls the tree-walking helper on that
//!   subtree, so the two engines can never disagree.
//! * The VM shares the [`crate::filter::eval::Evaluator`] state (scope
//!   stack, user functions, call-depth counter), so `let` scoping,
//!   D3.1 call semantics and the route-mutation behaviour are
//!   bit-identical with the interpreter.
//! * `accept` / `reject` inside a user-function body latch a pending
//!   verdict exactly like the interpreter (BIRD `f_cmd` semantics).

use std::collections::BTreeMap;

use lr_core::addr::Prefix;

use crate::filter::ast::{BinaryOp, Expr, Filter, RouteField, Stmt, UnaryOp, Value};

pub use crate::filter::eval::execute;

/// A compiled user function: parameter names plus a flat code slice.
#[derive(Debug, Clone)]
pub struct CompiledFunction {
    pub params: Vec<String>,
    pub code: Vec<Instr>,
}

/// One match-pattern item — the right-hand side of `~`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchItem {
    /// A constant item (community literal, AS number, ...).
    Value(Value),
    /// `10.0.0.0/8{16,24}` — the range lives in the AST, not the Value.
    PrefixSet {
        prefix: Prefix,
        ge: Option<u8>,
        le: Option<u8>,
    },
    /// A dynamic item the compiler could not lift — evaluated by the
    /// tree-walker at run time.
    Expr(Expr),
}

/// The compiled right-hand side of a `~` / `!~` test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchRhs {
    /// A single constant pattern.
    Value(Value),
    /// A set literal (the common BIRD shape: `[ 10.0.0.0/8, ... ]`).
    Set(Vec<MatchItem>),
    /// A set literal optimised with a prefix trie (#19 P4). The trie
    /// indexes every [`MatchItem::PrefixSet`] entry for O(prefix_len)
    /// containment lookup instead of the O(n) linear scan in
    /// [`MatchRhs::Set`]; non-prefix items (values, dynamic exprs)
    /// stay in `others` for a linear scan. The trie borrows its
    /// structure from `lr-bgp::roa_trie` (D8.4) — a path-compressed
    /// Patricia trie with a flat node arena, two family roots, and a
    /// covering walk that stops at the first divergence. The trie
    /// is only built when the set contains at least one prefix
    /// pattern; pure value / dynamic sets keep the linear scan.
    PrefixSet {
        trie: PrefixSetTrie,
        others: Vec<MatchItem>,
    },
    /// Fully dynamic fallback — the tree-walking `eval_match`.
    Expr(Expr),
}

/// Path-compressed (Patricia) prefix trie indexing the prefix patterns
/// of a `~` set literal (#19 P4). Turns the O(n) linear scan over
/// `MatchItem::PrefixSet` entries into an O(prefix_len) covering walk.
///
/// Each node owns a path-compressed segment of key bits and the
/// `(ge, le)` constraints of every pattern whose prefix terminates
/// exactly at that node. The walk follows the query prefix's bits
/// root-to-leaf, consulting each node whose prefix is a bit-prefix of
/// the query, and stops at the first divergence. The structure
/// mirrors `lr-bgp::roa_trie::RoaTrie` (D8.4) — the same high-aligned
/// `u128` key encoding, the same flat node arena with `u32` indices,
/// the same two-family root layout — but stores `(ge, le)` pairs
/// instead of ROA entry indices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixSetTrie {
    /// Node arena. Node 0 of each family is that family's root.
    nodes: Vec<TrieNode>,
    /// Per-family root node index: `[None; 2]` while empty (family 0
    /// = IPv4, family 1 = IPv6).
    roots: [Option<u32>; 2],
}

/// One trie node: a path-compressed segment plus the `(ge, le)`
/// constraints of every pattern terminating at this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrieNode {
    /// Segment key bits, high-aligned (bit 0 = MSB).
    segment: u128,
    /// Segment length in bits (0 for a family root).
    skip: u8,
    /// Patterns whose prefix terminates at this node. Each entry is
    /// `(ge, le)` — the range constraint from the source `~` pattern.
    patterns: Vec<(Option<u8>, Option<u8>)>,
    /// Children keyed by the next key bit after this node's prefix.
    children: [Option<u32>; 2],
}

/// Mask with the top `bits` bits set (`bits <= 128`).
fn high_bits_mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits as u32)
    }
}

/// Bit `i` (0-based from the MSB) of a high-aligned key.
fn bit_at(key: u128, i: u8) -> usize {
    ((key << i) >> 127) as usize
}

/// Encode a prefix as a high-aligned `u128` key, clamping the length
/// to the family width. Returns `(key, length, family)` where family
/// is 0 for IPv4 and 1 for IPv6. Mirrors `roa_trie::encode_prefix`.
fn encode_prefix(prefix: &Prefix) -> (u128, u8, usize) {
    match prefix.network() {
        lr_core::addr::IpAddr::V4(b) => (
            (u32::from_be_bytes(b) as u128) << 96,
            prefix.prefix_len.min(32),
            0,
        ),
        lr_core::addr::IpAddr::V6(b) => (u128::from_be_bytes(b), prefix.prefix_len.min(128), 1),
    }
}

impl PrefixSetTrie {
    /// Build a trie indexing every `MatchItem::PrefixSet` entry in
    /// `items` (by position). Non-prefix items are ignored — the
    /// caller keeps them in a separate linear-scan list.
    pub fn build(items: &[MatchItem]) -> Self {
        let mut trie = Self::new();
        for item in items {
            if let MatchItem::PrefixSet { prefix, ge, le } = item {
                let (key, len, family) = encode_prefix(prefix);
                trie.insert(key, len, family, *ge, *le);
            }
        }
        trie
    }

    /// Empty trie — no roots, no nodes.
    fn new() -> Self {
        Self::default()
    }

    /// Insert one `(ge, le)` pattern under the node for `(key, len)`.
    /// Mirrors `RoaTrie::insert` — the structure is identical; only
    /// the payload type differs (`(ge, le)` vs `RoaEntry` index).
    fn insert(&mut self, key: u128, len: u8, family: usize, ge: Option<u8>, le: Option<u8>) {
        let Some(root) = self.roots[family] else {
            let idx = self.nodes.len() as u32;
            self.nodes.push(TrieNode {
                segment: if len == 0 { 0 } else { key },
                skip: len,
                patterns: Vec::from([(ge, le)]),
                children: [None, None],
            });
            self.roots[family] = Some(idx);
            return;
        };

        enum Attach {
            Root(usize),
            Child(u32, usize),
        }

        let mut cur = root;
        let mut pos: u8 = 0;
        let mut attach = Attach::Root(family);
        loop {
            let (seg, skip) = {
                let node = &self.nodes[cur as usize];
                (node.segment, node.skip)
            };
            let remaining = len - pos;
            let cmp = skip.min(remaining);
            let xor = (seg ^ (key << pos)) & high_bits_mask(cmp);
            if xor != 0 {
                // Divergence inside the segment: factor the shared
                // prefix into a new branch node.
                let j = xor.leading_zeros() as u8;
                let branch_idx = self.nodes.len() as u32;
                let leaf_idx = branch_idx + 1;
                self.nodes.push(TrieNode {
                    segment: seg & high_bits_mask(j),
                    skip: j,
                    patterns: Vec::new(),
                    children: [None, None],
                });
                self.nodes.push(TrieNode {
                    segment: key << (pos + j),
                    skip: remaining - j,
                    patterns: Vec::from([(ge, le)]),
                    children: [None, None],
                });
                let old_bit = bit_at(seg, j);
                let old = &mut self.nodes[cur as usize];
                old.segment = seg << j;
                old.skip = skip - j;
                self.nodes[branch_idx as usize].children[old_bit] = Some(cur);
                self.nodes[branch_idx as usize].children[1 - old_bit] = Some(leaf_idx);
                match attach {
                    Attach::Root(f) => self.roots[f] = Some(branch_idx),
                    Attach::Child(parent, slot) => {
                        self.nodes[parent as usize].children[slot] = Some(branch_idx)
                    }
                }
                return;
            }
            if remaining < skip {
                // The key is a strict ancestor of this node: splice a
                // new node for it above.
                let new_idx = self.nodes.len() as u32;
                let old_bit = bit_at(seg, remaining);
                self.nodes.push(TrieNode {
                    segment: if remaining == 0 { 0 } else { key << pos },
                    skip: remaining,
                    patterns: Vec::from([(ge, le)]),
                    children: [None, None],
                });
                let old = &mut self.nodes[cur as usize];
                old.segment = seg << remaining;
                old.skip = skip - remaining;
                self.nodes[new_idx as usize].children[old_bit] = Some(cur);
                match attach {
                    Attach::Root(f) => self.roots[f] = Some(new_idx),
                    Attach::Child(parent, slot) => {
                        self.nodes[parent as usize].children[slot] = Some(new_idx)
                    }
                }
                return;
            }
            if remaining == skip {
                // The key terminates exactly at this node.
                self.nodes[cur as usize].patterns.push((ge, le));
                return;
            }
            // Full segment match with key bits to spare: descend.
            let slot = bit_at(key, pos + skip);
            match self.nodes[cur as usize].children[slot] {
                Some(child) => {
                    pos += skip;
                    attach = Attach::Child(cur, slot);
                    cur = child;
                }
                None => {
                    let idx = self.nodes.len() as u32;
                    self.nodes.push(TrieNode {
                        segment: key << (pos + skip),
                        skip: remaining - skip,
                        patterns: Vec::from([(ge, le)]),
                        children: [None, None],
                    });
                    self.nodes[cur as usize].children[slot] = Some(idx);
                    return;
                }
            }
        }
    }

    /// Walk the covering path for `prefix` and return `true` when any
    /// pattern in the trie matches. A pattern matches when its prefix
    /// is a bit-prefix of `prefix` (the trie structure guarantees
    /// this) AND `prefix.prefix_len` is within the pattern's
    /// `[lo, hi]` range (the `ge`/`le` constraint checked here).
    ///
    /// The walk is O(prefix_len) — at most 32 hops for IPv4, 128 for
    /// IPv6 — versus the O(n) linear scan over every pattern in the
    /// set. This is the win the #19 P4 plan targets: a 100-entry
    /// prefix set goes from ~100 comparisons per route to ~32.
    pub fn matches(&self, prefix: &Prefix) -> bool {
        let (key, len, family) = encode_prefix(prefix);
        let Some(mut cur) = self.roots[family] else {
            return false;
        };
        let mut pos: u8 = 0;
        let family_max = if family == 0 { 32 } else { 128 };
        loop {
            let (seg, skip, patterns) = {
                let node = &self.nodes[cur as usize];
                (node.segment, node.skip, &node.patterns)
            };
            let remaining = len - pos;
            let cmp = skip.min(remaining);
            let xor = (seg ^ (key << pos)) & high_bits_mask(cmp);
            if xor != 0 || remaining < skip {
                break;
            }
            // This node's prefix (length `pos + skip`) is a bit-prefix
            // of the query. Check every pattern terminating here.
            let set_len = pos + skip;
            if !patterns.is_empty() {
                for &(ge, le) in patterns {
                    let lo = ge.unwrap_or(set_len).max(set_len);
                    let hi = le.unwrap_or(family_max);
                    if len >= lo && len <= hi {
                        return true;
                    }
                }
            }
            if remaining == skip {
                break;
            }
            let slot = bit_at(key, pos + skip);
            match self.nodes[cur as usize].children[slot] {
                Some(child) => {
                    pos += skip;
                    cur = child;
                }
                None => break,
            }
        }
        false
    }
}

/// `defined()` targets. `defined()` must observe *presence*, not the
/// (default-collapsed) value, so its argument is never evaluated in
/// the ordinary sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinedTarget {
    /// A route attribute — presence via the typed accessors.
    Field(RouteField),
    /// A scope variable — presence via the scope stack.
    Var(String),
    /// A literal is always defined.
    Literal,
    /// Any other expression — probed against a route copy by the
    /// tree-walker (identical to the interpreter's fallback).
    Dynamic(Expr),
}

/// One VM instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    /// Push a constant.
    Push(Value),
    /// Look up a variable (runtime error when unbound).
    LoadVar(String),
    /// Read a route attribute.
    LoadField(RouteField),
    /// `let name = expr;` — bind in the current scope.
    StoreVar(String),
    /// `name = expr;` — reassign through the scope stack.
    AssignVar(String),
    /// Store the case scrutinee in the temp slot.
    StoreTmp,
    /// Load the case scrutinee from the temp slot.
    LoadTmp,
    /// Apply a binary operator to the top two stack values.
    Bin(BinaryOp),
    /// `!x` — truthiness negation.
    Not,
    /// `-x` — integer negation.
    Neg,
    /// Pop a condition, jump when falsy.
    JumpIfFalse(usize),
    /// Pop a condition, jump when truthy.
    JumpIfTrue(usize),
    /// Unconditional jump.
    Jump(usize),
    /// Pop a value, push its truthiness as a `Bool`.
    Truthy,
    /// `~` / `!~` — membership test against a compiled pattern.
    Match { negated: bool, rhs: MatchRhs },
    /// Fused `LoadField(field); Push(Int(c)); Bin(op); JumpIf*(t)` —
    /// reads an integer-typed route field directly, compares against
    /// the constant, and branches without touching the stack. Only
    /// emitted by `pass_fuse_branches` for fields whose
    /// `read_route_field` returns `Value::Int(_)` (LocalPref / Med /
    /// Origin / Source) and comparison ops in
    /// `{Eq, Ne, Lt, Le, Gt, Ge}`. The fused instruction preserves
    /// the `unwrap_or(0)` semantics of the int-typed field read — an
    /// absent attribute reads as 0, exactly like the unfused path.
    /// Stack traffic: zero push, zero pop (vs three pushes + two
    /// pops in the unfused four-instruction sequence). GitHub #19 P6.
    BranchFieldIntCmp {
        field: RouteField,
        op: BinaryOp,
        val: i64,
        target: usize,
        /// `true` = jump when the comparison is true (`JumpIfTrue`).
        /// `false` = jump when the comparison is false
        /// (`JumpIfFalse`).
        jump_if_true: bool,
    },
    /// `defined(x)` / `exists(x)`.
    Defined(DefinedTarget),
    /// Call a built-in function with `argc` stack arguments. The VM
    /// dispatches by name through the built-in table (`eval_call`).
    /// User-function calls are resolved to [`Instr::CallFn`] at
    /// compile time (GitHub #19 P2).
    Call { name: String, argc: usize },
    /// Call a user-defined function by index (GitHub #19 P2). The
    /// VM indexes directly into `CompiledFilter.functions[idx]` —
    /// no BTreeMap lookup per call. The compiler resolves
    /// `Expr::Call { name, .. }` to `CallFn { idx, argc }` when
    /// `name` is a user function (the parser's `validate_calls`
    /// pass guarantees every call name is a user function or a
    /// built-in).
    CallFn { idx: usize, argc: usize },
    /// Method call on a route field (`bgp.as_path.prepend`, ...).
    Method {
        field: RouteField,
        method: String,
        argc: usize,
    },
    /// `route.attr = expr;` — the value is on the stack.
    AssignField(RouteField),
    /// `route.attr += expr;` — the value is on the stack.
    AppendField(RouteField),
    /// Discard the top of the stack (expression statements).
    Pop,
    /// Open a block scope.
    PushScope,
    /// Close a block scope.
    PopScope,
    /// Terminate with `Accept`.
    Accept,
    /// Terminate with `Reject`. `from_stack` pops the reason value.
    Reject { from_stack: bool },
    /// Return from a user function with the popped value.
    Return,
    /// Tree-walking fallback for a dynamic expression subtree: pushes
    /// the evaluated value.
    EvalTree(Expr),
}

/// A compiled filter: flat code plus compiled user functions.
///
/// `functions` is a `Vec` indexed by the `CallFn { idx, argc }`
/// instruction (GitHub #19 P2) — the VM indexes directly into this
/// vector per call, no BTreeMap lookup. `function_index` maps a
/// function name to its `Vec` index; the compiler builds this first so
/// it can resolve `Expr::Call { name, .. }` to `CallFn { idx, argc }`
/// at compile time.
#[derive(Debug, Clone)]
pub struct CompiledFilter {
    pub name: String,
    pub code: Vec<Instr>,
    pub functions: Vec<CompiledFunction>,
    /// Name → index map for `functions` (GitHub #19 P2). Built so the
    /// compiler can resolve call names to indices at compile time.
    pub function_index: BTreeMap<String, usize>,
}

/// Compile a parsed filter to bytecode. Infallible: every AST shape
/// has a bytecode representation or a tree-walking fallback. The
/// compiled code is then run through the peephole passes (constant
/// propagation + literal folding + dead-branch elimination + jump
/// threading — see `crate::filter::peephole`); the passes are
/// transparent (preserve verdict + route state for every route, as
/// pinned by the equivalence tables in `eval.rs`).
///
/// GitHub #19 P2: the compiler builds a name → index map for user
/// functions *first*, then compiles the body and function bodies with
/// that map in scope. `Expr::Call { name, .. }` resolves to
/// `CallFn { idx, argc }` when `name` is a user function, and to
/// `Call { name, argc }` (built-in) otherwise. The parser's
/// `validate_calls` pass already guarantees every call name is one or
/// the other, so the resolution is total.
pub fn compile(filter: &Filter) -> CompiledFilter {
    // Build the function table first so body compilation can resolve
    // calls to indices.
    let mut function_index: BTreeMap<String, usize> = BTreeMap::new();
    for (i, f) in filter.functions.iter().enumerate() {
        function_index.insert(f.name.clone(), i);
    }

    let c = Compiler {
        function_index: &function_index,
    };
    let mut code = Vec::new();
    c.compile_stmts(&filter.body.stmts, &mut code);
    let code = crate::filter::peephole::optimize(code);
    let mut functions = Vec::with_capacity(filter.functions.len());
    for f in &filter.functions {
        let mut code = Vec::new();
        c.compile_stmts(&f.body.stmts, &mut code);
        code.push(Instr::Return);
        let code = crate::filter::peephole::optimize(code);
        functions.push(CompiledFunction {
            params: f.params.clone(),
            code,
        });
    }
    CompiledFilter {
        name: filter.name.clone(),
        code,
        functions,
        function_index,
    }
}

/// The bytecode compiler. Carries a reference to the function table
/// (GitHub #19 P2) so `Expr::Call { name, .. }` can resolve to
/// `CallFn { idx, argc }` at compile time.
struct Compiler<'a> {
    function_index: &'a BTreeMap<String, usize>,
}

impl<'a> Compiler<'a> {
    fn compile_stmts(&self, stmts: &[Stmt], out: &mut Vec<Instr>) {
        for s in stmts {
            self.compile_stmt(s, out);
        }
    }

    fn compile_stmt(&self, stmt: &Stmt, out: &mut Vec<Instr>) {
        match stmt {
            Stmt::Return(value) => match value {
                Some(e) => {
                    self.compile_expr(e, out);
                    out.push(Instr::Return);
                }
                None => {
                    out.push(Instr::Push(Value::Bool(false)));
                    out.push(Instr::Return);
                }
            },
            Stmt::Accept => out.push(Instr::Accept),
            Stmt::Reject(reason) => match reason {
                Some(e) => {
                    self.compile_expr(e, out);
                    out.push(Instr::Reject { from_stack: true });
                }
                None => out.push(Instr::Reject { from_stack: false }),
            },
            Stmt::If { cond, then, els } => {
                self.compile_expr(cond, out);
                if let Some(e) = els {
                    // cond? then : else
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX)); // patched
                    self.compile_stmt(then, out);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    out[jf] = Instr::JumpIfFalse(out.len());
                    self.compile_stmt(e, out);
                    out[j] = Instr::Jump(out.len());
                } else {
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX));
                    self.compile_stmt(then, out);
                    out[jf] = Instr::JumpIfFalse(out.len());
                }
            }
            Stmt::Case { scrutinee, arms } => {
                self.compile_expr(scrutinee, out);
                out.push(Instr::StoreTmp);
                let mut arm_jumps = Vec::new();
                for arm in arms {
                    if arm.patterns.is_empty() {
                        // default arm
                        self.compile_stmts(&arm.body, out);
                        arm_jumps.push(out.len());
                        out.push(Instr::Jump(usize::MAX));
                        continue;
                    }
                    let mut pattern_jumps = Vec::new();
                    for (i, p) in arm.patterns.iter().enumerate() {
                        if i > 0 {
                            // Only jump into pattern i when the previous
                            // ones did not match — chained by fall-through.
                        }
                        out.push(Instr::LoadTmp);
                        self.compile_expr(p, out);
                        out.push(Instr::Bin(BinaryOp::Eq));
                        let jf = out.len();
                        out.push(Instr::JumpIfFalse(usize::MAX));
                        pattern_jumps.push(jf);
                    }
                    self.compile_stmts(&arm.body, out);
                    arm_jumps.push(out.len());
                    out.push(Instr::Jump(usize::MAX));
                    for j in pattern_jumps {
                        out[j] = Instr::JumpIfFalse(out.len());
                    }
                }
                let end = out.len();
                for j in arm_jumps {
                    out[j] = Instr::Jump(end);
                }
            }
            Stmt::Let { name, value } => {
                self.compile_expr(value, out);
                out.push(Instr::StoreVar(name.clone()));
            }
            Stmt::Assign { name, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AssignVar(name.clone()));
            }
            Stmt::AssignRouteField { field, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AssignField(*field));
            }
            Stmt::AppendRouteField { field, value } => {
                self.compile_expr(value, out);
                out.push(Instr::AppendField(*field));
            }
            Stmt::Expr(e) => {
                self.compile_expr(e, out);
                out.push(Instr::Pop);
            }
            Stmt::Block(body) => {
                out.push(Instr::PushScope);
                self.compile_stmts(body, out);
                out.push(Instr::PopScope);
            }
        }
    }

    fn compile_expr(&self, expr: &Expr, out: &mut Vec<Instr>) {
        match expr {
            Expr::Lit(v) => out.push(Instr::Push(v.clone())),
            Expr::Var(name) => out.push(Instr::LoadVar(name.clone())),
            Expr::RouteField(f) => out.push(Instr::LoadField(*f)),
            Expr::Call { name, args } => {
                for a in args {
                    self.compile_expr(a, out);
                }
                // P2: resolve user-function calls to `CallFn { idx, argc }`
                // for direct Vec index access at run time. Built-in calls
                // keep `Call { name, argc }`. The parser's `validate_calls`
                // pass guarantees every name is one or the other.
                if let Some(&idx) = self.function_index.get(name) {
                    out.push(Instr::CallFn {
                        idx,
                        argc: args.len(),
                    });
                } else {
                    out.push(Instr::Call {
                        name: name.clone(),
                        argc: args.len(),
                    });
                }
            }
            Expr::Method {
                receiver,
                method,
                args,
            } => {
                if let Expr::RouteField(field) = receiver.as_ref() {
                    for a in args {
                        self.compile_expr(a, out);
                    }
                    out.push(Instr::Method {
                        field: *field,
                        method: method.clone(),
                        argc: args.len(),
                    });
                } else {
                    // The interpreter errors on this shape; keep the
                    // same behaviour by routing through the tree walk.
                    out.push(Instr::EvalTree(expr.clone()));
                }
            }
            Expr::Defined(inner) => {
                let target = match inner.as_ref() {
                    Expr::RouteField(f) => DefinedTarget::Field(*f),
                    Expr::Var(n) => DefinedTarget::Var(n.clone()),
                    Expr::Lit(_) => DefinedTarget::Literal,
                    other => DefinedTarget::Dynamic(other.clone()),
                };
                out.push(Instr::Defined(target));
            }
            Expr::Binary { op, lhs, rhs } => match op {
                // Short-circuit operators compile to jumps; everything
                // else is a plain three-address stack op.
                BinaryOp::And => {
                    // <a>; JumpIfFalse(Lf); <b>; Truthy; Jump(Le);
                    // Lf: Push(false); Le:
                    self.compile_expr(lhs, out);
                    let jf = out.len();
                    out.push(Instr::JumpIfFalse(usize::MAX));
                    self.compile_expr(rhs, out);
                    out.push(Instr::Truthy);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    let lf = out.len();
                    out.push(Instr::Push(Value::Bool(false)));
                    out[jf] = Instr::JumpIfFalse(lf);
                    out[j] = Instr::Jump(out.len());
                }
                BinaryOp::Or => {
                    // <a>; JumpIfTrue(Lt); <b>; Truthy; Jump(Le);
                    // Lt: Push(true); Le:
                    self.compile_expr(lhs, out);
                    let jt = out.len();
                    out.push(Instr::JumpIfTrue(usize::MAX));
                    self.compile_expr(rhs, out);
                    out.push(Instr::Truthy);
                    let j = out.len();
                    out.push(Instr::Jump(usize::MAX));
                    let lt = out.len();
                    out.push(Instr::Push(Value::Bool(true)));
                    out[jt] = Instr::JumpIfTrue(lt);
                    out[j] = Instr::Jump(out.len());
                }
                BinaryOp::Match | BinaryOp::NotMatch => {
                    self.compile_expr(lhs, out);
                    let rhs_c = self.compile_match_rhs(rhs);
                    out.push(Instr::Match {
                        negated: matches!(op, BinaryOp::NotMatch),
                        rhs: rhs_c,
                    });
                }
                other => {
                    self.compile_expr(lhs, out);
                    self.compile_expr(rhs, out);
                    out.push(Instr::Bin(*other));
                }
            },
            Expr::Unary { op, expr } => {
                self.compile_expr(expr, out);
                match op {
                    UnaryOp::Not => out.push(Instr::Not),
                    UnaryOp::Neg => out.push(Instr::Neg),
                }
            }
            Expr::Set(_) => {
                // Non-constant sets are only consumed by `~` in
                // practice; as a plain value they compile to the
                // tree walk so `Value::Set` construction semantics
                // stay identical.
                out.push(Instr::EvalTree(expr.clone()));
            }
            Expr::PrefixSet { prefix, .. } => {
                // As a bare value a prefix range evaluates to the
                // prefix itself (interpreter parity); the range only
                // matters inside a `~` pattern, handled there.
                out.push(Instr::Push(Value::Prefix(*prefix)));
            }
        }
    }

    fn compile_match_rhs(&self, rhs: &Expr) -> MatchRhs {
        match rhs {
            Expr::Set(items) => {
                // Compile each AST item into a `MatchItem`, then
                // check whether any are prefix patterns. When at
                // least one is, build a `PrefixSetTrie` over the
                // prefix items and keep the non-prefix items in
                // `others` for a linear scan. The trie turns the
                // O(n) prefix-containment scan into O(prefix_len) —
                // the #19 P4 win.
                let compiled: Vec<MatchItem> = items
                    .iter()
                    .map(|i| match i {
                        Expr::PrefixSet { prefix, ge, le } => MatchItem::PrefixSet {
                            prefix: *prefix,
                            ge: *ge,
                            le: *le,
                        },
                        Expr::Lit(v) => MatchItem::Value(v.clone()),
                        other => MatchItem::Expr(other.clone()),
                    })
                    .collect();
                let has_prefix = compiled
                    .iter()
                    .any(|i| matches!(i, MatchItem::PrefixSet { .. }));
                if has_prefix {
                    let trie = PrefixSetTrie::build(&compiled);
                    let others: Vec<MatchItem> = compiled
                        .into_iter()
                        .filter(|i| !matches!(i, MatchItem::PrefixSet { .. }))
                        .collect();
                    MatchRhs::PrefixSet { trie, others }
                } else {
                    MatchRhs::Set(compiled)
                }
            }
            Expr::PrefixSet { prefix, ge, le } => {
                // Single prefix pattern — build a one-entry trie.
                let trie = PrefixSetTrie::build(&[MatchItem::PrefixSet {
                    prefix: *prefix,
                    ge: *ge,
                    le: *le,
                }]);
                MatchRhs::PrefixSet {
                    trie,
                    others: Vec::new(),
                }
            }
            Expr::Lit(v) => MatchRhs::Value(v.clone()),
            other => MatchRhs::Expr(other.clone()),
        }
    }
}
