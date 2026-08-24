//! Detects oracle prices that are consumed without a reachable freshness check.
//!
//! Unlike every other check in this crate (a single `syn::visit::Visit` walk over one
//! function body), this check builds a small **call graph** over every function defined
//! in the file and asks a reachability question: starting from each public
//! `#[contractimpl]` entry point, does *any* function it can transitively call compare
//! the oracle's `last_updated`-style field against `env.ledger().timestamp()` before the
//! price is used in arithmetic? The freshness check does not have to live in the same
//! function as the read or the use — it only has to be reachable from the same entry
//! point.

use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet, VecDeque};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprField, ExprMethodCall, ExprPath, ExprStruct,
    File, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, Local, Member, Pat, Visibility,
};

const CHECK_NAME: &str = "oracle-price-staleness";

pub struct OraclePriceStalenessCheck;

impl Check for OraclePriceStalenessCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let tracked_keys = find_tracked_price_keys(file);
        if tracked_keys.is_empty() {
            return Vec::new();
        }

        let functions = collect_functions(file);
        let graph = build_call_graph(&functions);
        let entry_points = entry_point_names(file);

        let freshness_checkers: HashSet<String> = functions
            .iter()
            .filter(|(_, body)| is_freshness_checker(body, &tracked_keys))
            .map(|(name, _)| name.clone())
            .collect();

        let read_sites: Vec<(String, &Block)> = functions
            .iter()
            .filter(|(_, body)| reads_tracked_key(body, &tracked_keys))
            .map(|(name, body)| (name.clone(), *body))
            .collect();

        if read_sites.is_empty() {
            return Vec::new();
        }

        let mut reach_cache: HashMap<String, HashSet<String>> = HashMap::new();
        let mut out = Vec::new();
        let mut seen = HashSet::new();

        for (reader, _) in &read_sites {
            let roots = roots_reaching(reader, &entry_points, &graph, &mut reach_cache);

            let mut context: HashSet<String> = HashSet::new();
            for root in &roots {
                context.extend(reach_set(root, &graph, &mut reach_cache).iter().cloned());
            }
            context.insert(reader.clone());

            let has_check = context.iter().any(|f| freshness_checkers.contains(f));
            if has_check {
                continue;
            }

            let Some((use_fn, line)) = find_arithmetic_use(&context, &functions, &tracked_keys)
            else {
                continue;
            };

            if !seen.insert((use_fn.clone(), line)) {
                continue;
            }

            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: use_fn.clone(),
                description: format!(
                    "Function `{use_fn}` uses an oracle-fed price in arithmetic, but no \
                     function reachable from the same entry point (including `{reader}`, \
                     which reads it) ever compares the price's freshness field against \
                     `env.ledger().timestamp()`. A stale price can be used for the \
                     calculation if the oracle feed stops updating."
                ),
            });
        }

        out
    }
}

/// A `(price fields, freshness field, storage key)` pattern discovered at a write site:
/// `PriceData { value, last_updated: env.ledger().timestamp() }` written under one key.
struct TrackedPrice {
    key: String,
    freshness_field: String,
    price_fields: HashSet<String>,
}

/// Finds the `PriceData { value, last_updated: env.ledger().timestamp() }` pattern
/// written under a storage key, per function. The struct literal may appear inline in
/// the `.set()` call, or (the common case) be bound to a local first and passed by
/// reference — both are resolved within the same function body.
fn find_tracked_price_keys(file: &File) -> Vec<TrackedPrice> {
    let functions = collect_functions(file);
    let mut out = Vec::new();
    for body in functions.values() {
        out.extend(find_tracked_price_keys_in_block(body));
    }
    out
}

fn find_tracked_price_keys_in_block(body: &Block) -> Vec<TrackedPrice> {
    struct StructLocalScan {
        locals: HashMap<String, (String, HashSet<String>)>,
    }

    impl<'ast> Visit<'ast> for StructLocalScan {
        fn visit_local(&mut self, i: &'ast Local) {
            if let Some(init) = &i.init {
                if let Some(info) = struct_fields_info(strip_ref(&init.expr)) {
                    if let Some(name) = local_bound_name(&i.pat) {
                        self.locals.insert(name, info);
                    }
                }
            }
            visit::visit_local(self, i);
        }
    }

    let mut local_scan = StructLocalScan {
        locals: HashMap::new(),
    };
    local_scan.visit_block(body);

    struct SetCallScan<'a> {
        locals: &'a HashMap<String, (String, HashSet<String>)>,
        found: Vec<TrackedPrice>,
    }

    impl<'ast, 'a> Visit<'ast> for SetCallScan<'a> {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "set" && receiver_chain_contains(&i.receiver, "storage") {
                if let (Some(key_arg), Some(value_arg)) = (i.args.first(), i.args.iter().nth(1)) {
                    let value = strip_ref(value_arg);
                    let info = match value {
                        Expr::Struct(_) => struct_fields_info(value),
                        Expr::Path(p) => p
                            .path
                            .get_ident()
                            .and_then(|ident| self.locals.get(&ident.to_string()).cloned()),
                        _ => None,
                    };
                    if let Some((freshness_field, price_fields)) = info {
                        self.found.push(TrackedPrice {
                            key: key_repr(key_arg),
                            freshness_field,
                            price_fields,
                        });
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut scan = SetCallScan {
        locals: &local_scan.locals,
        found: Vec::new(),
    };
    scan.visit_block(body);
    scan.found
}

fn local_bound_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(pi) => Some(pi.ident.to_string()),
        Pat::Type(pt) => local_bound_name(&pt.pat),
        _ => None,
    }
}

/// Extracts `(freshness_field_name, price_field_names)` from a struct literal that has a
/// field whose initializer contains `env.ledger().timestamp()`.
fn struct_fields_info(expr: &Expr) -> Option<(String, HashSet<String>)> {
    let Expr::Struct(ExprStruct { fields, .. }) = expr else {
        return None;
    };

    let mut freshness_field = None;
    let mut price_fields = HashSet::new();
    for field in fields {
        let Member::Named(ident) = &field.member else {
            continue;
        };
        let name = ident.to_string();
        if expr_contains_ledger_timestamp(&field.expr) {
            freshness_field = Some(name);
        } else {
            price_fields.insert(name);
        }
    }

    let freshness_field = freshness_field?;
    if price_fields.is_empty() {
        return None;
    }
    Some((freshness_field, price_fields))
}

/// All functions in the file, keyed by identifier name: free functions and every method
/// inside every `impl` block (not only `#[contractimpl]` ones, since a helper such as
/// `check_price_fresh` is often a plain associated function or free function).
fn collect_functions(file: &File) -> HashMap<String, &Block> {
    let mut out = HashMap::new();
    for item in &file.items {
        match item {
            Item::Fn(ItemFn { sig, block, .. }) => {
                out.insert(sig.ident.to_string(), block.as_ref());
            }
            Item::Impl(ItemImpl { items, .. }) => {
                for impl_item in items {
                    if let ImplItem::Fn(ImplItemFn { sig, block, .. }) = impl_item {
                        out.insert(sig.ident.to_string(), block);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn entry_point_names(file: &File) -> Vec<String> {
    crate::util::contractimpl_functions(file)
        .into_iter()
        .filter(|m| matches!(m.vis, Visibility::Public(_)))
        .map(|m| m.sig.ident.to_string())
        .collect()
}

/// Directed caller -> callee edges, resolved by matching call/method-call idents against
/// known function names in the file. Name-based resolution (no type inference), same
/// heuristic style as the rest of this crate.
fn build_call_graph(functions: &HashMap<String, &Block>) -> HashMap<String, HashSet<String>> {
    struct CallScan<'a> {
        known: &'a HashMap<String, &'a Block>,
        callees: HashSet<String>,
    }

    impl<'ast, 'a> Visit<'ast> for CallScan<'a> {
        fn visit_expr_call(&mut self, i: &'ast ExprCall) {
            if let Expr::Path(ExprPath { path, .. }) = &*i.func {
                if let Some(seg) = path.segments.last() {
                    let name = seg.ident.to_string();
                    if self.known.contains_key(&name) {
                        self.callees.insert(name);
                    }
                }
            }
            visit::visit_expr_call(self, i);
        }

        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            let name = i.method.to_string();
            if self.known.contains_key(&name) {
                self.callees.insert(name);
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut graph = HashMap::new();
    for (name, body) in functions {
        let mut scan = CallScan {
            known: functions,
            callees: HashSet::new(),
        };
        scan.visit_block(body);
        scan.callees.remove(name);
        graph.insert(name.clone(), scan.callees);
    }
    graph
}

fn reach_set<'a>(
    start: &str,
    graph: &HashMap<String, HashSet<String>>,
    cache: &'a mut HashMap<String, HashSet<String>>,
) -> &'a HashSet<String> {
    if !cache.contains_key(start) {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(start.to_string());
        queue.push_back(start.to_string());
        while let Some(node) = queue.pop_front() {
            if let Some(callees) = graph.get(&node) {
                for callee in callees {
                    if visited.insert(callee.clone()) {
                        queue.push_back(callee.clone());
                    }
                }
            }
        }
        cache.insert(start.to_string(), visited);
    }
    cache.get(start).expect("just inserted")
}

/// The public entry points whose forward call tree contains `target` (i.e. `target` is
/// `reach_set(entry)`-reachable, or is the entry itself). Falls back to treating `target`
/// as its own root when no entry point reaches it (e.g. dead code, or the reader itself
/// is the only public function touching the key).
fn roots_reaching(
    target: &str,
    entry_points: &[String],
    graph: &HashMap<String, HashSet<String>>,
    cache: &mut HashMap<String, HashSet<String>>,
) -> Vec<String> {
    let mut roots = Vec::new();
    for entry in entry_points {
        if entry == target || reach_set(entry, graph, cache).contains(target) {
            roots.push(entry.clone());
        }
    }
    if roots.is_empty() {
        roots.push(target.to_string());
    }
    roots
}

fn reads_tracked_key(body: &Block, tracked: &[TrackedPrice]) -> bool {
    struct GetScan<'a> {
        tracked: &'a [TrackedPrice],
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for GetScan<'a> {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "get" && receiver_chain_contains(&i.receiver, "storage") {
                if let Some(key_arg) = i.args.first() {
                    let key = key_repr(key_arg);
                    if self.tracked.iter().any(|t| t.key == key) {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut scan = GetScan {
        tracked,
        found: false,
    };
    scan.visit_block(body);
    scan.found
}

/// A function is a freshness checker if it contains a comparison (`<`, `<=`, `>`, `>=`)
/// whose operand subtree contains both a timestamp signal (`env.ledger().timestamp()`,
/// inline or via a local bound to it, e.g. `let now = env.ledger().timestamp();`) and an
/// identifier or field access named like the tracked freshness field (e.g.
/// `last_updated`).
fn is_freshness_checker(body: &Block, tracked: &[TrackedPrice]) -> bool {
    let timestamp_vars = bound_timestamp_vars(body);

    struct CompareScan<'a> {
        tracked: &'a [TrackedPrice],
        timestamp_vars: &'a HashSet<String>,
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for CompareScan<'a> {
        fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
            if is_comparison(&i.op) {
                let has_timestamp = expr_contains_timestamp_signal(&i.left, self.timestamp_vars)
                    || expr_contains_timestamp_signal(&i.right, self.timestamp_vars);
                let has_field = self.tracked.iter().any(|t| {
                    expr_contains_named_field(&i.left, &t.freshness_field)
                        || expr_contains_named_field(&i.right, &t.freshness_field)
                });
                if has_timestamp && has_field {
                    self.found = true;
                }
            }
            visit::visit_expr_binary(self, i);
        }

        fn visit_macro(&mut self, i: &'ast syn::Macro) {
            for expr in macro_body_exprs(i) {
                self.visit_expr(&expr);
            }
            visit::visit_macro(self, i);
        }
    }

    let mut scan = CompareScan {
        tracked,
        timestamp_vars: &timestamp_vars,
        found: false,
    };
    scan.visit_block(body);
    scan.found
}

/// Local variable names bound from an initializer that contains `env.ledger().timestamp()`,
/// e.g. `let now = env.ledger().timestamp();`.
fn bound_timestamp_vars(body: &Block) -> HashSet<String> {
    struct LocalScan {
        vars: HashSet<String>,
    }

    impl<'ast> Visit<'ast> for LocalScan {
        fn visit_local(&mut self, i: &'ast Local) {
            if let Some(init) = &i.init {
                if expr_contains_ledger_timestamp(&init.expr) {
                    if let Some(name) = local_bound_name(&i.pat) {
                        self.vars.insert(name);
                    }
                }
            }
            visit::visit_local(self, i);
        }
    }

    let mut scan = LocalScan {
        vars: HashSet::new(),
    };
    scan.visit_block(body);
    scan.vars
}

fn expr_contains_timestamp_signal(expr: &Expr, timestamp_vars: &HashSet<String>) -> bool {
    struct TimestampSignalScan<'a> {
        timestamp_vars: &'a HashSet<String>,
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for TimestampSignalScan<'a> {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "timestamp" {
                if let Expr::MethodCall(inner) = &*i.receiver {
                    if inner.method == "ledger" {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }

        fn visit_expr_path(&mut self, i: &'ast ExprPath) {
            if let Some(ident) = i.path.get_ident() {
                if self.timestamp_vars.contains(&ident.to_string()) {
                    self.found = true;
                }
            }
            visit::visit_expr_path(self, i);
        }
    }

    let mut scan = TimestampSignalScan {
        timestamp_vars,
        found: false,
    };
    scan.visit_expr(expr);
    scan.found
}

/// Parses a macro invocation's body as a comma-separated list of expressions, so
/// `assert!(cond, "message")` still exposes `cond` for inspection even though the whole
/// body is not a single valid `Expr`.
fn macro_body_exprs(mac: &syn::Macro) -> Vec<Expr> {
    mac.parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        .map(|p| p.into_iter().collect())
        .unwrap_or_default()
}

fn is_comparison(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_)
    )
}

/// Finds the first function in `context` that performs arithmetic (`+ - * / %`) on a
/// value sourced from the tracked key: either a variable bound from a `.get(&KEY)` call
/// (directly, or through `.field`), or a field access matching a known price field name.
fn find_arithmetic_use(
    context: &HashSet<String>,
    functions: &HashMap<String, &Block>,
    tracked: &[TrackedPrice],
) -> Option<(String, usize)> {
    for name in context {
        let Some(body) = functions.get(name) else {
            continue;
        };
        let bound_vars = bound_price_vars(body, tracked);
        if let Some(line) = first_arithmetic_use_line(body, tracked, &bound_vars) {
            return Some((name.clone(), line));
        }
    }
    None
}

/// Local variable names bound from an initializer that reads the tracked key, e.g.
/// `let data: PriceData = env.storage().instance().get(&KEY).unwrap();`.
fn bound_price_vars(body: &Block, tracked: &[TrackedPrice]) -> HashSet<String> {
    struct LocalScan<'a> {
        tracked: &'a [TrackedPrice],
        vars: HashSet<String>,
    }

    impl<'ast, 'a> Visit<'ast> for LocalScan<'a> {
        fn visit_local(&mut self, i: &'ast Local) {
            if let Some(init) = &i.init {
                if expr_contains_tracked_get(&init.expr, self.tracked) {
                    if let Pat::Ident(pi) = &i.pat {
                        self.vars.insert(pi.ident.to_string());
                    } else if let Pat::Type(pt) = &i.pat {
                        if let Pat::Ident(pi) = &*pt.pat {
                            self.vars.insert(pi.ident.to_string());
                        }
                    }
                }
            }
            visit::visit_local(self, i);
        }
    }

    let mut scan = LocalScan {
        tracked,
        vars: HashSet::new(),
    };
    scan.visit_block(body);
    scan.vars
}

fn expr_contains_tracked_get(expr: &Expr, tracked: &[TrackedPrice]) -> bool {
    struct GetScan<'a> {
        tracked: &'a [TrackedPrice],
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for GetScan<'a> {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "get" && receiver_chain_contains(&i.receiver, "storage") {
                if let Some(key_arg) = i.args.first() {
                    let key = key_repr(key_arg);
                    if self.tracked.iter().any(|t| t.key == key) {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut scan = GetScan {
        tracked,
        found: false,
    };
    scan.visit_expr(expr);
    scan.found
}

fn first_arithmetic_use_line(
    body: &Block,
    tracked: &[TrackedPrice],
    bound_vars: &HashSet<String>,
) -> Option<usize> {
    struct ArithScan<'a> {
        tracked: &'a [TrackedPrice],
        bound_vars: &'a HashSet<String>,
        line: Option<usize>,
    }

    impl<'ast, 'a> Visit<'ast> for ArithScan<'a> {
        fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
            if self.line.is_none() && is_arithmetic(&i.op) {
                let hit = operand_is_price(&i.left, self.tracked, self.bound_vars)
                    || operand_is_price(&i.right, self.tracked, self.bound_vars);
                if hit {
                    self.line = Some(i.span().start().line);
                }
            }
            visit::visit_expr_binary(self, i);
        }
    }

    let mut scan = ArithScan {
        tracked,
        bound_vars,
        line: None,
    };
    scan.visit_block(body);
    scan.line
}

fn is_arithmetic(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_)
            | BinOp::Sub(_)
            | BinOp::Mul(_)
            | BinOp::Div(_)
            | BinOp::Rem(_)
            | BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
    )
}

fn operand_is_price(expr: &Expr, tracked: &[TrackedPrice], bound_vars: &HashSet<String>) -> bool {
    struct PriceOperandScan<'a> {
        tracked: &'a [TrackedPrice],
        bound_vars: &'a HashSet<String>,
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for PriceOperandScan<'a> {
        fn visit_expr_path(&mut self, i: &'ast ExprPath) {
            if let Some(ident) = i.path.get_ident() {
                if self.bound_vars.contains(&ident.to_string()) {
                    self.found = true;
                }
            }
            visit::visit_expr_path(self, i);
        }

        fn visit_expr_field(&mut self, i: &'ast ExprField) {
            if let Member::Named(ident) = &i.member {
                let name = ident.to_string();
                if self.tracked.iter().any(|t| t.price_fields.contains(&name))
                    && expr_rooted_in_bound_var(&i.base, self.bound_vars)
                {
                    self.found = true;
                }
            }
            visit::visit_expr_field(self, i);
        }

        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "get" && receiver_chain_contains(&i.receiver, "storage") {
                if let Some(key_arg) = i.args.first() {
                    let key = key_repr(key_arg);
                    if self.tracked.iter().any(|t| t.key == key) {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut scan = PriceOperandScan {
        tracked,
        bound_vars,
        found: false,
    };
    scan.visit_expr(expr);
    scan.found
}

fn expr_rooted_in_bound_var(expr: &Expr, bound_vars: &HashSet<String>) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|i| bound_vars.contains(&i.to_string())),
        Expr::Reference(r) => expr_rooted_in_bound_var(&r.expr, bound_vars),
        Expr::Field(f) => expr_rooted_in_bound_var(&f.base, bound_vars),
        Expr::MethodCall(m) => expr_rooted_in_bound_var(&m.receiver, bound_vars),
        _ => false,
    }
}

fn expr_contains_ledger_timestamp(expr: &Expr) -> bool {
    struct TimestampScan {
        found: bool,
    }

    impl<'ast> Visit<'ast> for TimestampScan {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if i.method == "timestamp" {
                if let Expr::MethodCall(inner) = &*i.receiver {
                    if inner.method == "ledger" {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_method_call(self, i);
        }
    }

    let mut scan = TimestampScan { found: false };
    scan.visit_expr(expr);
    scan.found
}

fn expr_contains_named_field(expr: &Expr, name: &str) -> bool {
    struct NamedScan<'a> {
        name: &'a str,
        found: bool,
    }

    impl<'ast, 'a> Visit<'ast> for NamedScan<'a> {
        fn visit_expr_path(&mut self, i: &'ast ExprPath) {
            if let Some(ident) = i.path.get_ident() {
                if ident == self.name {
                    self.found = true;
                }
            }
            visit::visit_expr_path(self, i);
        }

        fn visit_expr_field(&mut self, i: &'ast ExprField) {
            if let Member::Named(ident) = &i.member {
                if ident == self.name {
                    self.found = true;
                }
            }
            visit::visit_expr_field(self, i);
        }
    }

    let mut scan = NamedScan { name, found: false };
    scan.visit_expr(expr);
    scan.found
}

fn strip_ref(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(r) => strip_ref(&r.expr),
        _ => expr,
    }
}

fn receiver_chain_contains(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == name {
                return true;
            }
            receiver_chain_contains(&m.receiver, name)
        }
        Expr::Field(f) => receiver_chain_contains(&f.base, name),
        _ => false,
    }
}

fn key_repr(expr: &Expr) -> String {
    use quote::ToTokens;
    let stripped = strip_ref(expr);
    let mut ts = proc_macro2::TokenStream::new();
    stripped.to_tokens(&mut ts);
    ts.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_price_used_with_no_reachable_freshness_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, contracttype, Env};

#[contracttype]
pub struct PriceData {
    pub price: i128,
    pub last_updated: u64,
}

pub struct C;

#[contractimpl]
impl C {
    pub fn set_price(env: Env, price: i128) {
        let data = PriceData { price, last_updated: env.ledger().timestamp() };
        env.storage().instance().set(&"PRICE", &data);
    }

    pub fn swap(env: Env, amount: i128) -> i128 {
        let data: PriceData = env.storage().instance().get(&"PRICE").unwrap();
        amount * data.price / 1_000_000
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OraclePriceStalenessCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "swap");
        Ok(())
    }

    #[test]
    fn clears_when_freshness_check_is_a_reachable_helper() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, contracttype, Env};

#[contracttype]
pub struct PriceData {
    pub price: i128,
    pub last_updated: u64,
}

const MAX_AGE: u64 = 3600;

pub struct C;

#[contractimpl]
impl C {
    pub fn set_price(env: Env, price: i128) {
        let data = PriceData { price, last_updated: env.ledger().timestamp() };
        env.storage().instance().set(&"PRICE", &data);
    }

    pub fn swap(env: Env, amount: i128) -> i128 {
        let data: PriceData = env.storage().instance().get(&"PRICE").unwrap();
        check_price_fresh(&env, &data);
        amount * data.price / 1_000_000
    }
}

fn check_price_fresh(env: &Env, data: &PriceData) {
    let now = env.ledger().timestamp();
    assert!(now - data.last_updated <= MAX_AGE, "stale price");
}
"#;
        let file = parse_file(src)?;
        let hits = OraclePriceStalenessCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_findings_without_a_tracked_price_write() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn swap(env: Env, amount: i128, price: i128) -> i128 {
        amount * price
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OraclePriceStalenessCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_read_with_no_arithmetic_use() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, contracttype, Env};

#[contracttype]
pub struct PriceData {
    pub price: i128,
    pub last_updated: u64,
}

pub struct C;

#[contractimpl]
impl C {
    pub fn set_price(env: Env, price: i128) {
        let data = PriceData { price, last_updated: env.ledger().timestamp() };
        env.storage().instance().set(&"PRICE", &data);
    }

    pub fn get_price(env: Env) -> PriceData {
        env.storage().instance().get(&"PRICE").unwrap()
    }
}
"#;
        let file = parse_file(src)?;
        let hits = OraclePriceStalenessCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }
}
