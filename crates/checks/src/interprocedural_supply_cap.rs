//! Interprocedural total-supply cap bypass.
//!
//! `mint_no_cap` and `supply_cap` each look at a single function named `mint` in isolation.
//! A contract can have a *second* way to increase total supply — an admin/emergency/migration
//! entrypoint, or a helper reachable from more than one entrypoint — that increments the same
//! total-supply storage key but never repeats the cap check. Because that check is a whole-file,
//! single-function pattern match, it is blind to a second entrypoint that silently bypasses the
//! cap through its own call path.
//!
//! This check builds a small file-local call graph (by function name, resolved from `syn::ExprCall`
//! targets such as `foo(..)` / `Self::foo(..)` / `Type::foo(..)`), computes the set of functions
//! reachable from each public `#[contractimpl]` entrypoint, and independently asks of *each*
//! entrypoint's reachable set: does it write the total-supply key, and if so, does a cap
//! comparison (`<=`/`<` against something) also appear somewhere on that same reachable set?
//! An entrypoint whose own path writes the key with no cap check anywhere on that path is
//! flagged, even if a sibling entrypoint in the same file does enforce the cap.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::{HashMap, HashSet, VecDeque};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprBinary, ExprCall, ExprMethodCall, File, ImplItem, Item, Macro};

const CHECK_NAME: &str = "interprocedural-supply-cap-bypass";

/// Heuristics for recognizing the total-supply storage key, matching `mint_no_cap`/`supply_cap`.
const SUPPLY_KEY_HINTS: &[&str] = &["supply", "total", "minted", "cap", "max"];

pub struct InterproceduralSupplyCapCheck;

impl Check for InterproceduralSupplyCapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let registry = collect_fn_registry(file);

        let mut summaries: HashMap<String, FnSummary> = HashMap::new();
        for (name, block) in &registry {
            summaries.insert(name.clone(), summarize_fn(block));
        }

        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let entry_name = method.sig.ident.to_string();

            let reachable = reachable_set(&entry_name, &summaries);

            let mut has_write = false;
            let mut has_cap_check = false;
            let mut write_line = None;
            for name in &reachable {
                let Some(summary) = summaries.get(name) else {
                    continue;
                };
                if summary.supply_write {
                    has_write = true;
                    if write_line.is_none() {
                        write_line = summary.write_line;
                    }
                }
                if summary.cap_check {
                    has_cap_check = true;
                }
            }

            if has_write && !has_cap_check {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: write_line.unwrap_or_else(|| method.sig.ident.span().start().line),
                    function_name: entry_name.clone(),
                    description: format!(
                        "Entrypoint `{entry_name}` reaches a write to the total-supply storage \
                         key (directly or through a helper it calls) but no `<=`/`<` cap \
                         comparison appears anywhere on this entrypoint's own call path. \
                         Another entrypoint in this file may enforce the cap on a different \
                         path, but that does not protect this one."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct FnSummary {
    supply_write: bool,
    write_line: Option<usize>,
    cap_check: bool,
    calls: HashSet<String>,
}

/// Every named function body in the file: `#[contractimpl]` methods, methods in any other
/// `impl` block (private helpers are commonly grouped this way), and free `fn` items.
/// This is the callee universe the call graph resolves against.
fn collect_fn_registry(file: &File) -> HashMap<String, &Block> {
    let mut registry = HashMap::new();
    for item in &file.items {
        match item {
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(f) = impl_item {
                        registry.insert(f.sig.ident.to_string(), &f.block);
                    }
                }
            }
            Item::Fn(f) => {
                registry.insert(f.sig.ident.to_string(), &f.block);
            }
            _ => {}
        }
    }
    registry
}

fn summarize_fn(block: &Block) -> FnSummary {
    let mut scan = FnScan::default();
    scan.visit_block(block);
    FnSummary {
        supply_write: scan.supply_write,
        write_line: scan.write_line,
        cap_check: scan.cap_check,
        calls: scan.calls,
    }
}

/// BFS over the call graph starting at `start`, returning `start` plus every function name
/// transitively reachable through calls that resolve to another entry in `summaries`.
fn reachable_set(start: &str, summaries: &HashMap<String, FnSummary>) -> HashSet<String> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(start.to_string());
    queue.push_back(start.to_string());

    while let Some(name) = queue.pop_front() {
        let Some(summary) = summaries.get(&name) else {
            continue;
        };
        for callee in &summary.calls {
            if summaries.contains_key(callee) && visited.insert(callee.clone()) {
                queue.push_back(callee.clone());
            }
        }
    }
    visited
}

#[derive(Default)]
struct FnScan {
    supply_write: bool,
    write_line: Option<usize>,
    cap_check: bool,
    calls: HashSet<String>,
}

impl<'ast> Visit<'ast> for FnScan {
    fn visit_macro(&mut self, i: &'ast Macro) {
        // `assert!(cond)` parses as a single Expr; `assert!(cond, "msg")` does not, since the
        // macro body is `cond, "msg"`. Fall back to the tokens before the first top-level comma
        // so a cap check inside a message-carrying assert! is not silently missed.
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        } else if let Ok(expr) = syn::parse2::<Expr>(first_macro_arg(i)) {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_call(&mut self, i: &'ast ExprCall) {
        if let Expr::Path(p) = &*i.func {
            if let Some(seg) = p.path.segments.last() {
                self.calls.insert(seg.ident.to_string());
            }
        }
        visit::visit_expr_call(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if receiver_chain_contains_storage(&i.receiver) && i.method == "set" {
            if let Some(key_arg) = i.args.first() {
                if expr_contains_supply_hint(key_arg) {
                    self.supply_write = true;
                    if self.write_line.is_none() {
                        self.write_line = Some(i.span().start().line);
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Le(_) | BinOp::Lt(_)) {
            self.cap_check = true;
        }
        visit::visit_expr_binary(self, i);
    }
}

fn first_macro_arg(mac: &Macro) -> proc_macro2::TokenStream {
    let mut result = proc_macro2::TokenStream::new();
    for tt in mac.tokens.clone().into_iter() {
        if let proc_macro2::TokenTree::Punct(p) = &tt {
            if p.as_char() == ',' {
                break;
            }
        }
        result.extend(std::iter::once(tt));
    }
    result
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn expr_contains_supply_hint(expr: &Expr) -> bool {
    let text = expr_to_text(expr).to_lowercase();
    SUPPLY_KEY_HINTS.iter().any(|hint| text.contains(hint))
}

fn expr_to_text(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("_"),
        Expr::Macro(m) => m.mac.tokens.to_string(),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::new(),
        },
        Expr::Reference(r) => expr_to_text(&r.expr),
        Expr::Call(c) => {
            let mut s = expr_to_text(&c.func);
            for arg in &c.args {
                s.push('_');
                s.push_str(&expr_to_text(arg));
            }
            s
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        InterproceduralSupplyCapCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_second_entrypoint_with_direct_uncapped_write() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max_supply);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }

    pub fn emergency_mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "emergency_mint");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn flags_uncapped_write_reached_only_through_a_helper() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max_supply);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }

    pub fn migrate_supply(env: Env, amount: i128) {
        Self::bump_supply(env, amount);
    }

    fn bump_supply(env: Env, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "migrate_supply");
    }

    #[test]
    fn passes_when_every_entrypoint_funnels_through_a_checked_helper() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        Self::mint_checked(env, to, amount);
    }

    pub fn emergency_mint(env: Env, to: Address, amount: i128) {
        Self::mint_checked(env, to, amount);
    }

    fn mint_checked(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max_supply);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_each_entrypoint_independently_enforces_the_cap() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max_supply);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }

    pub fn emergency_mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount < max_supply);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_cap_check_uses_message_carrying_assert() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max_supply: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max_supply, "exceeds max supply");
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_entrypoints_that_never_reach_a_supply_write() {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn balance_of(env: Env, who: Address) -> i128 {
        env.storage().persistent().get(&symbol_short!("bal")).unwrap_or(0)
    }
}
"#,
        );
        assert!(hits.is_empty());
    }
}
