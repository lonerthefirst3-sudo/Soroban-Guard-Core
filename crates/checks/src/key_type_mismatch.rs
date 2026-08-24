//! Detects storage key type mismatches: the same logical key written as a
//! `Symbol` (via `symbol_short!` or `Symbol::new`) but looked up as a string
//! literal (or vice-versa).
//!
//! In Soroban, `Symbol` and `String`/`Bytes` are distinct runtime types. A
//! `set` call using a `Symbol` key and a `get` call using a string literal for
//! the same name will never find the entry — the data is silently shadowed.

use crate::util::is_contractimpl;
use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, ImplItem, Item};

const CHECK_NAME: &str = "key-type-mismatch";

// ---------------------------------------------------------------------------
// Key type classification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyKind {
    Symbol,
    StringLit,
}

/// Scan the file for top-level `const IDENT: Symbol = symbol_short!("name");`
/// declarations and return a map from ident name → string value.
fn collect_symbol_consts(file: &File) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for item in &file.items {
        let syn::Item::Const(c) = item else { continue };
        // Check the type is Symbol-ish (Symbol or soroban_sdk::Symbol)
        let type_is_symbol = match &*c.ty {
            syn::Type::Path(p) => p
                .path
                .segments
                .last()
                .map(|s| s.ident == "Symbol")
                .unwrap_or(false),
            _ => false,
        };
        if !type_is_symbol {
            continue;
        }
        // Check the value is symbol_short!("name")
        if let Expr::Macro(m) = &*c.expr {
            let mac_name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if mac_name == "symbol_short" {
                let tokens = m.mac.tokens.to_string();
                let name = tokens.trim().trim_matches('"').to_string();
                if !name.is_empty() {
                    map.insert(c.ident.to_string(), name);
                }
            }
        }
    }
    map
}

/// Classify a storage key argument.
///
/// Returns `(canonical_string_name, KeyKind)` or `None` when the form is not
/// statically classifiable.
fn classify_key(arg: &Expr, symbol_consts: &HashMap<String, String>) -> Option<(String, KeyKind)> {
    // Strip a leading `&`
    let inner = match arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };

    match inner {
        // "literal"  →  StringLit
        Expr::Lit(l) => {
            if let syn::Lit::Str(s) = &l.lit {
                return Some((s.value(), KeyKind::StringLit));
            }
            None
        }

        // symbol_short!("name") inline  →  Symbol
        Expr::Macro(m) => {
            let mac_name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            if mac_name == "symbol_short" {
                let tokens = m.mac.tokens.to_string();
                let name = tokens.trim().trim_matches('"').to_string();
                if !name.is_empty() {
                    return Some((name, KeyKind::Symbol));
                }
            }
            None
        }

        // Symbol::new(&env, "name")  →  Symbol with the literal name
        Expr::Call(c) => {
            if let Expr::Path(p) = &*c.func {
                let segs = &p.path.segments;
                if segs.len() == 2 && segs[0].ident == "Symbol" && segs[1].ident == "new" {
                    if let Some(name_arg) = c.args.iter().nth(1) {
                        let name_inner = match name_arg {
                            Expr::Reference(r) => &*r.expr,
                            other => other,
                        };
                        if let Expr::Lit(l) = name_inner {
                            if let syn::Lit::Str(s) = &l.lit {
                                return Some((s.value(), KeyKind::Symbol));
                            }
                        }
                    }
                    // Dynamic Symbol::new — not classifiable by name
                    return None;
                }
            }
            None
        }

        // A path like `KEY` or `BALANCE` — resolve via the const map
        Expr::Path(p) => {
            if p.path.segments.len() == 1 {
                let ident = p.path.segments[0].ident.to_string();
                if let Some(resolved) = symbol_consts.get(&ident) {
                    return Some((resolved.clone(), KeyKind::Symbol));
                }
            }
            None
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Per-impl collector
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct KeyUse {
    kind: KeyKind,
    op: String,
    fn_name: String,
    line: usize,
}

struct KeyCollector<'a> {
    fn_name: String,
    symbol_consts: &'a HashMap<String, String>,
    uses: HashMap<String, Vec<KeyUse>>,
}

fn extract_tier(expr: &Expr) -> String {
    match expr {
        Expr::MethodCall(m) => {
            let method = m.method.to_string();
            if matches!(method.as_str(), "persistent" | "instance" | "temporary") {
                return method;
            }
            extract_tier(&m.receiver)
        }
        Expr::Field(f) => extract_tier(&f.base),
        _ => String::new(),
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "storage" || receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

impl<'a> Visit<'_> for KeyCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let op = i.method.to_string();
        if matches!(op.as_str(), "set" | "get" | "has" | "remove")
            && receiver_chain_contains_storage(&i.receiver)
        {
            if let Some(key_arg) = i.args.first() {
                if let Some((name, kind)) = classify_key(key_arg, self.symbol_consts) {
                    self.uses.entry(name).or_default().push(KeyUse {
                        kind,
                        op,
                        fn_name: self.fn_name.clone(),
                        line: i.span().start().line,
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

pub struct KeyTypeMismatchCheck;

impl Check for KeyTypeMismatchCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let symbol_consts = collect_symbol_consts(file);
        let mut out = Vec::new();

        for item in &file.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };
            if !is_contractimpl(item_impl) {
                continue;
            }

            // Collect all key uses across every function in this impl block.
            let mut all_uses: HashMap<String, Vec<KeyUse>> = HashMap::new();

            for impl_item in &item_impl.items {
                let ImplItem::Fn(method) = impl_item else {
                    continue;
                };
                let fn_name = method.sig.ident.to_string();
                let mut collector = KeyCollector {
                    fn_name,
                    symbol_consts: &symbol_consts,
                    uses: HashMap::new(),
                };
                collector.visit_block(&method.block);
                for (key, uses) in collector.uses {
                    all_uses.entry(key).or_default().extend(uses);
                }
            }

            // Flag any key that appears with both Symbol and StringLit kinds.
            for (key, uses) in &all_uses {
                let has_symbol = uses.iter().any(|u| u.kind == KeyKind::Symbol);
                let has_string = uses.iter().any(|u| u.kind == KeyKind::StringLit);

                if has_symbol && has_string {
                    for u in uses {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: u.line,
                            function_name: u.fn_name.clone(),
                            description: format!(
                                "Storage key `{key}` is used with mixed types: as a `Symbol` \
                                 in one call and as a string literal in another (op `{}` in \
                                 `{}`). In Soroban, `Symbol` and string keys are distinct \
                                 runtime types — a lookup with the wrong type will never find \
                                 the entry, silently returning empty/default data.",
                                u.op, u.fn_name
                            ),
                        });
                    }
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(KeyTypeMismatchCheck.run(&file, src))
    }

    // ------------------------------------------------------------------
    // Should flag
    // ------------------------------------------------------------------

    #[test]
    fn flags_symbol_short_set_string_get() -> Result<(), syn::Error> {
        // Written with symbol_short! const, read back with a string literal.
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const BALANCE: Symbol = symbol_short!("balance");
#[contractimpl]
impl C {
    pub fn set_bal(env: Env, v: i128) {
        env.storage().persistent().set(&BALANCE, &v);
    }
    pub fn get_bal(env: Env) -> i128 {
        // ❌ wrong key type — will never find the entry written above
        env.storage().persistent().get("balance").unwrap_or(0)
    }
}
"#)?;
        assert_eq!(hits.len(), 2, "expected 2 findings, got {hits:?}");
        assert!(hits.iter().all(|f| f.severity == Severity::Medium));
        assert!(hits.iter().all(|f| f.description.contains("balance")));
        Ok(())
    }

    #[test]
    fn flags_string_set_symbol_get() -> Result<(), syn::Error> {
        // Written with a string literal, read back with symbol_short! const.
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const KEY: Symbol = symbol_short!("nonce");
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().instance().set("nonce", &1u64);
    }
    pub fn read(env: Env) -> u64 {
        env.storage().instance().get(&KEY).unwrap_or(0)
    }
}
"#)?;
        assert_eq!(hits.len(), 2, "got {hits:?}");
        Ok(())
    }

    #[test]
    fn flags_symbol_new_set_string_get() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn write(env: Env) {
        env.storage().persistent().set(&Symbol::new(&env, "config"), &42u32);
    }
    pub fn read(env: Env) -> u32 {
        env.storage().persistent().get("config").unwrap_or(0)
    }
}
"#)?;
        assert_eq!(hits.len(), 2, "got {hits:?}");
        Ok(())
    }

    #[test]
    fn flags_cross_function_mismatch() -> Result<(), syn::Error> {
        // Mismatch spread across three functions.
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const STATE: Symbol = symbol_short!("state");
#[contractimpl]
impl C {
    pub fn init(env: Env) {
        env.storage().persistent().set(&STATE, &0u32);
    }
    pub fn check(env: Env) -> bool {
        env.storage().persistent().has("state")
    }
    pub fn reset(env: Env) {
        env.storage().persistent().set("state", &0u32);
    }
}
"#)?;
        // STATE (Symbol) in init + "state" (StringLit) in check and reset → 3 findings
        assert_eq!(hits.len(), 3, "got {hits:?}");
        let fn_names: Vec<&str> = hits.iter().map(|f| f.function_name.as_str()).collect();
        assert!(fn_names.contains(&"init"));
        assert!(fn_names.contains(&"check"));
        assert!(fn_names.contains(&"reset"));
        Ok(())
    }

    // ------------------------------------------------------------------
    // Should NOT flag
    // ------------------------------------------------------------------

    #[test]
    fn passes_consistent_symbol_short() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const BAL: Symbol = symbol_short!("bal");
#[contractimpl]
impl C {
    pub fn set(env: Env, v: i128) { env.storage().persistent().set(&BAL, &v); }
    pub fn get(env: Env) -> i128  { env.storage().persistent().get(&BAL).unwrap_or(0) }
}
"#)?;
        assert!(hits.is_empty(), "unexpected findings: {hits:?}");
        Ok(())
    }

    #[test]
    fn passes_consistent_string_literal() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set(env: Env, v: u32) { env.storage().instance().set("counter", &v); }
    pub fn get(env: Env) -> u32  { env.storage().instance().get("counter").unwrap_or(0) }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_different_keys_different_types() -> Result<(), syn::Error> {
        // Symbol key for one slot, string key for a different slot — no collision.
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
const ADMIN: Symbol = symbol_short!("admin");
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, v: u32) { env.storage().persistent().set(&ADMIN, &v); }
    pub fn set_count(env: Env, v: u32) { env.storage().persistent().set("count", &v); }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_outside_contractimpl() -> Result<(), syn::Error> {
        // Plain impl block — not scanned.
        let hits = run(r#"
use soroban_sdk::{symbol_short, Env, Symbol};
pub struct C;
const KEY: Symbol = symbol_short!("key");
impl C {
    pub fn set(env: Env, v: u32) { env.storage().persistent().set(&KEY, &v); }
    pub fn get(env: Env) -> u32  { env.storage().persistent().get("key").unwrap_or(0) }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }
}
