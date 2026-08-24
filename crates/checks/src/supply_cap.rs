//! Mint function without max-supply cap enforcement.
//!
//! A `pub fn mint` in a `#[contractimpl]` block that reads a total supply from storage
//! and adds an amount to it must assert `current_supply + amount <= max_supply` before
//! the storage write. Without this guard, minting can exceed the declared cap.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "supply-cap-not-enforced";

/// Supply key heuristics.
const SUPPLY_KEY_HINTS: &[&str] = &["supply", "total", "minted", "cap", "max"];

pub struct SupplyCapCheck;

impl Check for SupplyCapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if method.sig.ident != "mint" {
                continue;
            }
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }

            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);

            if scan.supply_get && scan.storage_write && !scan.cap_comparison {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: scan.write_line.unwrap_or_else(|| method.sig.ident.span().start().line),
                    function_name: "mint".to_string(),
                    description: "Method `mint` reads a supply value from storage and writes \
                                  back an increased amount, but contains no `<=` or `<` \
                                  comparison against a max-supply cap before the write. \
                                  Minting can exceed the declared cap."
                        .to_string(),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct BodyScan {
    supply_get: bool,
    storage_write: bool,
    cap_comparison: bool,
    write_line: Option<usize>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        if receiver_chain_contains_storage(&i.receiver) {
            match method.as_str() {
                "get" | "get_unchecked" => {
                    if i.args.iter().any(|a| expr_contains_supply_hint(a)) {
                        self.supply_get = true;
                    }
                }
                "set" => {
                    self.storage_write = true;
                    if self.write_line.is_none() {
                        self.write_line = Some(i.span().start().line);
                    }
                }
                _ => {}
            }
        }

        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Le(_) | BinOp::Lt(_)) {
            self.cap_comparison = true;
        }
        visit::visit_expr_binary(self, i);
    }
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
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        SupplyCapCheck.run(&file, src)
    }

    #[test]
    fn flags_mint_without_cap_check() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "mint");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_when_le_guard_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let max: i128 = env.storage().persistent().get(&symbol_short!("max_supply")).unwrap();
        assert!(supply + amount <= max);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_lt_guard_present() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        let cap: i128 = 1_000_000;
        assert!(supply + amount < cap);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_mint_functions() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: i128) {
        let supply: i128 = env.storage().persistent().get(&symbol_short!("supply")).unwrap_or(0);
        env.storage().persistent().set(&symbol_short!("supply"), &(supply + amount));
    }
}
"#);
        assert!(hits.is_empty());
    }
}
