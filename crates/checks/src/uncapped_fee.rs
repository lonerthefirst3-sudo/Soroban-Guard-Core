//! Uncapped fee rate: a fee/rate/commission value read from storage is multiplied
//! against an amount without a preceding `<= 10000` or `<= 100` guard.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, Macro, Stmt};

const CHECK_NAME: &str = "uncapped-fee";

/// Fee-related identifier fragments (case-insensitive substring match).
const FEE_NAMES: &[&str] = &["fee", "rate", "commission"];

/// Cap thresholds that count as a valid guard (`<= 10000` or `<= 100`).
const CAP_VALUES: &[u64] = &[10_000, 100];

/// Flags `#[contractimpl]` functions that:
///   1. read a fee/rate/commission value from storage, AND
///   2. multiply it against another variable (`*`), AND
///   3. have no preceding `<= 10000` / `<= 100` guard on that variable.
pub struct UncappedFeeCheck;

impl Check for UncappedFeeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let stmts = &method.block.stmts;

            // Collect local variable names bound from a storage get whose key
            // string heuristically matches a fee/rate/commission name.
            let fee_vars = collect_fee_vars(stmts);
            if fee_vars.is_empty() {
                continue;
            }

            // For each fee var, check whether a cap guard precedes any `*` use.
            for fee_var in &fee_vars {
                let guarded = stmts.iter().any(|s| stmt_has_cap_guard(s, fee_var));

                if !guarded {
                    // Look for a multiplication involving this fee var.
                    let mut finder = MulFinder {
                        fee_var,
                        line: None,
                    };
                    for stmt in stmts {
                        finder.visit_stmt(stmt);
                    }
                    if let Some(line) = finder.line {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line,
                            function_name: fn_name.clone(),
                            description: format!(
                                "`{}` multiplies `{}` (read from storage) against an amount \
                                 without a preceding `<= 10000` or `<= 100` cap guard. A fee \
                                 rate exceeding 100% can drain the user's entire balance.",
                                fn_name, fee_var
                            ),
                        });
                        break; // one finding per function
                    }
                }
            }
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn is_fee_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    FEE_NAMES.iter().any(|f| lower.contains(f))
}

/// Walk a storage `.get(…)` call and return the key string if it looks like a
/// fee/rate/commission key, or the bound variable name if the local binding name matches.
fn collect_fee_vars(stmts: &[Stmt]) -> Vec<String> {
    let mut vars = Vec::new();
    for stmt in stmts {
        if let Stmt::Local(local) = stmt {
            // Unwrap Pat::Type (e.g. `let fee_bps: i128 = …`)
            let pat = match &local.pat {
                syn::Pat::Type(pt) => &*pt.pat,
                p => p,
            };
            // Binding name heuristic: `let fee_bps = …` or `let rate = …`
            if let syn::Pat::Ident(pi) = pat {
                let var_name = pi.ident.to_string();
                if is_fee_name(&var_name) {
                    vars.push(var_name.clone());
                    continue;
                }
            }
            // RHS heuristic: storage get with a key string matching fee/rate/commission
            if let Some(init) = &local.init {
                if let Some(var_name) = fee_var_from_storage_get(&init.expr) {
                    // Use the binding name if available, else the key-derived name.
                    let bind_name = if let syn::Pat::Ident(pi) = pat {
                        pi.ident.to_string()
                    } else {
                        var_name
                    };
                    if !vars.contains(&bind_name) {
                        vars.push(bind_name);
                    }
                }
            }
        }
    }
    vars
}

/// Returns `Some(key_name)` if `expr` is (or contains) a `storage().*.get(&KEY)`
/// where KEY's string representation matches a fee/rate/commission name.
fn fee_var_from_storage_get(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" && receiver_chain_contains(expr, "storage") {
                // Inspect the key argument for a fee-like name.
                if let Some(arg) = m.args.first() {
                    let key_str = expr_to_name_hint(arg);
                    if is_fee_name(&key_str) {
                        return Some(key_str);
                    }
                }
            }
            // Also check chained calls like `.unwrap_or(0)` wrapping a get.
            fee_var_from_storage_get(&m.receiver)
                .or_else(|| m.args.iter().find_map(fee_var_from_storage_get))
        }
        Expr::Try(t) => fee_var_from_storage_get(&t.expr),
        _ => None,
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
        _ => false,
    }
}

/// Best-effort: extract a name hint from a key expression (path ident, ref, or string lit).
fn expr_to_name_hint(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => expr_to_name_hint(&r.expr),
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string().to_lowercase())
            .unwrap_or_default(),
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => s.value().to_lowercase(),
        _ => String::new(),
    }
}

/// Returns true if the statement contains a `<= CAP_VALUE` comparison involving `var`.
fn stmt_has_cap_guard(stmt: &Stmt, var: &str) -> bool {
    let mut v = CapGuardFinder { var, found: false };
    v.visit_stmt(stmt);
    v.found
}

struct CapGuardFinder<'a> {
    var: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for CapGuardFinder<'_> {
    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Le(_)) {
            let lhs_is_var = expr_ident_matches(&i.left, self.var);
            let rhs_is_cap = expr_is_cap_literal(&i.right);
            if lhs_is_var && rhs_is_cap {
                self.found = true;
                return;
            }
        }
        syn::visit::visit_expr_binary(self, i);
    }
}

fn expr_ident_matches(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Path(p) => p.path.is_ident(name),
        _ => false,
    }
}

fn expr_is_cap_literal(expr: &Expr) -> bool {
    if let Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(n),
        ..
    }) = expr
    {
        if let Ok(v) = n.base10_parse::<u64>() {
            return CAP_VALUES.contains(&v);
        }
    }
    false
}

/// Finds the first `*` binary expression where one operand is `fee_var`.
struct MulFinder<'a> {
    fee_var: &'a str,
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for MulFinder<'_> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if self.line.is_none()
            && matches!(i.op, BinOp::Mul(_) | BinOp::MulAssign(_))
            && (expr_ident_matches(&i.left, self.fee_var)
                || expr_ident_matches(&i.right, self.fee_var))
        {
            self.line = Some(i.span().start().line);
            return;
        }
        syn::visit::visit_expr_binary(self, i);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    const VULNERABLE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const FEE_KEY: Symbol = symbol_short!("fee_bps");

#[contractimpl]
impl C {
    pub fn charge(env: Env, amount: i128) -> i128 {
        let fee_bps: i128 = env.storage().persistent().get(&FEE_KEY).unwrap_or(0);
        amount * fee_bps / 10000
    }
}
"#;

    const SAFE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const FEE_KEY: Symbol = symbol_short!("fee_bps");

#[contractimpl]
impl C {
    pub fn charge(env: Env, amount: i128) -> i128 {
        let fee_bps: i128 = env.storage().persistent().get(&FEE_KEY).unwrap_or(0);
        assert!(fee_bps <= 10000);
        amount * fee_bps / 10000
    }
}
"#;

    #[test]
    fn flags_uncapped_fee_mul() -> Result<(), syn::Error> {
        let file = parse_file(VULNERABLE)?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "expected one finding, got: {hits:?}");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_with_le_10000_guard() -> Result<(), syn::Error> {
        let file = parse_file(SAFE)?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert!(hits.is_empty(), "expected no findings, got: {hits:?}");
        Ok(())
    }

    #[test]
    fn passes_with_le_100_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const R: Symbol = symbol_short!("rate");
#[contractimpl]
impl C {
    pub fn charge(env: Env, amount: i128) -> i128 {
        let rate: i128 = env.storage().persistent().get(&R).unwrap_or(0);
        assert!(rate <= 100);
        amount * rate / 100
    }
}
"#,
        )?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn flags_commission_without_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const K: Symbol = symbol_short!("comm");
#[contractimpl]
impl C {
    pub fn apply(env: Env, amount: i128) -> i128 {
        let commission: i128 = env.storage().persistent().get(&K).unwrap_or(0);
        amount * commission
    }
}
"#,
        )?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn ignores_non_fee_mul() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const K: Symbol = symbol_short!("count");
#[contractimpl]
impl C {
    pub fn scale(env: Env, amount: i128) -> i128 {
        let count: i128 = env.storage().persistent().get(&K).unwrap_or(1);
        amount * count
    }
}
"#,
        )?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{symbol_short, Env, Symbol};
pub struct C;
const K: Symbol = symbol_short!("fee_bps");
impl C {
    pub fn charge(env: Env, amount: i128) -> i128 {
        let fee_bps: i128 = env.storage().persistent().get(&K).unwrap_or(0);
        amount * fee_bps / 10000
    }
}
"#,
        )?;
        let hits = UncappedFeeCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }
}
