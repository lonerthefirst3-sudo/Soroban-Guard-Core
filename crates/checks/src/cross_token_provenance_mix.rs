//! Arithmetic that mixes amounts denominated in two different tokens.
//!
//! A function handling two assets (e.g. `fn swap(env: Env, token_a: Address, token_b:
//! Address, amount_a: i128, amount_b: i128)`) combines `amount_a` and `amount_b` with
//! `+`/`-` almost never correctly, because the two values are denominated in different
//! tokens' units. This check has no real type system to lean on, so it traces which
//! `Address` parameter a numeric value's *name* suggests it is denominated in, and flags
//! arithmetic that combines two differently-denominated values.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File, FnArg, Local, Pat, Type};

const CHECK_NAME: &str = "cross-token-provenance-mix";

pub struct CrossTokenProvenanceMixCheck;

impl Check for CrossTokenProvenanceMixCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            let asset_params = address_asset_params(&method.sig.inputs);
            // Heuristic gate: this check only applies to functions that look like they
            // juggle two (or more) distinct token/asset handles. Fewer than two such
            // `Address` params and there is nothing to mix provenance across.
            if asset_params.len() < 2 {
                continue;
            }

            let initial_tags = initial_numeric_tags(&method.sig.inputs, &asset_params);

            let mut scanner = Scanner {
                var_tags: initial_tags,
                conversion_seen: false,
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            scanner.visit_block(&method.block);
        }
        out
    }
}

/// Names of `Address`-typed parameters that look like distinct token/asset handles.
///
/// Heuristic: an `Address` parameter counts as an "asset" handle only if its name
/// (lowercased) contains `token` or `asset` — e.g. `token_a`, `token_b`, `asset_in`.
/// This is deliberately narrow: it will miss swaps that name their token params
/// something else entirely (`from_currency`, `sell`, ...), but a looser heuristic
/// (any two `Address` params) produces far too many false positives, since most
/// contract methods take multiple unrelated addresses (caller, recipient, admin...).
fn address_asset_params(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> Vec<String> {
    let mut names = Vec::new();
    for arg in inputs {
        let FnArg::Typed(pt) = arg else { continue };
        if !type_is_address(&pt.ty) {
            continue;
        }
        if let Pat::Ident(pi) = &*pt.pat {
            let name = pi.ident.to_string();
            if name.to_ascii_lowercase().contains("token") || name.to_ascii_lowercase().contains("asset") {
                names.push(name);
            }
        }
    }
    names
}

fn type_is_address(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.is_ident("Address"))
}

fn type_is_numeric(ty: &Type) -> bool {
    matches!(
        ty,
        Type::Path(p) if ["i128", "u128", "i64", "u64", "i32", "u32"]
            .iter()
            .any(|n| p.path.is_ident(n))
    )
}

/// Seeds the tag map with each numeric parameter that can be paired with one of
/// `asset_params` by naming convention.
///
/// Heuristic (first pass, documented limitation): strip the trailing `_<suffix>` off
/// both the numeric parameter and each asset parameter (`amount_a` -> `a`, `token_a` ->
/// `a`) and match on that suffix. If no suffix matches, fall back to checking whether
/// the numeric parameter's name textually contains the full asset parameter name
/// (`token_a_amount` contains `token_a`). Parameters that match neither rule are left
/// untagged and are invisible to the rest of this check — this trades false negatives
/// (an unrecognized naming scheme) for not flagging unrelated numeric parameters.
fn initial_numeric_tags(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
    asset_params: &[String],
) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for arg in inputs {
        let FnArg::Typed(pt) = arg else { continue };
        if !type_is_numeric(&pt.ty) {
            continue;
        }
        let Pat::Ident(pi) = &*pt.pat else { continue };
        let numeric_name = pi.ident.to_string();
        if let Some(asset) = match_asset_for_numeric(&numeric_name, asset_params) {
            tags.insert(numeric_name, asset);
        }
    }
    tags
}

fn match_asset_for_numeric(numeric_name: &str, asset_params: &[String]) -> Option<String> {
    let numeric_suffix = numeric_name.rsplit('_').next().unwrap_or(numeric_name);
    for asset in asset_params {
        let asset_suffix = asset.rsplit('_').next().unwrap_or(asset.as_str());
        if !asset_suffix.is_empty() && numeric_suffix.eq_ignore_ascii_case(asset_suffix) {
            return Some(asset.clone());
        }
    }
    for asset in asset_params {
        if numeric_name.to_ascii_lowercase().contains(&asset.to_ascii_lowercase()) {
            return Some(asset.clone());
        }
    }
    None
}

/// A call whose name contains one of these substrings is treated as an explicit
/// exchange-rate conversion, and suppresses mismatched-tag findings that occur later
/// in the (source-order) traversal of the function body.
fn is_conversion_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("rate") || n.contains("price") || n.contains("convert") || n.contains("exchange")
}

fn is_mixable_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Add(_) | BinOp::Sub(_) | BinOp::AddAssign(_) | BinOp::SubAssign(_)
    )
}

/// Resolves the asset tag an expression's value carries, by def-use tracing through
/// `var_tags`. Returns `None` for untracked values (literals, untagged variables) and
/// for arithmetic that has already mixed two different tags (the mismatch itself is
/// reported by `Scanner::visit_expr_binary`; propagating a tag past it would either
/// silently pick a side or cause cascading duplicate findings).
fn classify_expr(expr: &Expr, tags: &HashMap<String, String>) -> Option<String> {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .and_then(|id| tags.get(&id.to_string()).cloned()),
        Expr::Paren(p) => classify_expr(&p.expr, tags),
        Expr::Group(g) => classify_expr(&g.expr, tags),
        Expr::Reference(r) => classify_expr(&r.expr, tags),
        Expr::Unary(u) => classify_expr(&u.expr, tags),
        Expr::Cast(c) => classify_expr(&c.expr, tags),
        Expr::Binary(b) if is_mixable_op(&b.op) => {
            let l = classify_expr(&b.left, tags);
            let r = classify_expr(&b.right, tags);
            match (l, r) {
                (Some(lt), Some(rt)) if lt == rt => Some(lt),
                (Some(lt), None) => Some(lt),
                (None, Some(rt)) => Some(rt),
                _ => None,
            }
        }
        _ => None,
    }
}

struct Scanner<'a> {
    var_tags: HashMap<String, String>,
    conversion_seen: bool,
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_local(&mut self, loc: &'ast Local) {
        if let Pat::Ident(pat_ident) = &loc.pat {
            if let Some(init) = &loc.init {
                match classify_expr(&init.expr, &self.var_tags) {
                    Some(tag) => {
                        self.var_tags.insert(pat_ident.ident.to_string(), tag);
                    }
                    None => {
                        self.var_tags.remove(&pat_ident.ident.to_string());
                    }
                }
            }
        }
        visit::visit_local(self, loc);
    }

    fn visit_expr(&mut self, e: &'ast Expr) {
        match e {
            Expr::Call(c) => {
                if let Expr::Path(p) = &*c.func {
                    if let Some(seg) = p.path.segments.last() {
                        if is_conversion_like(&seg.ident.to_string()) {
                            self.conversion_seen = true;
                        }
                    }
                }
            }
            Expr::MethodCall(m) => {
                if is_conversion_like(&m.method.to_string()) {
                    self.conversion_seen = true;
                }
            }
            _ => {}
        }
        visit::visit_expr(self, e);
    }

    fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
        if is_mixable_op(&b.op) && !self.conversion_seen {
            let lt = classify_expr(&b.left, &self.var_tags);
            let rt = classify_expr(&b.right, &self.var_tags);
            if let (Some(lt), Some(rt)) = (&lt, &rt) {
                if lt != rt {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: b.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "In `{}`, an arithmetic expression combines a value denominated in \
                             `{lt}` with one denominated in `{rt}` without an intervening \
                             conversion (no call with `rate`/`price`/`convert`/`exchange` in its \
                             name was seen first). Amounts from different tokens are not directly \
                             comparable or combinable — this can under- or over-account one side \
                             of a swap.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_binary(self, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Check, Severity};
    use syn::parse_file;

    fn run(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(CrossTokenProvenanceMixCheck.run(&file, src))
    }

    #[test]
    fn flags_direct_cross_token_addition() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, amount_b: i128) -> i128 {
        let total = amount_a + amount_b;
        total
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "swap");
        Ok(())
    }

    #[test]
    fn flags_after_rebinding_through_lets() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, amount_b: i128) -> i128 {
        let a = amount_a;
        let b = amount_b;
        let total = a + b;
        total
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_rate_conversion_applied_first() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

fn convert_rate(amount: i128) -> i128 {
    amount
}

#[contractimpl]
impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, amount_b: i128) -> i128 {
        let amount_b_in_a = convert_rate(amount_b);
        let total = amount_a + amount_b_in_a;
        total
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_arithmetic_within_the_same_asset() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, extra_a: i128) -> i128 {
        let total = amount_a + extra_a;
        total
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_single_asset_function() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, token_a: Address, amount_a: i128, amount_b: i128) -> i128 {
        amount_a + amount_b
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let hits = run(
            r#"
use soroban_sdk::{Address, Env};

pub struct Contract;

impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, amount_b: i128) -> i128 {
        amount_a + amount_b
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_multiplication() -> Result<(), syn::Error> {
        // Mul/Div across assets can be a legitimate rate computation (amount_a * price),
        // so only Add/Sub are treated as "combining" two denominations.
        let hits = run(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn swap(env: Env, token_a: Address, token_b: Address, amount_a: i128, amount_b: i128) -> i128 {
        amount_a * amount_b
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
