//! Detects a storage key written and read through different fixed-point scale factors.
//!
//! Token contracts frequently store an amount under one scale (e.g. multiplying by
//! `10_000_000` for 7-decimal stroops) and later read it back assuming a different
//! scale (e.g. dividing by `1_000_000` for 6 decimals). Each call site is internally
//! consistent; the bug only exists as a disagreement between independent call sites
//! for what is meant to be the same logical value. This check correlates the integer
//! scale literal used at every storage `set()`/`get()` call site, grouped by the
//! (textual) storage key, and flags any key associated with more than one distinct
//! literal.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprMethodCall, File, Lit, Local, Pat, Stmt};

const CHECK_NAME: &str = "scale-factor-drift";

/// Flags a storage key that is scaled by different integer literals at different
/// `set()`/`get()` call sites within the same file.
pub struct ScaleFactorDriftCheck;

impl Check for ScaleFactorDriftCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut sites: Vec<Site> = Vec::new();
        for method in contractimpl_functions(file) {
            let mut scanner = FnScanner {
                fn_name: method.sig.ident.to_string(),
                var_key: HashMap::new(),
                var_scale: HashMap::new(),
                sites: Vec::new(),
            };
            scanner.scan_block(&method.block);
            sites.extend(scanner.sites);
        }

        let mut by_key: HashMap<String, Vec<&Site>> = HashMap::new();
        for site in &sites {
            by_key.entry(site.key.clone()).or_default().push(site);
        }

        let mut out = Vec::new();
        for (key, key_sites) in by_key {
            let mut literals: Vec<&str> = key_sites.iter().map(|s| s.literal.as_str()).collect();
            literals.sort();
            literals.dedup();
            if literals.len() < 2 {
                continue;
            }

            // One finding per distinct literal, anchored at its first call site,
            // so every disagreeing site is individually visible in the report.
            let mut seen_literals: Vec<&str> = Vec::new();
            for site in &key_sites {
                if seen_literals.contains(&site.literal.as_str()) {
                    continue;
                }
                seen_literals.push(&site.literal);

                let other_sites: Vec<&&Site> = key_sites
                    .iter()
                    .filter(|s| s.literal != site.literal)
                    .collect();
                let other_summary = other_sites
                    .iter()
                    .map(|s| {
                        format!(
                            "{}() in `{}` at line {} scales by {}",
                            s.kind.as_str(),
                            s.fn_name,
                            s.line,
                            s.literal
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");

                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: site.line,
                    function_name: site.fn_name.clone(),
                    description: format!(
                        "Storage key `{key}` is scaled by {} at {}() in `{}` (line {}), but {}. \
                         Every call site touching the same logical key must agree on the \
                         fixed-point scale factor, or values silently gain or lose decimal places.",
                        site.literal,
                        site.kind.as_str(),
                        site.fn_name,
                        site.line,
                        other_summary
                    ),
                });
            }
        }
        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Write,
    Read,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Write => "set",
            Kind::Read => "get",
        }
    }
}

struct Site {
    key: String,
    literal: String,
    line: usize,
    fn_name: String,
    kind: Kind,
}

/// Per-function scan tracking a minimal, flow-insensitive def-use map so a scale
/// factor applied via an intermediate `let` binding is still attributed to the
/// storage key it originated from (or will be written to).
struct FnScanner {
    fn_name: String,
    /// variable name -> storage key, for `let v = ...storage...get(key)...;` (unscaled).
    var_key: HashMap<String, String>,
    /// variable name -> scale literal, for `let v = expr (*|/) LIT;`.
    var_scale: HashMap<String, String>,
    sites: Vec<Site>,
}

impl FnScanner {
    fn scan_block(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.scan_stmt(stmt);
        }
    }

    fn scan_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Local(local) => self.scan_local(local),
            Stmt::Expr(expr, _) => self.scan_top_expr(expr),
            _ => {}
        }
    }

    fn scan_local(&mut self, local: &Local) {
        let Some(init) = &local.init else { return };
        let ident = pat_ident(&local.pat);

        if let Some((literal, inner)) = as_scaled_binary(&init.expr) {
            if let Some(key) = key_of_get_expr(inner) {
                self.sites.push(Site {
                    key,
                    literal: literal.clone(),
                    line: expr_line(&init.expr),
                    fn_name: self.fn_name.clone(),
                    kind: Kind::Read,
                });
            } else if let Some(varname) = path_ident(inner) {
                if let Some(key) = self.var_key.get(&varname).cloned() {
                    self.sites.push(Site {
                        key,
                        literal: literal.clone(),
                        line: expr_line(&init.expr),
                        fn_name: self.fn_name.clone(),
                        kind: Kind::Read,
                    });
                }
            }
            if let Some(id) = ident {
                self.var_scale.insert(id, literal);
            }
        } else if let Some(key) = key_of_get_expr(&init.expr) {
            if let Some(id) = ident {
                self.var_key.insert(id, key);
            }
        }

        // A set() call could also appear inside the init expression itself
        // (e.g. behind a helper call's argument list); walk it too.
        self.scan_for_set_calls(&init.expr);
        self.recurse_into_nested(&init.expr);
    }

    fn scan_top_expr(&mut self, expr: &Expr) {
        if let Some((literal, inner)) = as_scaled_binary(expr) {
            if let Some(key) = key_of_get_expr(inner) {
                self.sites.push(Site {
                    key,
                    literal,
                    line: expr_line(expr),
                    fn_name: self.fn_name.clone(),
                    kind: Kind::Read,
                });
            } else if let Some(varname) = path_ident(inner) {
                if let Some(key) = self.var_key.get(&varname).cloned() {
                    self.sites.push(Site {
                        key,
                        literal,
                        line: expr_line(expr),
                        fn_name: self.fn_name.clone(),
                        kind: Kind::Read,
                    });
                }
            }
        }
        self.scan_for_set_calls(expr);
        self.recurse_into_nested(expr);
    }

    /// Finds `.set(key, value)` calls anywhere in `expr` and resolves the value's
    /// scale factor, either directly or through a previously-seen `var_scale` binding.
    fn scan_for_set_calls(&mut self, expr: &Expr) {
        let mut visitor = SetCallVisitor { scanner: self };
        visitor.visit_expr(expr);
    }

    /// Descends into nested block-bearing expressions (`if`, loops, blocks) so
    /// bindings and call sites inside them are still picked up in statement order.
    fn recurse_into_nested(&mut self, expr: &Expr) {
        match expr {
            Expr::If(e) => {
                self.scan_block(&e.then_branch);
                if let Some((_, else_expr)) = &e.else_branch {
                    match else_expr.as_ref() {
                        Expr::Block(b) => self.scan_block(&b.block),
                        other => self.recurse_into_nested(other),
                    }
                }
            }
            Expr::Block(e) => self.scan_block(&e.block),
            Expr::Loop(e) => self.scan_block(&e.body),
            Expr::While(e) => self.scan_block(&e.body),
            Expr::ForLoop(e) => self.scan_block(&e.body),
            _ => {}
        }
    }
}

struct SetCallVisitor<'a> {
    scanner: &'a mut FnScanner,
}

impl<'ast> Visit<'ast> for SetCallVisitor<'_> {
    fn visit_expr_method_call(&mut self, mc: &'ast ExprMethodCall) {
        if mc.method == "set" && receiver_chain_contains_storage(&mc.receiver) {
            if let Some(key_arg) = mc.args.first() {
                if let Some(val_arg) = mc.args.get(1) {
                    let key = expr_to_string(key_arg);
                    let val = strip_ref(val_arg);
                    if let Some((literal, _inner)) = as_scaled_binary(val) {
                        self.scanner.sites.push(Site {
                            key,
                            literal,
                            line: expr_line(val_arg),
                            fn_name: self.scanner.fn_name.clone(),
                            kind: Kind::Write,
                        });
                    } else if let Some(varname) = path_ident(val) {
                        if let Some(literal) = self.scanner.var_scale.get(&varname).cloned() {
                            self.scanner.sites.push(Site {
                                key,
                                literal,
                                line: expr_line(val_arg),
                                fn_name: self.scanner.fn_name.clone(),
                                kind: Kind::Write,
                            });
                        }
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, mc);
    }
}

fn expr_line(expr: &Expr) -> usize {
    expr.span().start().line
}

fn expr_to_string(expr: &Expr) -> String {
    expr.to_token_stream().to_string()
}

fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(p) => Some(p.ident.to_string()),
        Pat::Type(p) => pat_ident(&p.pat),
        _ => None,
    }
}

fn path_ident(expr: &Expr) -> Option<String> {
    match strip_ref(expr) {
        Expr::Path(p) if p.path.segments.len() == 1 => Some(p.path.segments[0].ident.to_string()),
        _ => None,
    }
}

fn strip_ref(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(r) => strip_ref(&r.expr),
        Expr::Paren(p) => strip_ref(&p.expr),
        Expr::Group(g) => strip_ref(&g.expr),
        _ => expr,
    }
}

/// If `expr` (after stripping `&`/parens) is a `*` or `/` of an integer literal
/// against some other expression, returns `(literal_digits, other_operand)`.
fn as_scaled_binary(expr: &Expr) -> Option<(String, &Expr)> {
    let Expr::Binary(bin) = strip_ref(expr) else {
        return None;
    };
    if !matches!(bin.op, BinOp::Mul(_) | BinOp::Div(_)) {
        return None;
    }
    match (int_literal(&bin.left), int_literal(&bin.right)) {
        (Some(lit), None) => Some((lit, bin.right.as_ref())),
        (None, Some(lit)) => Some((lit, bin.left.as_ref())),
        _ => None,
    }
}

fn int_literal(expr: &Expr) -> Option<String> {
    match strip_ref(expr) {
        Expr::Lit(l) => match &l.lit {
            Lit::Int(i) => Some(i.base10_digits().to_string()),
            _ => None,
        },
        _ => None,
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

/// Peels known "unwrap"-shaped method calls off a `.get(...)` chain and, if the
/// receiver chain is rooted in storage, returns the storage key argument.
fn key_of_get_expr(expr: &Expr) -> Option<String> {
    let mc = peel_get_call(expr)?;
    mc.args.first().map(expr_to_string)
}

fn peel_get_call(expr: &Expr) -> Option<&ExprMethodCall> {
    match strip_ref(expr) {
        Expr::MethodCall(mc) => {
            if mc.method == "get" && receiver_chain_contains_storage(&mc.receiver) {
                Some(mc)
            } else if matches!(
                mc.method.to_string().as_str(),
                "unwrap" | "unwrap_or" | "unwrap_or_default" | "unwrap_or_else" | "expect"
            ) {
                peel_get_call(&mc.receiver)
            } else {
                None
            }
        }
        Expr::Try(t) => peel_get_call(&t.expr),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(ScaleFactorDriftCheck.run(&file, src))
    }

    #[test]
    fn flags_scale_drift_across_deposit_and_withdraw() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = (symbol_short!("bal"), user);
        let scaled = amount * 10_000_000;
        env.storage().persistent().set(&key, &scaled);
    }

    pub fn withdraw(env: Env, user: Address) -> i128 {
        let key = (symbol_short!("bal"), user);
        let raw: i128 = env.storage().persistent().get(&key).unwrap();
        raw / 1_000_000
    }
}
"#)?;
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h.check_name == CHECK_NAME));
        assert!(hits.iter().all(|h| h.severity == Severity::High));
        assert!(hits.iter().any(|h| h.function_name == "deposit"));
        assert!(hits.iter().any(|h| h.function_name == "withdraw"));
        Ok(())
    }

    #[test]
    fn passes_when_scale_factor_is_consistent() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = (symbol_short!("bal"), user);
        let scaled = amount * 10_000_000;
        env.storage().persistent().set(&key, &scaled);
    }

    pub fn withdraw(env: Env, user: Address) -> i128 {
        let key = (symbol_short!("bal"), user);
        let raw: i128 = env.storage().persistent().get(&key).unwrap();
        raw / 10_000_000
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_for_unrelated_keys() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        let key_a = symbol_short!("bal_a");
        let scaled = amount * 10_000_000;
        env.storage().persistent().set(&key_a, &scaled);
    }

    pub fn withdraw(env: Env, user: Address) -> i128 {
        let key_b = symbol_short!("bal_b");
        let raw: i128 = env.storage().persistent().get(&key_b).unwrap();
        raw / 1_000_000
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_scaling_arithmetic() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn deposit(env: Env, user: Address, amount: i128, fee: i128) {
        let key = symbol_short!("bal");
        let total = amount - fee;
        env.storage().persistent().set(&key, &total);
    }

    pub fn withdraw(env: Env, user: Address) -> i128 {
        let key = symbol_short!("bal");
        env.storage().persistent().get(&key).unwrap()
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }
}
