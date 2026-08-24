//! Balance multiplication without overflow check before storage write.
//!
//! `storage.get(key)` followed by `*` or `*=` (not `checked_mul`) and then
//! `storage.set(key, result)` can silently overflow on large balances.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "balance-mul-overflow";

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

fn is_storage_get(m: &ExprMethodCall) -> bool {
    m.method == "get" && receiver_chain_contains_storage(&m.receiver)
}

fn is_storage_set(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

/// Collect variable names bound from storage get calls.
fn collect_storage_get_bindings(block: &syn::Block) -> Vec<String> {
    let mut c = StorageGetBindingCollector { bindings: vec![] };
    c.visit_block(block);
    c.bindings
}

struct StorageGetBindingCollector {
    bindings: Vec<String>,
}

impl<'ast> Visit<'ast> for StorageGetBindingCollector {
    fn visit_local(&mut self, i: &'ast syn::Local) {
        if let Some(init) = &i.init {
            let mut f = StorageGetFinder { found: false };
            f.visit_expr(&init.expr);
            if f.found {
                if let syn::Pat::Ident(pi) = &i.pat {
                    self.bindings.push(pi.ident.to_string());
                }
            }
        }
        visit::visit_local(self, i);
    }
}

struct StorageGetFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for StorageGetFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_get(i) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Check if an expression references a storage-bound variable.
fn expr_uses_storage_binding(expr: &Expr, bindings: &[String]) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                return bindings.contains(&seg.ident.to_string());
            }
            false
        }
        Expr::MethodCall(m) => {
            // unwrap(), unwrap_or(), etc. on a storage binding
            expr_uses_storage_binding(&m.receiver, bindings)
        }
        Expr::Reference(r) => expr_uses_storage_binding(&r.expr, bindings),
        _ => false,
    }
}

struct MulOverflowVisitor<'a> {
    fn_name: String,
    storage_bindings: Vec<String>,
    has_storage_get: bool,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for MulOverflowVisitor<'ast> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        let is_mul = matches!(i.op, BinOp::Mul(_) | BinOp::MulAssign(_));
        if is_mul {
            let uses_storage = expr_uses_storage_binding(&i.left, &self.storage_bindings)
                || expr_uses_storage_binding(&i.right, &self.storage_bindings)
                || self.has_storage_get;
            if uses_storage {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` multiplies a value read from storage using `*` or `*=` \
                         without `checked_mul`. On large balances this silently overflows, \
                         producing incorrect results. Use `checked_mul` or `saturating_mul` instead.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_get(i) {
            self.has_storage_get = true;
        }
        // If it's a storage set, reset the flag (we only care about mul between get and set)
        if is_storage_set(i) {
            self.has_storage_get = false;
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct BalanceMulOverflowCheck;

impl Check for BalanceMulOverflowCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let storage_bindings = collect_storage_get_bindings(&method.block);
            let mut v = MulOverflowVisitor {
                fn_name,
                storage_bindings,
                has_storage_get: false,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_mul_on_storage_binding() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn apply_interest(env: Env, rate: i128) {
        let balance: i128 = env.storage().persistent().get(&symbol_short!("bal")).unwrap_or(0);
        let new_balance = balance * rate;
        env.storage().persistent().set(&symbol_short!("bal"), &new_balance);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BalanceMulOverflowCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_mul_assign_on_storage_binding() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn apply_fee(env: Env, rate: i128) {
        let mut balance: i128 = env.storage().persistent().get(&symbol_short!("bal")).unwrap_or(0);
        balance *= rate;
        env.storage().persistent().set(&symbol_short!("bal"), &balance);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BalanceMulOverflowCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn no_finding_for_checked_mul() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn apply_interest(env: Env, rate: i128) {
        let balance: i128 = env.storage().persistent().get(&symbol_short!("bal")).unwrap_or(0);
        let new_balance = balance.checked_mul(rate).expect("overflow");
        env.storage().persistent().set(&symbol_short!("bal"), &new_balance);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BalanceMulOverflowCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_mul_without_storage() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn compute(env: Env, a: i128, b: i128) -> i128 {
        a * b
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BalanceMulOverflowCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
