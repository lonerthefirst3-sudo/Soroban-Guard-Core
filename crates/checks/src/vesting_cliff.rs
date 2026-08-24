//! Detects vesting cliff compared against timestamp without adding start_time.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, Macro};

const CHECK_NAME: &str = "vesting-cliff";

const VESTING_FN_NAMES: &[&str] = &["claim", "vest", "release"];

/// Flags vesting functions that read `start_time` and `cliff` from storage but compare
/// `cliff` directly against `timestamp()` without adding `start_time` first.
pub struct VestingCliffCheck;

impl Check for VestingCliffCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !VESTING_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }
            let mut scan = VestingScan::default();
            scan.visit_block(&method.block);

            if scan.has_start_time_read
                && scan.has_cliff_read
                && scan.has_timestamp_comparison
                && !scan.has_start_time_add_in_comparison
            {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` compares `cliff` directly against \
                         `env.ledger().timestamp()` without adding `start_time`. \
                         The cliff check will be incorrect — either always passing or \
                         never passing."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct VestingScan {
    has_start_time_read: bool,
    has_cliff_read: bool,
    has_timestamp_comparison: bool,
    has_start_time_add_in_comparison: bool,
}

impl<'ast> Visit<'ast> for VestingScan {
    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Detect storage.get() calls with keys heuristically matching start/cliff
        if i.method == "get" || i.method == "get_unchecked" || i.method == "unwrap_or" {
            // Check if any argument contains "start" or "cliff"
            for arg in &i.args {
                let arg_str = expr_to_string(arg);
                if arg_str.contains("start") {
                    self.has_start_time_read = true;
                }
                if arg_str.contains("cliff") {
                    self.has_cliff_read = true;
                }
            }
        }
        // Detect env.ledger().timestamp()
        if i.method == "timestamp" {
            self.has_timestamp_comparison = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        // Detect cliff <= timestamp() or cliff < timestamp() comparisons
        match i.op {
            BinOp::Le(_) | BinOp::Lt(_) | BinOp::Ge(_) | BinOp::Gt(_) => {
                let left = expr_to_string(&i.left);
                let right = expr_to_string(&i.right);
                let combined = format!("{left} {right}");
                if combined.contains("cliff") && combined.contains("timestamp") {
                    // Check if start_time is added somewhere in the comparison
                    if combined.contains("start") {
                        self.has_start_time_add_in_comparison = true;
                    }
                }
                // Also check for addition expressions involving start_time + cliff
                if let BinOp::Add(_) = i.op {
                    if combined.contains("start") {
                        self.has_start_time_add_in_comparison = true;
                    }
                }
            }
            BinOp::Add(_) => {
                let combined = format!("{} {}", expr_to_string(&i.left), expr_to_string(&i.right));
                if combined.contains("start") && combined.contains("cliff") {
                    self.has_start_time_add_in_comparison = true;
                }
            }
            _ => {}
        }
        visit::visit_expr_binary(self, i);
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::MethodCall(m) => {
            format!("{}.{}()", expr_to_string(&m.receiver), m.method)
        }
        Expr::Binary(b) => format!("{} {}", expr_to_string(&b.left), expr_to_string(&b.right)),
        Expr::Reference(r) => expr_to_string(&r.expr),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::from("literal"),
        },
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_cliff_compared_without_start_time() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn claim(env: Env) {
        let start_time: u64 = env.storage().instance().get(&"start").unwrap();
        let cliff: u64 = env.storage().instance().get(&"cliff").unwrap();
        let now = env.ledger().timestamp();
        assert!(cliff <= now);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VestingCliffCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_cliff_with_start_time_added() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn claim(env: Env) {
        let start_time: u64 = env.storage().instance().get(&"start").unwrap();
        let cliff: u64 = env.storage().instance().get(&"cliff").unwrap();
        let now = env.ledger().timestamp();
        assert!(start_time + cliff <= now);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VestingCliffCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_fn_names() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env) {
        let start_time: u64 = env.storage().instance().get(&"start").unwrap();
        let cliff: u64 = env.storage().instance().get(&"cliff").unwrap();
        let now = env.ledger().timestamp();
        assert!(cliff <= now);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VestingCliffCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }
}
