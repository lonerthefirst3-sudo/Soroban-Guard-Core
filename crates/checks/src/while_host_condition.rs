//! Detects while loop conditions that depend on host function calls.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ExprWhile, File};

const CHECK_NAME: &str = "while-host-condition";

/// Flags `while` loop conditions containing method calls on `env` receiver chains
/// (storage, ledger, crypto).
pub struct WhileHostConditionCheck;

impl Check for WhileHostConditionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = WhileConditionVisitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct WhileConditionVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for WhileConditionVisitor<'a> {
    fn visit_expr_while(&mut self, i: &ExprWhile) {
        // Check if the condition contains a host call
        if has_host_call(&i.cond) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "While loop condition in `{}` depends on a host call (e.g., storage, ledger). \
                     This may loop unboundedly and exhaust the transaction budget. \
                     Cache the result before the loop or use a bounded counter.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_while(self, i);
    }
}

fn has_host_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            // Check if it's a method call on env or its chains
            if is_env_host_call(m) {
                return true;
            }
            // Recursively check receiver and arguments
            if has_host_call(&m.receiver) {
                return true;
            }
            for arg in &m.args {
                if has_host_call(arg) {
                    return true;
                }
            }
            false
        }
        Expr::Binary(b) => has_host_call(&b.left) || has_host_call(&b.right),
        Expr::Unary(u) => has_host_call(&u.expr),
        Expr::Paren(p) => has_host_call(&p.expr),
        _ => false,
    }
}

fn is_env_host_call(m: &ExprMethodCall) -> bool {
    // Check if this is a method call on env or its storage/ledger chains
    let method_name = m.method.to_string();

    // Host methods that are expensive
    let host_methods = [
        "get",
        "has",
        "set",
        "remove",
        "get_ledger_sequence",
        "get_timestamp",
        "get_network_id",
        "get_current_contract_address",
        "invoke",
        "invoke_contract",
    ];

    if !host_methods.contains(&method_name.as_str()) {
        return false;
    }

    // Check if receiver is env or env.storage() or similar
    is_env_receiver(&m.receiver)
}

fn is_env_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                ident == "env"
            } else {
                false
            }
        }
        Expr::MethodCall(m) => {
            // Check if it's env.storage(), env.ledger(), etc.
            let method_name = m.method.to_string();
            if [
                "storage",
                "ledger",
                "crypto",
                "instance",
                "temporary",
                "persistent",
            ]
            .contains(&method_name.as_str())
            {
                return is_env_receiver(&m.receiver);
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_while_with_storage_condition() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        while env.storage().instance().has(&"key") {
            let _ = 1;
            break;
        }
    }
}
"#,
        )?;
        let hits = WhileHostConditionCheck.run(&file, "");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_while_with_local_condition() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let mut i = 0;
        while i < 10 {
            let _ = i;
            i += 1;
        }
    }
}
"#,
        )?;
        let hits = WhileHostConditionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_while_with_cached_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let has_key = env.storage().instance().has(&"key");
        while has_key {
            let _ = 1;
            break;
        }
    }
}
"#,
        )?;
        let hits = WhileHostConditionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
