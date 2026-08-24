//! Detects `update_current_contract_wasm()` without event or hash verification.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "upgrade-no-event";

/// Flags `update_current_contract_wasm(...)` calls where:
/// 1. No event is emitted in the same function body, AND
/// 2. The wasm_hash argument is not compared against a stored trusted hash before the call.
pub struct UpgradeNoEventCheck;

impl Check for UpgradeNoEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Walk statements in order; track event and hash verification
            let mut upgrade_line: Option<usize> = None;
            let mut has_event = false;
            let mut has_hash_check = false;

            for stmt in &method.block.stmts {
                // Check current statement for events
                let mut event_check = EventChecker { found: false };
                event_check.visit_stmt(stmt);
                if event_check.found {
                    has_event = true;
                }

                // Check for upgrade call and hash verification
                let mut upgrade_check = UpgradeChecker {
                    upgrade_line: None,
                    has_verification: false,
                };
                upgrade_check.visit_stmt(stmt);

                if upgrade_check.upgrade_line.is_some() && !has_hash_check && upgrade_line.is_none()
                {
                    upgrade_line = upgrade_check.upgrade_line;
                }
                if upgrade_check.has_verification && upgrade_line.is_none() {
                    has_hash_check = true;
                }
            }

            if let Some(line) = upgrade_line {
                if !has_event {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Function `{}` calls `update_current_contract_wasm()` without \
                             emitting an event. Critical operations like WASM upgrades must be \
                             logged for transparency and verification. Add \
                             `env.events().publish(...)` to make the upgrade visible.",
                            fn_name
                        ),
                    });
                }
            }
        }
        out
    }
}

struct EventChecker {
    found: bool,
}

impl Visit<'_> for EventChecker {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "publish" && receiver_contains_events(&i.receiver) {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

struct UpgradeChecker {
    upgrade_line: Option<usize>,
    has_verification: bool,
}

impl Visit<'_> for UpgradeChecker {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "update_current_contract_wasm" {
            self.upgrade_line = Some(i.span().start().line);
        }
        // Check for comparison operations on storage reads
        // This is a simple heuristic: if there's a binary operation in the stmt,
        // we assume there's hash verification
        syn::visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &syn::ExprBinary) {
        // Mark as having verification if we see a binary comparison (==, !=, etc.)
        self.has_verification = true;
        syn::visit::visit_expr_binary(self, i);
    }
}

fn receiver_contains_events(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_contains_events(&m.receiver)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        UpgradeNoEventCheck.run(&file, src)
    }

    #[test]
    fn flags_upgrade_without_event() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_wasm: Bytes) {
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn ignores_upgrade_with_event() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Bytes, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_wasm: Bytes) {
        env.deployer().update_current_contract_wasm(new_wasm);
        env.events().publish((Symbol::new(&env, "upgraded"),), &new_wasm);
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }
}
