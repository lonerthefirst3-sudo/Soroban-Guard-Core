//! Detects cross-contract call results stored without emitting events.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Local, Pat};

const CHECK_NAME: &str = "invoke-store-no-event";

/// Flags functions where `invoke_contract()` result is stored without emitting events.
pub struct InvokeStoreNoEventCheck;

impl Check for InvokeStoreNoEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = FuncBodyScan::default();
            scan.visit_block(&method.block);

            if scan.invoke_stored && !scan.events_publish {
                let line = scan
                    .invoke_line
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` stores the result of `invoke_contract()` \
                         without emitting an event. Off-chain monitors cannot track this \
                         state change without events.",
                        fn_name = fn_name
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct FuncBodyScan {
    invoke_stored: bool,
    events_publish: bool,
    invoke_line: Option<usize>,
    invoke_bindings: Vec<String>,
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_local(&mut self, i: &'ast Local) {
        if let Some(init) = &i.init {
            if let Expr::MethodCall(m) = &*init.expr {
                if is_invoke_contract_call(m) {
                    let pat = match &i.pat {
                        Pat::Type(pt) => &*pt.pat,
                        p => p,
                    };
                    if let Pat::Ident(pi) = pat {
                        let name = pi.ident.to_string();
                        if name != "_" {
                            self.invoke_bindings.push(name);
                            if self.invoke_line.is_none() {
                                self.invoke_line = Some(m.method.span().start().line);
                            }
                        }
                    }
                }
            }
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) {
            // Check if any arg uses an invoke binding.
            for arg in &i.args {
                if let Some(name) = expr_ident(arg) {
                    if self.invoke_bindings.contains(&name) {
                        self.invoke_stored = true;
                        if self.invoke_line.is_none() {
                            self.invoke_line = Some(i.span().start().line);
                        }
                    }
                }
            }
        }
        if is_events_publish(i) {
            self.events_publish = true;
        }
        visit::visit_expr_method_call(self, i);
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
        _ => false,
    }
}

fn expr_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        Expr::Reference(r) => expr_ident(&r.expr),
        _ => None,
    }
}

fn is_invoke_contract_call(m: &ExprMethodCall) -> bool {
    m.method == "invoke_contract"
}

fn is_events_publish(m: &ExprMethodCall) -> bool {
    if m.method != "publish" {
        return false;
    }
    receiver_chain_contains_events(&m.receiver)
}

fn receiver_chain_contains_events(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_chain_contains_events(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_events(&f.base),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_invoke_stored_without_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_other(env: Env, addr: Address) {
        let result = env.invoke_contract(&addr, &"method", &());
        env.storage().persistent().set(&"result", &result);
    }
}
"#,
        )?;
        let hits = InvokeStoreNoEventCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_invoke_stored_with_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_other(env: Env, addr: Address) {
        let result = env.invoke_contract(&addr, &"method", &());
        env.storage().persistent().set(&"result", &result);
        env.events().publish(("invoke_result",), (&result,));
    }
}
"#,
        )?;
        let hits = InvokeStoreNoEventCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_invoke_without_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct C;

#[contractimpl]
impl C {
    pub fn call_other(env: Env, addr: Address) {
        let result = env.invoke_contract(&addr, &"method", &());
        let _ = result;
    }
}
"#,
        )?;
        let hits = InvokeStoreNoEventCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
