//! Detects events publishing full storage values instead of meaningful deltas.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "event-full-state";

/// Flags `events().publish()` where data is a direct storage `get` result.
pub struct EventFullStateCheck;

impl Check for EventFullStateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = EventPublishVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct EventPublishVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for EventPublishVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_events_publish(i) {
            if let Some(data_arg) = i.args.first() {
                if is_storage_get_result(data_arg) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Event data in `{}` contains a full storage value from `get()`. \
                             Publish only meaningful deltas to reduce data leakage and storage costs.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
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

fn is_storage_get_result(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" {
                return receiver_chain_contains_storage(&m.receiver);
            }
            false
        }
        _ => false,
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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_event_with_full_storage_value() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let val = env.storage().persistent().get(&"key").unwrap_or(0);
        env.events().publish(("state",), (val,));
    }
}
"#,
        )?;
        let hits = EventFullStateCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_event_with_computed_delta() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let old_val = env.storage().persistent().get(&"key").unwrap_or(0);
        let new_val = old_val + 10;
        env.storage().persistent().set(&"key", &new_val);
        env.events().publish(("delta",), (10,));
    }
}
"#,
        )?;
        let hits = EventFullStateCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_event_with_literal_data() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.events().publish(("event",), (42,));
    }
}
"#,
        )?;
        let hits = EventFullStateCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
