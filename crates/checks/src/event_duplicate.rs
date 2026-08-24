//! Flags duplicate event publishes in a single function.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "event-duplicate";

/// Flags `env.events().publish(topics, data)` when same (topics, data) appears multiple times.
pub struct EventDuplicateCheck;

impl Check for EventDuplicateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = EventCollector { events: Vec::new() };
            v.visit_block(&method.block);

            // Find duplicates
            let mut seen: HashMap<String, usize> = HashMap::new();
            for (line, event_sig) in v.events {
                if let Some(first_line) = seen.get(&event_sig) {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "Event with identical topics and data published multiple times \
                             (first at line {}). This spams the event log and may indicate a \
                             logic error.",
                            first_line
                        ),
                    });
                } else {
                    seen.insert(event_sig, line);
                }
            }
        }
        out
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
        _ => false,
    }
}

fn event_signature(m: &ExprMethodCall) -> String {
    // Create a simple signature from the arguments by converting to string representation
    if m.args.len() >= 2 {
        let topics = m.args[0].to_token_stream().to_string();
        let data = m.args[1].to_token_stream().to_string();
        format!("{}|{}", topics, data)
    } else {
        String::new()
    }
}

struct EventCollector {
    events: Vec<(usize, String)>,
}

impl<'a> Visit<'a> for EventCollector {
    fn visit_expr_method_call(&mut self, m: &'a ExprMethodCall) {
        if is_events_publish(m) {
            let sig = event_signature(m);
            if !sig.is_empty() {
                self.events.push((m.span().start().line, sig));
            }
        }
        visit::visit_expr_method_call(self, m);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(EventDuplicateCheck.run(&file, src))
    }

    #[test]
    fn flags_duplicate_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        let topic = Symbol::new(&env, "event");
        env.events().publish((topic,), &42);
        env.events().publish((topic,), &42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "test");
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn allows_different_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        let topic = Symbol::new(&env, "event");
        env.events().publish((topic,), &42);
        env.events().publish((topic,), &43);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}
