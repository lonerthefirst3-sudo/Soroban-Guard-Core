//! Detects env.events() called multiple times without caching.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "events-no-cache";

/// Flags functions where `env.events()` is called more than 3 times without caching.
pub struct EventsNoCacheCheck;

impl Check for EventsNoCacheCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = EventsCallCounter {
                fn_name: fn_name.clone(),
                calls: Vec::new(),
            };
            visitor.visit_block(&method.block);
            
            if visitor.calls.len() > 3 {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: visitor.calls[0].1,
                    function_name: fn_name,
                    description: format!(
                        "`env.events()` is called {} times in `{}`. \
                         Cache the result in a local variable to avoid redundant host calls.",
                        visitor.calls.len(),
                        visitor.fn_name
                    ),
                });
            }
        }
        out
    }
}

struct EventsCallCounter {
    fn_name: String,
    calls: Vec<(String, usize)>,
}

impl<'a> Visit<'a> for EventsCallCounter {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_events_call(i) {
            self.calls.push((i.method.to_string(), i.span().start().line));
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_events_call(m: &ExprMethodCall) -> bool {
    if m.method != "events" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_multiple_env_events_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.events().publish(("a",), ());
        env.events().publish(("b",), ());
        env.events().publish(("c",), ());
        env.events().publish(("d",), ());
    }
}
"#,
        )?;
        let hits = EventsNoCacheCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_three_or_fewer_env_events_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.events().publish(("a",), ());
        env.events().publish(("b",), ());
        env.events().publish(("c",), ());
    }
}
"#,
        )?;
        let hits = EventsNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_cached_env_events() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let events = env.events();
        events.publish(("a",), ());
        events.publish(("b",), ());
        events.publish(("c",), ());
        events.publish(("d",), ());
    }
}
"#,
        )?;
        let hits = EventsNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
