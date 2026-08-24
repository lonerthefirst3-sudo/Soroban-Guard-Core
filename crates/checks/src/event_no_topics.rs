//! Flags `env.events().publish()` calls with empty topics array.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "event-no-topics";

/// Flags `env.events().publish(topics, data)` where topics is empty.
pub struct EventNoTopicsCheck;

impl Check for EventNoTopicsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = EventVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
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

fn is_empty_array(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(r) => {
            // Check if it's a reference to an empty array
            if let Expr::Array(arr) = &*r.expr {
                return arr.elems.is_empty();
            }
            false
        }
        Expr::Array(arr) => arr.elems.is_empty(),
        Expr::Call(call) => {
            // Check for Vec::new()
            if let Expr::Path(p) = &*call.func {
                if p.path.segments.len() == 2 {
                    let first = &p.path.segments[0].ident.to_string();
                    let second = &p.path.segments[1].ident.to_string();
                    if first == "Vec" && second == "new" && call.args.is_empty() {
                        return true;
                    }
                }
            }
            false
        }
        Expr::Macro(m) => {
            // Check for vec![]
            if m.mac.path.is_ident("vec") {
                // vec![] has empty tokens
                let tokens = m.mac.tokens.to_string();
                return tokens.trim().is_empty() || tokens.trim() == "!";
            }
            false
        }
        _ => false,
    }
}

struct EventVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for EventVisitor<'a> {
    fn visit_expr_method_call(&mut self, m: &'a ExprMethodCall) {
        if is_events_publish(m) && !m.args.is_empty() {
            let first_arg = &m.args[0];
            if is_empty_array(first_arg) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: m.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: "Event published with empty topics array. Events must have \
                                       at least one topic for off-chain indexers to categorize \
                                       and filter events."
                        .to_string(),
                });
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
        Ok(EventNoTopicsCheck.run(&file, src))
    }

    #[test]
    fn flags_empty_array_literal() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish(&[], &42);
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
    fn flags_vec_new() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish(Vec::new(), &42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn allows_non_empty_topics() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish((Symbol::new(&env, "topic"),), &42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}
