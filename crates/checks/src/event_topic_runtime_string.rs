//! Flags event topics using runtime strings instead of symbol_short!.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "event-topic-runtime-string";

/// Flags `env.events().publish(topics, ...)` where topics contain `Symbol::from_str`.
pub struct EventTopicRuntimeStringCheck;

impl Check for EventTopicRuntimeStringCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = EventTopicVisitor {
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

fn is_symbol_from_str(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(p) = &*call.func {
                if p.path.segments.len() == 2 {
                    let first = &p.path.segments[0].ident.to_string();
                    let second = &p.path.segments[1].ident.to_string();
                    if first == "Symbol" && second == "from_str" {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn check_topics_for_runtime_strings(expr: &Expr) -> bool {
    match expr {
        Expr::Tuple(t) => {
            for elem in &t.elems {
                if is_symbol_from_str(elem) {
                    return true;
                }
            }
            false
        }
        Expr::Array(a) => {
            for elem in &a.elems {
                if is_symbol_from_str(elem) {
                    return true;
                }
            }
            false
        }
        _ => is_symbol_from_str(expr),
    }
}

struct EventTopicVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for EventTopicVisitor<'a> {
    fn visit_expr_method_call(&mut self, m: &'a ExprMethodCall) {
        if is_events_publish(m) && !m.args.is_empty() {
            let first_arg = &m.args[0];
            if check_topics_for_runtime_strings(first_arg) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: m.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: "Event topic uses `Symbol::from_str()` with a runtime string. \
                                       Use `symbol_short!()` macro for compile-time symbols to \
                                       ensure predictable event signatures for off-chain indexers."
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
        Ok(EventTopicRuntimeStringCheck.run(&file, src))
    }

    #[test]
    fn flags_symbol_from_str() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish((Symbol::from_str(&env, "topic"),), &42);
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
    fn allows_symbol_short() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, symbol_short};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish((symbol_short!("topic"),), &42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}
