//! Flags `env.events().publish(topics, data)` calls where a topic element is
//! derived from a function parameter rather than a constant or `symbol_short!`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat};

const CHECK_NAME: &str = "event-topic-user-input";

/// Flags `env.events().publish(topics, data)` calls where any element of the
/// topics tuple traces back to a function parameter rather than a literal or
/// `symbol_short!` macro.
pub struct EventTopicUserInputCheck;

impl Check for EventTopicUserInputCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Collect parameter names (skip `env` / `self`).
            let params: HashSet<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pt) = arg {
                        if let Pat::Ident(pi) = pt.pat.as_ref() {
                            let name = pi.ident.to_string();
                            if name != "env" {
                                return Some(name);
                            }
                        }
                    }
                    None
                })
                .collect();

            let fn_name = method.sig.ident.to_string();
            let mut v = TopicVisitor {
                fn_name,
                params: &params,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

fn is_publish_call(m: &ExprMethodCall) -> bool {
    m.method == "publish" && receiver_chain_contains_events(&m.receiver)
}

/// Returns `true` when `expr` is a safe, constant topic value:
/// - `symbol_short!(...)` macro invocation
/// - A multi-segment path (qualified constant / enum variant, e.g. `Foo::BAR`)
/// - A function/associated-function call (e.g. `Symbol::new(…)`)
///
/// Single-ident paths are NOT considered safe here; `expr_uses_param` decides
/// whether they are parameters (flagged) or unrecognised constants (ignored).
fn is_safe_topic(expr: &Expr) -> bool {
    match expr {
        Expr::Macro(m) => m
            .mac
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "symbol_short"),
        Expr::Path(p) => p.path.segments.len() > 1,
        Expr::Call(_) => true,
        Expr::Reference(r) => is_safe_topic(&r.expr),
        _ => false,
    }
}

/// Returns `true` when `expr` directly references one of the tracked parameter
/// names (shallow check — sufficient for the common pattern).
fn expr_uses_param(expr: &Expr, params: &HashSet<String>) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|id| params.contains(&id.to_string())),
        Expr::Reference(r) => expr_uses_param(&r.expr, params),
        Expr::MethodCall(m) => expr_uses_param(&m.receiver, params),
        Expr::Field(f) => expr_uses_param(&f.base, params),
        _ => false,
    }
}

/// Returns `true` when the topics expression contains at least one element that
/// is not a safe constant and traces back to a function parameter.
fn topics_contain_user_input(topics: &Expr, params: &HashSet<String>) -> bool {
    match topics {
        Expr::Tuple(t) => t
            .elems
            .iter()
            .any(|e| !is_safe_topic(e) && expr_uses_param(e, params)),
        other => !is_safe_topic(other) && expr_uses_param(other, params),
    }
}

// ── visitor ──────────────────────────────────────────────────────────────────

struct TopicVisitor<'a> {
    fn_name: String,
    params: &'a HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for TopicVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_publish_call(i)
            && !i.args.is_empty()
            && topics_contain_user_input(&i.args[0], self.params)
        {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: "events.publish() called with a user-supplied function \
                    parameter as a topic. Topics should be fixed Symbol constants or \
                    symbol_short! literals, not dynamic user input. This can leak \
                    sensitive data, bloat the event stream, and enable event-log spam."
                    .to_string(),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse error");
        EventTopicUserInputCheck.run(&file, src)
    }

    #[test]
    fn flags_param_as_sole_topic() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn emit(env: Env, topic: Symbol) {
        env.events().publish((topic,), 42u32);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].function_name, "emit");
    }

    #[test]
    fn flags_param_in_multi_element_tuple() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn emit(env: Env, user_topic: Symbol) {
        env.events().publish((symbol_short!("evt"), user_topic), 1u32);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_symbol_short_topic() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn emit(env: Env) {
        env.events().publish((symbol_short!("evt"),), 42u32);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_const_path_topic() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
const TOPIC: Symbol = symbol_short!("t");
#[contractimpl]
impl C {
    pub fn emit(env: Env) {
        env.events().publish((TOPIC,), 42u32);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_symbol_new_topic() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn emit(env: Env) {
        env.events().publish((Symbol::new(&env, "topic"),), 42u32);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env, Symbol};
pub struct C;
impl C {
    pub fn emit(env: Env, topic: Symbol) {
        env.events().publish((topic,), 42u32);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
