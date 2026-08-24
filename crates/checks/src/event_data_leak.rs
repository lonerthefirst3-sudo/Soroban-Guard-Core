//! Flags `env.events().publish(topics, data)` calls with oversized plaintext string data.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "event-data-leak";
const MAX_DATA_LEN: usize = 32;

/// Flags `env.events().publish(topics, data)` calls where the second argument
/// is a string literal with length > 32 characters.
pub struct EventDataLeakCheck;

impl Check for EventDataLeakCheck {
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

struct EventVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for EventVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_publish_call(i) && i.args.len() >= 2 {
            if let Expr::Lit(syn::ExprLit {
                lit: Lit::Str(lit_str),
                ..
            }) = &i.args[1]
            {
                let data_len = lit_str.value().len();
                if data_len > MAX_DATA_LEN {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "events.publish() called with oversized plaintext string data \
                             ({} chars > {} char limit). This data is permanently visible \
                             on-chain and may leak sensitive information.",
                            data_len, MAX_DATA_LEN
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(EventDataLeakCheck.run(&file, src))
    }

    #[test]
    fn flags_publish_with_oversized_string() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit_event(env: Env) {
        env.events().publish(
            (Symbol::new(&env, "topic"),),
            "this is a very long string that exceeds the limit"
        );
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "emit_event");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_with_short_string() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit_event(env: Env) {
        env.events().publish(
            (Symbol::new(&env, "topic"),),
            "short"
        );
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_exactly_32_chars() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit_event(env: Env) {
        env.events().publish(
            (Symbol::new(&env, "topic"),),
            "12345678901234567890123456789012"
        );
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_string_data() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn emit_event(env: Env, data: String) {
        env.events().publish(
            (Symbol::new(&env, "topic"),),
            data
        );
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{Env, Symbol};

pub struct Contract;

impl Contract {
    pub fn helper(env: Env) {
        env.events().publish(
            (Symbol::new(&env, "topic"),),
            "this is a very long string that exceeds the limit"
        );
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
