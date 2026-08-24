//! Event topics array contains duplicate values.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, ExprTuple, File, Lit};

const CHECK_NAME: &str = "event-topic-duplicates";

/// Flags `env.events().publish(topics, ...)` where the `topics` array/tuple
/// contains duplicate literal values.
pub struct EventTopicDuplicatesCheck;

impl Check for EventTopicDuplicatesCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = EventTopicVisitor {
                fn_name: fn_name.clone(),
                findings: &mut out,
            };
            visitor.visit_block(&method.block);
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
        Expr::Field(f) => receiver_chain_contains_events(&f.base),
        _ => false,
    }
}

fn extract_literal_value(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(el) => match &el.lit {
            Lit::Int(i) => Some(i.base10_digits().to_string()),
            Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        _ => None,
    }
}

struct EventTopicVisitor<'a> {
    fn_name: String,
    findings: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for EventTopicVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_events_publish(i) && !i.args.is_empty() {
            let topics_arg = &i.args[0];
            
            // Check if topics is a tuple
            if let Expr::Tuple(tuple) = topics_arg {
                let mut literals = Vec::new();
                for elem in &tuple.elems {
                    if let Some(val) = extract_literal_value(elem) {
                        literals.push((val, elem.span().start().line));
                    }
                }
                
                // Check for duplicates
                for j in 0..literals.len() {
                    for k in (j + 1)..literals.len() {
                        if literals[j].0 == literals[k].0 {
                            let line = i.span().start().line;
                            self.findings.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Low,
                                file_path: String::new(),
                                line,
                                function_name: self.fn_name.clone(),
                                description: format!(
                                    "Method `{}` publishes an event with duplicate topic values. \
                                     Each topic should carry unique information for indexing. \
                                     Remove duplicate values from the topics tuple.",
                                    self.fn_name
                                ),
                            });
                            return; // one finding per publish call
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_duplicate_topic_literals() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, amount: i128) {
        env.events().publish((1u32, 1u32), amount);
    }
}
"#,
        )?;
        let hits = EventTopicDuplicatesCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_unique_topic_literals() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, amount: i128) {
        env.events().publish((1u32, 2u32), amount);
    }
}
"#,
        )?;
        let hits = EventTopicDuplicatesCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_duplicate_string_topics() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, amount: i128) {
        env.events().publish(("transfer", "transfer"), amount);
    }
}
"#,
        )?;
        let hits = EventTopicDuplicatesCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_non_literal_topics() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, amount: i128) {
        let topic1 = symbol_short!("transfer");
        let topic2 = symbol_short!("transfer");
        env.events().publish((topic1, topic2), amount);
    }
}
"#,
        )?;
        let hits = EventTopicDuplicatesCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_event_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let tuple = (1u32, 1u32);
        some_function(tuple);
    }
}
"#,
        )?;
        let hits = EventTopicDuplicatesCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
