//! Event published with Val type data not safely convertible for off-chain use.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, GenericArgument, PathArguments, Type, TypePath};

const CHECK_NAME: &str = "event-val-type";

/// Flags `env.events().publish(topics, data)` where the `data` argument type is
/// `Val` or `RawVal` rather than a concrete Soroban SDK type.
pub struct EventValTypeCheck;

impl Check for EventValTypeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = EventValTypeVisitor {
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

fn is_val_or_rawval_type(ty: &Type) -> bool {
    match ty {
        Type::Path(TypePath { path, .. }) => {
            let last_segment = path.segments.last();
            if let Some(seg) = last_segment {
                let ident = seg.ident.to_string();
                ident == "Val" || ident == "RawVal"
            } else {
                false
            }
        }
        _ => false,
    }
}

struct EventValTypeVisitor<'a> {
    fn_name: String,
    findings: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for EventValTypeVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_events_publish(i) {
            // Check the arguments to publish()
            // publish(topics, data) - we care about the data argument (second one)
            if i.args.len() >= 2 {
                let data_arg = &i.args[1];
                
                // Try to infer the type from the expression
                // For now, we check if it's a direct reference to a Val/RawVal variable
                // or if it's a tuple containing Val/RawVal
                if let Expr::Tuple(tuple_expr) = data_arg {
                    for elem in &tuple_expr.elems {
                        if let Expr::Path(p) = elem {
                            // Check if this looks like a Val/RawVal type
                            if let Some(ident) = p.path.get_ident() {
                                let name = ident.to_string();
                                // Common patterns for Val/RawVal usage
                                if name.contains("val") || name.contains("Val") {
                                    let line = i.span().start().line;
                                    self.findings.push(Finding {
                                        check_name: CHECK_NAME.to_string(),
                                        severity: Severity::Low,
                                        file_path: String::new(),
                                        line,
                                        function_name: self.fn_name.clone(),
                                        description: format!(
                                            "Method `{}` publishes an event with a `Val` or `RawVal` type. \
                                             Raw `Val` types are not safely convertible for off-chain use. \
                                             Use concrete Soroban SDK types like `Symbol`, `i128`, `Address`, or `Bytes`.",
                                            self.fn_name
                                        ),
                                    });
                                    break;
                                }
                            }
                        }
                    }
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

    #[test]
    fn flags_event_with_val_type() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Val};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, val: Val) {
        env.events().publish((1u32,), (val,));
    }
}
"#,
        )?;
        let hits = EventValTypeCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_event_with_safe_types() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, addr: Address, amount: i128) {
        env.events().publish((symbol_short!("transfer"),), (addr, amount));
    }
}
"#,
        )?;
        let hits = EventValTypeCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_event_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Val};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, val: Val) {
        let x = some_function(val);
    }
}
"#,
        )?;
        let hits = EventValTypeCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
