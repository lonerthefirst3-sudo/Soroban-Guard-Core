//! Detects unbounded batch operations over Vec parameters (compute DoS).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprMethodCall, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "unbounded-batch";

/// Flags `for` loops iterating over a `Vec`-typed parameter that call
/// `invoke_contract`, `transfer`, `mint`, or `burn` inside the loop body
/// without a preceding `.len()` upper-bound guard in the source text.
pub struct UnboundedBatchCheck;

impl Check for UnboundedBatchCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let vec_params = collect_vec_params(method);
            if vec_params.is_empty() {
                continue;
            }
            // Use the source text to detect a .len() guard anywhere in the function.
            // We extract the function's source span lines as a heuristic.
            let fn_start = method.sig.fn_token.span().start().line;
            let fn_end = method.block.brace_token.span.close().start().line;
            let has_len_guard = source_has_len_guard(source, fn_start, fn_end);

            let mut visitor = BatchLoopVisitor {
                fn_name: fn_name.clone(),
                vec_params: &vec_params,
                has_len_guard,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

fn source_has_len_guard(source: &str, start_line: usize, end_line: usize) -> bool {
    for (idx, line) in source.lines().enumerate() {
        let lineno = idx + 1;
        if lineno >= start_line && lineno <= end_line && line.contains(".len()") {
            return true;
        }
    }
    false
}

fn collect_vec_params(method: &syn::ImplItemFn) -> HashSet<String> {
    let mut names = HashSet::new();
    for arg in &method.sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        if !is_vec_type(&pat_type.ty) {
            continue;
        }
        if let Pat::Ident(pi) = &*pat_type.pat {
            names.insert(pi.ident.to_string());
        }
    }
    names
}

fn is_vec_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => {
            let last = tp.path.segments.last();
            last.map(|s| s.ident == "Vec").unwrap_or(false)
        }
        _ => false,
    }
}

struct BatchLoopVisitor<'a> {
    fn_name: String,
    vec_params: &'a HashSet<String>,
    has_len_guard: bool,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for BatchLoopVisitor<'a> {
    fn visit_expr_for_loop(&mut self, i: &ExprForLoop) {
        let iter_name = extract_iter_name(&i.expr);
        if let Some(name) = iter_name {
            if self.vec_params.contains(&name) && !self.has_len_guard {
                let mut body_scan = BodyScan::default();
                body_scan.visit_block(&i.body);
                if body_scan.has_dangerous_call {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Function `{}` iterates over Vec parameter `{}` calling \
                             `invoke_contract`/`transfer`/`mint`/`burn` without a `.len()` \
                             upper-bound guard. An attacker can pass a huge list to exhaust \
                             the transaction compute budget.",
                            self.fn_name, name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_for_loop(self, i);
    }
}

fn extract_iter_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        Expr::MethodCall(m) => {
            if matches!(
                m.method.to_string().as_str(),
                "iter" | "into_iter" | "iter_mut"
            ) {
                extract_iter_name(&m.receiver)
            } else {
                None
            }
        }
        Expr::Reference(r) => extract_iter_name(&r.expr),
        _ => None,
    }
}

#[derive(Default)]
struct BodyScan {
    has_dangerous_call: bool,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if matches!(
            name.as_str(),
            "invoke_contract" | "transfer" | "mint" | "burn"
        ) {
            self.has_dangerous_call = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_vec_loop_with_transfer() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn distribute(env: Env, recipients: Vec<Address>, amount: i128) {
        for recipient in recipients.iter() {
            token_client.transfer(&env, &recipient, &amount);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnboundedBatchCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_with_len_guard() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn distribute(env: Env, recipients: Vec<Address>, amount: i128) {
        assert!(recipients.len() <= 100);
        for recipient in recipients.iter() {
            token_client.transfer(&env, &recipient, &amount);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnboundedBatchCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_no_dangerous_call_in_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn log_all(env: Env, recipients: Vec<Address>) {
        for r in recipients.iter() {
            let _ = r;
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnboundedBatchCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_invoke_contract_in_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn batch_invoke(env: Env, targets: Vec<Address>) {
        for target in targets.iter() {
            env.invoke_contract(target, &symbol, args);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnboundedBatchCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
