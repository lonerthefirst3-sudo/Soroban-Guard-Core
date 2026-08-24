//! Flags `extend_ttl(min, max)` where both arguments are integer literals and `max < 10000`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "ttl-hardcoded-low";
const TTL_THRESHOLD: u64 = 10_000;

pub struct TtlHardcodedLowCheck;

impl Check for TtlHardcodedLowCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlLowVisitor { fn_name, out: &mut out };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "storage" || receiver_chain_contains_storage(&m.receiver),
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn extract_int_literal(expr: &Expr) -> Option<u64> {
    if let Expr::Lit(syn::ExprLit { lit: Lit::Int(i), .. }) = expr {
        i.base10_parse().ok()
    } else {
        None
    }
}

struct TtlLowVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for TtlLowVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if i.method == "extend_ttl"
            && receiver_chain_contains_storage(&i.receiver)
            && i.args.len() == 2
        {
            if let (Some(min), Some(max)) = (
                extract_int_literal(&i.args[0]),
                extract_int_literal(&i.args[1]),
            ) {
                if max < TTL_THRESHOLD {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "extend_ttl called with hardcoded max_ttl ({}) below {} ledgers. \
                             Consider using a configurable TTL to avoid frequent re-extension. \
                             min_ttl={}.",
                            max, TTL_THRESHOLD, min
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

    fn run(src: &str) -> Vec<Finding> {
        TtlHardcodedLowCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_low_max_ttl() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn bump(env: Env) {
        env.storage().instance().extend_ttl(50, 100);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_high_max_ttl() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn bump(env: Env) {
        env.storage().instance().extend_ttl(5000, 10000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_variable_args() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn bump(env: Env, min: u32, max: u32) {
        env.storage().instance().extend_ttl(min, max);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
pub struct C;
impl C {
    pub fn bump(env: Env) {
        env.storage().instance().extend_ttl(50, 100);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
