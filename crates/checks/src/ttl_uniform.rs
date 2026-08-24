//! Flags contracts where every `extend_ttl(key, min, max)` call uses the same literal
//! min/max values regardless of which key is being extended.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "ttl-uniform";

fn lit_u64(expr: &Expr) -> Option<u64> {
    if let Expr::Lit(el) = expr {
        if let Lit::Int(i) = &el.lit {
            return i.base10_parse().ok();
        }
    }
    None
}

fn receiver_has(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == method || receiver_has(&m.receiver, method),
        _ => false,
    }
}

#[derive(Default)]
struct ExtendTtlScanner {
    calls: Vec<(u64, u64, usize)>, // (min, max, line)
}

impl<'ast> Visit<'ast> for ExtendTtlScanner {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "extend_ttl" && receiver_has(&i.receiver, "storage") {
            // extend_ttl(key, min, max) — 3 args for persistent/temporary,
            // or extend_ttl(min, max) — 2 args for instance
            let args: Vec<&Expr> = i.args.iter().collect();
            let (min_expr, max_expr) = if args.len() == 3 {
                (args[1], args[2])
            } else if args.len() == 2 {
                (args[0], args[1])
            } else {
                visit::visit_expr_method_call(self, i);
                return;
            };
            if let (Some(min), Some(max)) = (lit_u64(min_expr), lit_u64(max_expr)) {
                self.calls.push((min, max, i.span().start().line));
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct TtlUniformCheck;

impl Check for TtlUniformCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // Collect all extend_ttl calls across the whole file.
        let mut scanner = ExtendTtlScanner::default();
        scanner.visit_file(file);

        if scanner.calls.len() < 2 {
            return vec![];
        }

        // Check if every call uses the same (min, max) pair.
        let first = (scanner.calls[0].0, scanner.calls[0].1);
        let all_same = scanner
            .calls
            .iter()
            .all(|(min, max, _)| (*min, *max) == first);
        if !all_same {
            return vec![];
        }

        // Only flag if there are multiple distinct keys being extended (i.e., multiple
        // contractimpl functions each calling extend_ttl with the same values).
        let fn_count = contractimpl_functions(file)
            .iter()
            .filter(|m| {
                let mut s = ExtendTtlScanner::default();
                s.visit_block(&m.block);
                !s.calls.is_empty()
            })
            .count();

        if fn_count < 2 {
            return vec![];
        }

        vec![Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Low,
            file_path: String::new(),
            line: scanner.calls[0].2,
            function_name: String::new(),
            description: format!(
                "All `extend_ttl` calls in this contract use the same TTL values \
                 (min={}, max={}). Different storage keys likely have different \
                 criticality; use distinct TTL values to reflect their intended lifetimes.",
                first.0, first.1
            ),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        TtlUniformCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_uniform_ttl() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store_config(env: Env) {
        env.storage().persistent().set(&CONFIG_KEY, &1u32);
        env.storage().persistent().extend_ttl(&CONFIG_KEY, 1000, 2000);
    }
    pub fn store_session(env: Env) {
        env.storage().persistent().set(&SESSION_KEY, &2u32);
        env.storage().persistent().extend_ttl(&SESSION_KEY, 1000, 2000);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("1000"));
    }

    #[test]
    fn no_flag_when_different_ttls() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store_config(env: Env) {
        env.storage().persistent().extend_ttl(&CONFIG_KEY, 10000, 20000);
    }
    pub fn store_session(env: Env) {
        env.storage().persistent().extend_ttl(&SESSION_KEY, 100, 200);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_flag_single_call() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        env.storage().persistent().extend_ttl(&KEY, 1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
