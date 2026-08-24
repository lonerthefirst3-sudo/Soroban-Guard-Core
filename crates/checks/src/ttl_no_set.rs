//! Flags `extend_ttl(key, min, max)` calls where `key` is never passed to `set` anywhere
//! in the same contract file (phantom TTL extension — dead code or wrong key).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ttl-no-set";

pub struct TtlNoSetCheck;

impl Check for TtlNoSetCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // Collect all keys passed to `set` across the whole file.
        let mut set_collector = KeyCollector { method: "set", keys: Vec::new() };
        set_collector.visit_file(file);
        let set_keys: Vec<String> = set_collector.keys;

        // Collect all (key, line, fn_name) passed to `extend_ttl` (3-arg form).
        let mut ttl_collector = TtlExtendCollector { entries: Vec::new() };
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            ttl_collector.current_fn = fn_name;
            ttl_collector.visit_block(&method.block);
        }

        // Flag extend_ttl keys that never appear in any set call.
        ttl_collector
            .entries
            .into_iter()
            .filter(|(key, _, _)| !set_keys.contains(key))
            .map(|(key, line, fn_name)| Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line,
                function_name: fn_name,
                description: format!(
                    "extend_ttl called for key `{key}` which is never written via `set` \
                     in this contract. This may be dead code or a wrong key."
                ),
            })
            .collect()
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "storage" || receiver_chain_contains_storage(&m.receiver),
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

/// Extract a simple string representation of an expression used as a storage key.
fn key_repr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(r) => key_repr(&r.expr),
        Expr::Path(p) => Some(p.path.segments.last()?.ident.to_string()),
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
        Expr::Macro(m) => Some(m.mac.path.segments.last()?.ident.to_string()),
        _ => None,
    }
}

/// Visits the whole file and collects key representations for a given method name.
struct KeyCollector {
    method: &'static str,
    keys: Vec<String>,
}

impl<'ast> Visit<'ast> for KeyCollector {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == self.method
            && receiver_chain_contains_storage(&i.receiver)
            && !i.args.is_empty()
        {
            if let Some(k) = key_repr(&i.args[0]) {
                self.keys.push(k);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Collects (key, line, fn_name) for 3-arg extend_ttl calls inside contractimpl functions.
struct TtlExtendCollector {
    current_fn: String,
    entries: Vec<(String, usize, String)>,
}

impl<'ast> Visit<'ast> for TtlExtendCollector {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "extend_ttl"
            && receiver_chain_contains_storage(&i.receiver)
            && i.args.len() == 3
        {
            if let Some(k) = key_repr(&i.args[0]) {
                self.entries.push((k, i.span().start().line, self.current_fn.clone()));
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
        TtlNoSetCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_extend_ttl_without_set() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh(env: Env) {
        // extend_ttl for KEY but KEY is never set anywhere
        env.storage().persistent().extend_ttl(&KEY, 100, 1000);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_key_is_set() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, v: u32) {
        env.storage().persistent().set(&KEY, &v);
        env.storage().persistent().extend_ttl(&KEY, 100, 1000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_two_arg_extend_ttl() {
        // 2-arg form (instance/temporary) — not flagged by this check
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_set_in_different_function() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, v: u32) {
        env.storage().persistent().set(&KEY, &v);
    }
    pub fn refresh(env: Env) {
        env.storage().persistent().extend_ttl(&KEY, 100, 1000);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
