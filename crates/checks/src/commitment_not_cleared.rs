//! Commitment not cleared after reveal — replay attack vector.
//!
//! A `reveal` or `claim` function that reads a commitment from storage but never
//! removes or overwrites it allows an attacker to replay the same reveal transaction.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "commitment-not-cleared";

/// Commitment key heuristics — any storage key whose ident text contains one of these.
const COMMIT_KEY_HINTS: &[&str] = &["commit", "hash", "nonce", "secret"];

pub struct CommitmentNotClearedCheck;

impl Check for CommitmentNotClearedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !matches!(fn_name.as_str(), "reveal" | "claim") {
                continue;
            }

            let mut scan = BodyScan::default();
            scan.visit_block(&method.block);

            if scan.commitment_get && !scan.commitment_cleared {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: scan.get_line.unwrap_or_else(|| method.sig.ident.span().start().line),
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` reads a commitment from storage but never removes \
                         or overwrites it. An attacker can replay the same reveal transaction \
                         to trigger the reveal logic multiple times."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct BodyScan {
    commitment_get: bool,
    commitment_cleared: bool,
    get_line: Option<usize>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        if receiver_chain_contains_storage(&i.receiver) {
            match method.as_str() {
                "get" | "get_unchecked" => {
                    if i.args.iter().any(|a| expr_contains_commit_hint(a)) {
                        self.commitment_get = true;
                        if self.get_line.is_none() {
                            self.get_line = Some(i.span().start().line);
                        }
                    }
                }
                "remove" => {
                    if i.args.iter().any(|a| expr_contains_commit_hint(a)) {
                        self.commitment_cleared = true;
                    }
                }
                "set" if i.args.len() == 2 => {
                    if i.args.iter().next().is_some_and(|a| expr_contains_commit_hint(a)) {
                        self.commitment_cleared = true;
                    }
                }
                _ => {}
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

/// Collect all ident/string-literal text from an expression and check for commit hints.
fn expr_contains_commit_hint(expr: &Expr) -> bool {
    let text = expr_to_text(expr).to_lowercase();
    COMMIT_KEY_HINTS.iter().any(|hint| text.contains(hint))
}

fn expr_to_text(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("_"),
        Expr::Macro(m) => {
            // e.g. symbol_short!("commit") — grab the token stream as string
            m.mac.tokens.to_string()
        }
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            syn::Lit::ByteStr(b) => String::from_utf8_lossy(&b.value()).into_owned(),
            _ => String::new(),
        },
        Expr::Reference(r) => expr_to_text(&r.expr),
        Expr::Call(c) => {
            // e.g. DataKey::Commit
            let mut s = expr_to_text(&c.func);
            for arg in &c.args {
                s.push('_');
                s.push_str(&expr_to_text(arg));
            }
            s
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        CommitmentNotClearedCheck.run(&file, src)
    }

    #[test]
    fn flags_reveal_without_remove() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn reveal(env: Env, secret: u64) {
        let stored: u64 = env.storage().persistent().get(&symbol_short!("commit")).unwrap();
        assert_eq!(stored, secret);
        // BUG: commitment never removed — replay possible
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "reveal");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_when_remove_called() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn reveal(env: Env, secret: u64) {
        let stored: u64 = env.storage().persistent().get(&symbol_short!("commit")).unwrap();
        assert_eq!(stored, secret);
        env.storage().persistent().remove(&symbol_short!("commit"));
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_overwrite_set_called() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn reveal(env: Env, secret: u64) {
        let stored: u64 = env.storage().persistent().get(&symbol_short!("commit")).unwrap();
        assert_eq!(stored, secret);
        env.storage().persistent().set(&symbol_short!("commit"), &0u64);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_reveal_functions() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env) {
        let _: u64 = env.storage().persistent().get(&symbol_short!("commit")).unwrap();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_claim_without_remove() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn claim(env: Env) {
        let _: u64 = env.storage().persistent().get(&symbol_short!("commit")).unwrap();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "claim");
    }
}
