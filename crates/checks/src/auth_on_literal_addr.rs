//! Flags `require_auth()` called on an Address that was constructed inside the
//! function body (e.g. `Address::from_string`, `Address::from_contract_id`, or
//! `env.current_contract_address()`) rather than on a function parameter.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, Stmt};

const CHECK_NAME: &str = "auth-on-literal-addr";

pub struct AuthOnLiteralAddrCheck;

impl Check for AuthOnLiteralAddrCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Collect parameter names so we can exclude them.
            let params: HashSet<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    if let FnArg::Typed(pt) = arg {
                        if let Pat::Ident(pi) = pt.pat.as_ref() {
                            return Some(pi.ident.to_string());
                        }
                    }
                    None
                })
                .collect();

            let fn_name = method.sig.ident.to_string();
            let mut v = LiteralAddrVisitor {
                fn_name,
                params: &params,
                literal_vars: HashSet::new(),
                out: &mut out,
            };
            // First pass: collect local vars assigned from literal constructors.
            for stmt in &method.block.stmts {
                v.visit_stmt(stmt);
            }
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns true when `expr` is a call that produces a locally-constructed Address:
/// - `Address::from_string(…)`
/// - `Address::from_contract_id(…)`
/// - `env.current_contract_address()`
fn is_literal_addr_expr(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            let method = m.method.to_string();
            method == "current_contract_address"
        }
        Expr::Call(c) => {
            if let Expr::Path(p) = c.func.as_ref() {
                let segs: Vec<_> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if segs.len() == 2 {
                    matches!(segs[1].as_str(), "from_string" | "from_contract_id")
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

// ── visitor ──────────────────────────────────────────────────────────────────

struct LiteralAddrVisitor<'a> {
    fn_name: String,
    params: &'a HashSet<String>,
    /// Local variable names that hold a literal-constructed Address.
    literal_vars: HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for LiteralAddrVisitor<'a> {
    fn visit_stmt(&mut self, i: &'a Stmt) {
        // Detect `let <ident> = <literal_addr_expr>;`
        if let Stmt::Local(local) = i {
            if let Pat::Ident(pi) = &local.pat {
                if let Some(init) = &local.init {
                    if is_literal_addr_expr(&init.expr) {
                        self.literal_vars.insert(pi.ident.to_string());
                    }
                }
            }
        }
        visit::visit_stmt(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if i.method == "require_auth" || i.method == "require_auth_for_args" {
            let receiver_ident = match i.receiver.as_ref() {
                Expr::Path(p) => p.path.get_ident().map(|id| id.to_string()),
                _ => None,
            };
            if let Some(name) = receiver_ident {
                // Flag if the receiver is a locally-constructed literal addr,
                // not a function parameter.
                if self.literal_vars.contains(&name) && !self.params.contains(&name) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Function `{}` calls `require_auth()` on `{}`, which is a \
                             locally-constructed Address (not a caller parameter). This \
                             provides no real access control — the contract is authorising \
                             itself or a hardcoded address rather than the actual caller.",
                            self.fn_name, name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse error");
        AuthOnLiteralAddrCheck.run(&file, src)
    }

    #[test]
    fn flags_current_contract_address() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn admin_only(env: Env) {
        let contract = env.current_contract_address();
        contract.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "admin_only");
    }

    #[test]
    fn flags_address_from_string() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env, String};
pub struct C;
#[contractimpl]
impl C {
    pub fn do_thing(env: Env) {
        let admin = Address::from_string(&String::from_str(&env, "GABC..."));
        admin.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "do_thing");
    }

    #[test]
    fn flags_address_from_contract_id() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env, BytesN};
pub struct C;
#[contractimpl]
impl C {
    pub fn do_thing(env: Env) {
        let addr = Address::from_contract_id(&BytesN::from_array(&env, &[0u8; 32]));
        addr.require_auth();
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_param_require_auth() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, caller: Address) {
        caller.require_auth();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_env_require_auth() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn action(env: Env) {
        env.require_auth();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Env};
pub struct C;
impl C {
    pub fn action(env: Env) {
        let contract = env.current_contract_address();
        contract.require_auth();
    }
}
"#);
        assert!(hits.is_empty());
    }
}
