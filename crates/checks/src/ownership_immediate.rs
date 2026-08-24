//! Detects immediate single-step ownership transfer without a two-step
//! propose/accept pattern.
//!
//! Directly writing a new admin/owner address in one step is risky: if the
//! supplied address is wrong, ownership is permanently lost. The safe pattern
//! is propose + accept (two-step handoff).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ownership-immediate";

/// Names that indicate a direct ownership-transfer function.
const TRANSFER_FN_NAMES: &[&str] = &[
    "set_admin",
    "set_owner",
    "transfer_ownership",
    "change_admin",
    "change_owner",
    "update_admin",
    "update_owner",
];

/// Names that indicate a safe two-step acceptance function exists.
const ACCEPT_FN_NAMES: &[&str] = &[
    "accept_ownership",
    "accept_admin",
    "confirm_admin",
    "confirm_ownership",
    "claim_ownership",
    "claim_admin",
];

pub struct OwnershipImmediateCheck;

impl Check for OwnershipImmediateCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let methods: Vec<_> = contractimpl_functions(file).into_iter().collect();

        // Check whether a safe accept function exists anywhere in the impl block.
        let has_accept_fn = methods
            .iter()
            .any(|m| ACCEPT_FN_NAMES.contains(&m.sig.ident.to_string().as_str()));

        if has_accept_fn {
            return vec![];
        }

        let mut out = Vec::new();
        for method in &methods {
            let fn_name = method.sig.ident.to_string();
            if !TRANSFER_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }

            // Check if the body writes directly to an admin/owner storage key.
            let mut scan = AdminWriteScan::default();
            scan.visit_block(&method.block);

            if scan.writes_admin_key {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` transfers ownership in a single step without a \
                         corresponding `accept_ownership` / `accept_admin` function. \
                         If the new address is wrong, ownership is permanently lost. \
                         Use a two-step propose-then-accept pattern."
                    ),
                });
            }
        }
        out
    }
}

fn is_admin_key(expr: &Expr) -> bool {
    let text = expr_to_string(expr).to_lowercase();
    text.contains("admin") || text.contains("owner")
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Reference(r) => expr_to_string(&r.expr),
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::new(),
        },
        Expr::Macro(m) => m.mac.tokens.to_string().trim_matches('"').to_string(),
        _ => String::new(),
    }
}

fn receiver_has(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == method || receiver_has(&m.receiver, method),
        _ => false,
    }
}

#[derive(Default)]
struct AdminWriteScan {
    writes_admin_key: bool,
}

impl<'ast> Visit<'ast> for AdminWriteScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Detect storage().{instance,persistent}().set(admin_key, value)
        if i.method == "set" && receiver_has(&i.receiver, "storage") && i.args.len() >= 2 {
            if let Some(key_arg) = i.args.first() {
                if is_admin_key(key_arg) {
                    self.writes_admin_key = true;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_single_step_set_admin() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &new_admin);
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = OwnershipImmediateCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn passes_when_accept_fn_exists() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("pending"), &new_admin);
    }
    pub fn accept_admin(env: Env) {
        let pending: Address = env.storage().instance().get(&symbol_short!("pending")).unwrap();
        pending.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &pending);
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = OwnershipImmediateCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_functions() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.storage().instance().set(&to, &amount);
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = OwnershipImmediateCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
