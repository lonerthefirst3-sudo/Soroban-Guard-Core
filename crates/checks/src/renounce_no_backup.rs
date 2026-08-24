//! Detects `renounce_ownership` / `renounce_admin` functions that remove the
//! admin key without verifying a backup or fallback admin mechanism exists.
//!
//! Calling `storage().remove(admin_key)` or setting the admin to `None` without
//! any alternative authorization path permanently locks the contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "renounce-no-backup";

/// Function names that indicate an ownership-renouncement operation.
const RENOUNCE_FN_NAMES: &[&str] = &[
    "renounce_ownership",
    "renounce_admin",
    "revoke_ownership",
    "revoke_admin",
];

pub struct RenounceNoBackupCheck;

impl Check for RenounceNoBackupCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if !RENOUNCE_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }

            let mut scan = RenounceScan::default();
            scan.visit_block(&method.block);

            // Flag if the function removes/clears the admin key without setting a backup.
            if scan.removes_admin && !scan.sets_backup {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` removes or clears the admin key without \
                         setting a backup or fallback admin. This permanently locks the \
                         contract with no recovery path."
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
struct RenounceScan {
    removes_admin: bool,
    sets_backup: bool,
}

impl<'ast> Visit<'ast> for RenounceScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        // Detect storage().{instance,persistent}().remove(admin_key)
        if method == "remove" && receiver_has(&i.receiver, "storage") {
            if let Some(key_arg) = i.args.first() {
                if is_admin_key(key_arg) {
                    self.removes_admin = true;
                }
            }
        }

        // Detect storage().{instance,persistent}().set(admin_key, backup_value)
        // as a backup mechanism (e.g. setting a multisig or DAO address).
        if method == "set" && receiver_has(&i.receiver, "storage") {
            if let Some(key_arg) = i.args.first() {
                if is_admin_key(key_arg) {
                    self.sets_backup = true;
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
    fn flags_renounce_without_backup() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn renounce_ownership(env: Env) {
        env.require_auth();
        env.storage().instance().remove(&symbol_short!("admin"));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = RenounceNoBackupCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].function_name, "renounce_ownership");
    }

    #[test]
    fn passes_when_backup_set_before_remove() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn renounce_ownership(env: Env, backup: Address) {
        env.require_auth();
        env.storage().instance().set(&symbol_short!("admin"), &backup);
        env.storage().instance().remove(&symbol_short!("owner"));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = RenounceNoBackupCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_renounce_functions() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn clear_data(env: Env) {
        env.storage().instance().remove(&symbol_short!("admin"));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = RenounceNoBackupCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_renounce_admin_variant() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn renounce_admin(env: Env) {
        env.storage().persistent().remove(&symbol_short!("admin"));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = RenounceNoBackupCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
    }
}
