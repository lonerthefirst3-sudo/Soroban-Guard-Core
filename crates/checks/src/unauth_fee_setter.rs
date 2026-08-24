//! Fee-setter functions missing `require_auth`.
//!
//! A function named `set_fee`, `set_rate`, `set_commission`, or `update_fee`
//! that writes a value to storage without first calling `require_auth` allows
//! any user to manipulate protocol economics.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Visibility};

const CHECK_NAME: &str = "unauth-fee-setter";

const FEE_SETTER_NAMES: &[&str] = &["set_fee", "set_rate", "set_commission", "update_fee"];

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

#[derive(Default)]
struct FeeScan {
    has_require_auth: bool,
    has_storage_set: bool,
    storage_set_line: usize,
}

impl<'ast> Visit<'ast> for FeeScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if matches!(
            i.method.to_string().as_str(),
            "require_auth" | "require_auth_for_args"
        ) {
            self.has_require_auth = true;
        }
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) {
            if self.storage_set_line == 0 {
                self.storage_set_line = i.span().start().line;
            }
            self.has_storage_set = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn scan_block(block: &Block) -> FeeScan {
    let mut s = FeeScan::default();
    s.visit_block(block);
    s
}

pub struct UnauthFeeSetterCheck;

impl Check for UnauthFeeSetterCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let name = method.sig.ident.to_string();
            if !FEE_SETTER_NAMES.contains(&name.as_str()) {
                continue;
            }
            let scan = scan_block(&method.block);
            if scan.has_storage_set && !scan.has_require_auth {
                let line = if scan.storage_set_line > 0 {
                    scan.storage_set_line
                } else {
                    method.sig.fn_token.span().start().line
                };
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: name.clone(),
                    description: format!(
                        "Function `{name}` writes a fee/rate value to storage without calling \
                         `require_auth()`. Any caller can manipulate protocol economics. \
                         Verify the caller is the admin before updating the fee."
                    ),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        UnauthFeeSetterCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_set_fee_without_auth() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn set_fee(env: Env, fee: u32) {
        env.storage().instance().set(&FEE_KEY, &fee);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn flags_set_rate_without_auth() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn set_rate(env: Env, rate: u32) {
        env.storage().persistent().set(&RATE_KEY, &rate);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn flags_set_commission_without_auth() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn set_commission(env: Env, bps: u32) {
        env.storage().instance().set(&COMM_KEY, &bps);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn flags_update_fee_without_auth() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn update_fee(env: Env, fee: u32) {
        env.storage().instance().set(&FEE_KEY, &fee);
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn no_finding_when_require_auth_present() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn set_fee(env: Env, admin: Address, fee: u32) {
        admin.require_auth();
        env.storage().instance().set(&FEE_KEY, &fee);
    }
}
"#);
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn no_finding_for_unrelated_function() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn configure(env: Env, fee: u32) {
        env.storage().instance().set(&FEE_KEY, &fee);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_finding_for_private_function() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    fn set_fee(env: Env, fee: u32) {
        env.storage().instance().set(&FEE_KEY, &fee);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_finding_when_no_storage_write() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn set_fee(env: Env, fee: u32) {
        let _ = fee;
    }
}
"#);
        assert!(hits.is_empty());
    }
}
