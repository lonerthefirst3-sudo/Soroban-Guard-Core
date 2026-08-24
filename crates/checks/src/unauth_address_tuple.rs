//! Storage `set` with a tuple value containing Address parameters and no `require_auth`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "unauth-address-tuple";

pub struct UnauthAddressTupleCheck;

impl Check for UnauthAddressTupleCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Collect Address-typed parameter names.
            let addr_params: Vec<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    let FnArg::Typed(pt) = arg else { return None };
                    if !type_is_address(&pt.ty) {
                        return None;
                    }
                    if let Pat::Ident(pi) = &*pt.pat {
                        Some(pi.ident.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            if addr_params.is_empty() {
                continue;
            }

            let mut scan = BodyScan::new(addr_params);
            scan.visit_block(&method.block);

            if scan.tuple_set && !scan.has_require_auth {
                let fn_name = method.sig.ident.to_string();
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: scan.set_line.unwrap_or_else(|| method.sig.ident.span().start().line),
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` stores a tuple containing Address parameters \
                         without calling `require_auth()` on any of them. An attacker can \
                         record arbitrary address pairs as authorized relationships."
                    ),
                });
            }
        }
        out
    }
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Address"),
        _ => false,
    }
}

struct BodyScan {
    addr_params: Vec<String>,
    tuple_set: bool,
    has_require_auth: bool,
    set_line: Option<usize>,
}

impl BodyScan {
    fn new(addr_params: Vec<String>) -> Self {
        Self {
            addr_params,
            tuple_set: false,
            has_require_auth: false,
            set_line: None,
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Detect require_auth on any Address parameter.
        if i.method == "require_auth" {
            if let syn::Expr::Path(p) = &*i.receiver {
                let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if self.addr_params.contains(&name) {
                    self.has_require_auth = true;
                }
            }
        }

        // Detect storage().*.set(key, tuple_with_address_param)
        if i.method == "set" && i.args.len() == 2 {
            if receiver_chain_contains_storage(&i.receiver) {
                let value_arg = i.args.iter().nth(1).unwrap();
                if self.expr_is_tuple_with_addr_param(value_arg) {
                    self.tuple_set = true;
                    if self.set_line.is_none() {
                        self.set_line = Some(i.span().start().line);
                    }
                }
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}

impl BodyScan {
    fn expr_is_tuple_with_addr_param(&self, expr: &syn::Expr) -> bool {
        let syn::Expr::Tuple(t) = expr else { return false };
        t.elems.iter().any(|e| self.expr_references_addr_param(e))
    }

    fn expr_references_addr_param(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(p) => {
                let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                self.addr_params.contains(&name)
            }
            syn::Expr::Reference(r) => self.expr_references_addr_param(&r.expr),
            _ => false,
        }
    }
}

fn receiver_chain_contains_storage(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        syn::Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        UnauthAddressTupleCheck.run(&file, src)
    }

    #[test]
    fn flags_tuple_set_without_require_auth() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn approve(env: Env, from: Address, to: Address) {
        env.storage().persistent().set(&symbol_short!("appr"), &(from, to));
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "approve");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_when_require_auth_called() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn approve(env: Env, from: Address, to: Address) {
        from.require_auth();
        env.storage().persistent().set(&symbol_short!("appr"), &(from, to));
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_address_tuple() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, a: u32, b: u32) {
        env.storage().persistent().set(&symbol_short!("k"), &(a, b));
    }
}
"#);
        assert!(hits.is_empty());
    }
}
