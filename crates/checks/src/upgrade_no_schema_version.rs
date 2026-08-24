//! `update_current_contract_wasm` calls with no schema/version key written anywhere in the file.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "upgrade-no-schema-version";

/// Flags contracts that call `update_current_contract_wasm` but never write a
/// version or schema key to storage anywhere in the file.
///
/// Without a schema/version sentinel, upgraded code cannot detect it is reading
/// data that was serialized by an older layout, leading to silent corruption or
/// deserialization panics.
pub struct UpgradeNoSchemaVersionCheck;

impl Check for UpgradeNoSchemaVersionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // Step 1 - find any function that calls update_current_contract_wasm.
        let mut upgrade_fn: Option<(String, usize)> = None;
        for method in contractimpl_functions(file) {
            let mut scan = UpgradeScan::default();
            scan.visit_block(&method.block);
            if let Some(line) = scan.upgrade_line {
                upgrade_fn = Some((method.sig.ident.to_string(), line));
                break;
            }
        }

        let (fn_name, line) = match upgrade_fn {
            Some(v) => v,
            None => return vec![],
        };

        // Step 2 - check whether any function in the file writes a version/schema key.
        for method in contractimpl_functions(file) {
            let mut scan = VersionKeyScan::default();
            scan.visit_block(&method.block);
            if scan.found {
                return vec![];
            }
        }

        vec![Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path: String::new(),
            line,
            function_name: fn_name.clone(),
            description: format!(
                "Function `{fn_name}` calls `update_current_contract_wasm` but no \
                 storage `set` with a key containing \"version\" or \"schema\" was found \
                 anywhere in the file. Without a schema version key, upgraded code cannot \
                 detect stale storage layouts, risking silent corruption or panic on \
                 deserialization."
            ),
        }]
    }
}

// === Helpers

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

fn key_tokens_contain_version(expr: &Expr) -> bool {
    let mut ts = TokenStream::new();
    expr.to_tokens(&mut ts);
    let s = ts.to_string().to_lowercase();
    s.contains("version") || s.contains("schema")
}

#[derive(Default)]
struct UpgradeScan {
    upgrade_line: Option<usize>,
}

impl<'ast> Visit<'ast> for UpgradeScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "update_current_contract_wasm" {
            self.upgrade_line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[derive(Default)]
struct VersionKeyScan {
    found: bool,
}

impl<'ast> Visit<'ast> for VersionKeyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) {
            if let Some(key_arg) = i.args.first() {
                if key_tokens_contain_version(key_arg) {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

// === Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        UpgradeNoSchemaVersionCheck.run(&file, src)
    }

    #[test]
    fn flags_upgrade_with_no_schema_key() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "upgrade");
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_schema_version_set_in_upgrade() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, symbol_short, BytesN, Env};

#[contract]
pub struct C;

const SCHEMA_VERSION: soroban_sdk::Symbol = symbol_short!("ver");

#[contractimpl]
impl C {
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
        env.storage().instance().set(&SCHEMA_VERSION, &2u32);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_version_key_set_in_init() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, symbol_short, BytesN, Env};

#[contract]
pub struct C;

const SCHEMA_VERSION: soroban_sdk::Symbol = symbol_short!("ver");

#[contractimpl]
impl C {
    pub fn init(env: Env) {
        env.storage().instance().set(&SCHEMA_VERSION, &1u32);
    }

    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_schema_literal_key_used() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, BytesN, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
        env.storage().instance().set(&Symbol::new(&env, "schema"), &2u32);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_findings_when_no_upgrade_call() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn init(env: Env) {
        env.storage().instance().set(&42u32, &0u32);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
