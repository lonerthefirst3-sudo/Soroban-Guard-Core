//! Detects contract initialization functions that don't emit an `Initialized` event.
//!
//! Contract initialization (storing admin, setting up state) without emitting an
//! `Initialized` event makes it impossible to know from on-chain data that the
//! contract has been set up.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "init-no-event";

/// Flags `pub fn init`, `pub fn initialize`, or `pub fn setup` in `#[contractimpl]` blocks
/// that call `set(...)` but do not call `events().publish(...)`.
pub struct InitNoEventCheck;

impl Check for InitNoEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Check if function name matches initialization functions
            if !matches!(fn_name.as_str(), "init" | "initialize" | "setup") {
                continue;
            }

            // Check if function is public
            if !method.sig.vis.is_pub() {
                continue;
            }

            let mut scan = FuncBodyScan::default();
            scan.visit_block(&method.block);
            
            if scan.storage_write && !scan.events_publish {
                let line = first_storage_write_line(&method.block)
                    .unwrap_or_else(|| method.sig.ident.span().start().line);
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Initialization function `{fn_name}` writes to storage but does not emit \
                         an `Initialized` event via `env.events().publish()`. Off-chain indexers \
                         and users cannot know from on-chain data that the contract has been set up."
                    ),
                });
            }
        }
        out
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

fn is_storage_mutation_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    if !matches!(
        name.as_str(),
        "set" | "remove" | "extend_ttl" | "bump" | "append"
    ) {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
}

fn is_events_publish(m: &ExprMethodCall) -> bool {
    if m.method != "publish" {
        return false;
    }
    // Check if the receiver chain contains events()
    receiver_chain_contains_events(&m.receiver)
}

fn receiver_chain_contains_events(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_chain_contains_events(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_events(&f.base),
        _ => false,
    }
}

#[derive(Default)]
struct FuncBodyScan {
    storage_write: bool,
    events_publish: bool,
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_mutation_call(i) {
            self.storage_write = true;
        }
        if is_events_publish(i) {
            self.events_publish = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct FirstStorageWrite {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstStorageWrite {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_mutation_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_storage_write_line(block: &Block) -> Option<usize> {
    let mut v = FirstStorageWrite { line: None };
    v.visit_block(block);
    v.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(InitNoEventCheck.run(&file, src))
    }

    #[test]
    fn flags_init_without_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "init");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_initialize_without_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "initialize");
        Ok(())
    }

    #[test]
    fn flags_setup_without_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn setup(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "setup");
        Ok(())
    }

    #[test]
    fn does_not_flag_init_with_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol, symbol_short};

pub struct Contract;

const INITIALIZED: Symbol = symbol_short!("init");

#[contractimpl]
impl Contract {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
        env.events().publish((INITIALIZED,), (admin,));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_private_init() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_non_init_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_init_without_storage_write() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(env: Env) {
        // No storage writes
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_init_with_multiple_storage_writes() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(env: Env, admin: Address, version: u32) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
        env.storage().instance().set(&Symbol::new(&env, "version"), &version);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "init");
        Ok(())
    }
}
</content>
