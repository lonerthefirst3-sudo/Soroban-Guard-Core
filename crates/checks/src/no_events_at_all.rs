//! Detects contracts that perform storage operations but have zero event publish calls.
//!
//! Contracts that perform storage operations (set/remove) in any function but have
//! zero event publish calls anywhere in the file provide no on-chain audit trail.
//! State changes are invisible to indexers and users, violating the transparency
//! principle of smart contracts.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "no-events-at-all";

/// Flags entire files where any `#[contractimpl]`-reachable function calls
/// `env.storage()...set(...)` or `env.storage()...remove(...)` but no function
/// in the file calls `env.events().publish(...)`.
pub struct NoEventsAtAllCheck;

impl Check for NoEventsAtAllCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut file_scan = FileScan::default();
        let mut out = Vec::new();
        
        // Scan all contractimpl functions in the file
        for method in contractimpl_functions(file) {
            let mut func_scan = FuncBodyScan::default();
            func_scan.visit_block(&method.block);
            
            if func_scan.storage_write {
                file_scan.has_storage_write = true;
            }
            if func_scan.events_publish {
                file_scan.has_events_publish = true;
            }
            
            // Track the first storage write line for reporting
            if file_scan.first_storage_write_line.is_none() && func_scan.storage_write {
                if let Some(line) = first_storage_write_line(&method.block) {
                    file_scan.first_storage_write_line = Some(line);
                }
            }
        }
        
        // Flag if file has storage writes but no events publish
        if file_scan.has_storage_write && !file_scan.has_events_publish {
            let line = file_scan.first_storage_write_line.unwrap_or(1);
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: String::new(),
                description: format!(
                    "Contract performs storage operations (set/remove) but has zero \
                     `env.events().publish()` calls. State changes are invisible to \
                     indexers and users, violating the transparency principle of \
                     smart contracts."
                ),
            });
        }
        
        out
    }
}

#[derive(Default)]
struct FileScan {
    has_storage_write: bool,
    has_events_publish: bool,
    first_storage_write_line: Option<usize>,
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
        Ok(NoEventsAtAllCheck.run(&file, src))
    }

    #[test]
    fn flags_file_with_storage_but_no_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
    }
    
    pub fn remove_value(env: Env, key: Symbol) {
        env.storage().persistent().remove(&key);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].function_name.is_empty());
        Ok(())
    }

    #[test]
    fn does_not_flag_file_with_storage_and_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol, symbol_short};

pub struct Contract;

const VALUE_SET: Symbol = symbol_short!("set");

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
        env.events().publish((VALUE_SET,), (key, value));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_file_without_storage_operations() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn do_nothing(_env: Env) {
        // No storage operations
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_file_with_multiple_functions_no_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }
    
    pub fn update(env: Env, value: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "val"), &value);
    }
    
    pub fn cleanup(env: Env) {
        env.storage().persistent().remove(&Symbol::new(&env, "temp"));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn does_not_flag_file_with_events_in_any_function() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol, symbol_short};

pub struct Contract;

const EVENT: Symbol = symbol_short!("event");

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
    }
    
    pub fn log_event(env: Env) {
        // This function has events even though others don't
        env.events().publish((EVENT,), ());
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_only_contractimpl_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

// Non-contractimpl function with storage write
fn helper(env: Env) {
    env.storage().persistent().set(&Symbol::new(&env, "test"), &1);
}

#[contractimpl]
impl Contract {
    pub fn set_value(env: Env, key: Symbol, value: i128) {
        env.storage().persistent().set(&key, &value);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
</content>
