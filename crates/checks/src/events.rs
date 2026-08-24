//! Missing `env.events().publish()` when writing to storage in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-events";

/// Flags `#[contractimpl]` methods that write via `env.storage()` without calling
/// `env.events().publish()` to emit events for state changes.
pub struct MissingEventsCheck;

impl Check for MissingEventsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut scan = FuncBodyScan::default();
            scan.visit_block(&method.block);
            if !scan.storage_write || scan.events_publish {
                continue;
            }
            let line = first_storage_write_line(&method.block)
                .unwrap_or_else(|| method.sig.ident.span().start().line);
            let fn_name = method.sig.ident.to_string();
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` writes to `env.storage()` but does not call \
                     `env.events().publish()`. Off-chain indexers and users cannot track \
                     contract activity without events."
                ),
            });
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
        Ok(MissingEventsCheck.run(&file, src))
    }

    #[test]
    fn flags_storage_set_without_events_publish() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_balance");
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn does_not_flag_storage_set_with_events_publish() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol, symbol_short};

pub struct Contract;

const BALANCE: Symbol = symbol_short!("balance");

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, amount: i128) {
        env.storage().persistent().set(&BALANCE, &amount);
        env.events().publish(("balance_updated",), (amount,));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_multiple_storage_writes_without_events() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Symbol, to: Symbol, amount: i128) {
        let from_balance = env.storage().persistent().get(&from).unwrap_or(0);
        let to_balance = env.storage().persistent().get(&to).unwrap_or(0);
        env.storage().persistent().set(&from, &(from_balance - amount));
        env.storage().persistent().set(&to, &(to_balance + amount));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer");
        Ok(())
    }

    #[test]
    fn does_not_flag_read_only_methods() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}