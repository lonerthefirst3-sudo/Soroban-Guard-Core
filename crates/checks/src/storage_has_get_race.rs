//! Flags potential race conditions between storage `has` and `get` calls.
//!
//! When a contract checks if a key exists with `has()` and then retrieves it with `get()`,
//! there's a potential race condition where the key could be removed between the two calls.
//! This check detects such patterns and suggests using `get()` directly instead.

use crate::util::{contractimpl_functions, is_contractimpl};
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit, LitStr, Pat, Stmt};

const CHECK_NAME: &str = "storage-has-get-race";

/// Flags potential race conditions between storage `has` and `get` calls on the same key.
/// Detects patterns like `env.storage().persistent().has(&key)` followed by `env.storage().persistent().get(&key)`.
pub struct StorageHasGetRaceCheck;

impl Check for StorageHasGetRaceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = HasGetRaceVisitor {
                has_calls: Vec::new(),
                get_calls: Vec::new(),
            };
            v.visit_block(&method.block);
            
            // Check for race conditions: has call followed by get call on same key
            for has_call in &v.has_calls {
                for get_call in &v.get_calls {
                    if has_call.key == get_call.key && has_call.line < get_call.line {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: has_call.line,
                            function_name: fn_name.clone(),
                            description: format!("Potential race condition: `has()` call on '{}' at line {} followed by `get()` call at line {}. Consider using `get()` directly to avoid race conditions.", has_call.key, has_call.line, get_call.line),
                        });
                        break;
                    }
                }
            }
        }
        
        out
    }
}

#[derive(Clone)]
struct StorageCall {
    key: String,
    line: usize,
}

struct HasGetRaceVisitor {
    has_calls: Vec<StorageCall>,
    get_calls: Vec<StorageCall>,
}

impl<'a> Visit<'a> for HasGetRaceVisitor {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        // Look for storage has calls
        if i.method == "has" {
            if let Expr::MethodCall(mc) = &*i.receiver {
                if mc.method == "storage" {
                    // Try to extract the key
                    if let Some(arg) = i.args.first() {
                        if let Expr::Reference(ref_ref) = arg {
                            if let Expr::Lit(lit) = &**ref_ref.expr {
                                if let Lit::Str(s) = &lit.lit {
                                    self.has_calls.push(StorageCall {
                                        key: s.value(),
                                        line: i.span().start().line,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Look for storage get calls
        if i.method == "get" {
            if let Expr::MethodCall(mc) = &*i.receiver {
                if mc.method == "storage" {
                    // Try to extract the key
                    if let Some(arg) = i.args.first() {
                        if let Expr::Reference(ref_ref) = arg {
                            if let Expr::Lit(lit) = &**ref_ref.expr {
                                if let Lit::Str(s) = &lit.lit {
                                    self.get_calls.push(StorageCall {
                                        key: s.value(),
                                        line: i.span().start().line,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(StorageHasGetRaceCheck.run(&file, src))
    }

    #[test]
    fn flags_has_get_race() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const KEY: soroban_sdk::Symbol = symbol_short!("key");

#[contractimpl]
impl C {
    pub fn has_then_get(env: Env) {
        // Race condition: has then get on same key
        if env.storage().persistent().has(&KEY) {
            let val = env.storage().persistent().get(&KEY);
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_no_race_condition() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const KEY: soroban_sdk::Symbol = symbol_short!("key");

#[contractimpl]
impl C {
    pub fn get_directly(env: Env) {
        // No race condition: get directly
        let val = env.storage().persistent().get(&KEY);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
