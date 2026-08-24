//! Flags dead code (functions or constants) that reference storage operations but are never called.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Item};

const CHECK_NAME: &str = "dead-storage-code";

/// Flags functions or `const` items that contain storage `set`/`get`/`has` calls but are never referenced from any `#[contractimpl]` function in the same file.
pub struct DeadStorageCodeCheck;

impl Check for DeadStorageCodeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // First, collect all functions that are referenced from #[contractimpl] functions
        let mut referenced_functions = std::collections::HashSet::new();

        for method in contractimpl_functions(file) {
            let mut v = ReferenceVisitor {
                referenced_functions: &mut referenced_functions,
            };
            v.visit_block(&method.block);
        }

        // Then, find all functions and const items in the file
        for item in &file.items {
            match item {
                Item::Fn(func) => {
                    let func_name = func.sig.ident.to_string();
                    if !referenced_functions.contains(&func_name) {
                        // Check if this function contains storage operations
                        let mut v = StorageVisitor {
                            has_storage_ops: false,
                        };
                        v.visit_item_fn(func);
                        if v.has_storage_ops {
                            out.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Low,
                                file_path: String::new(),
                                line: func.span().start().line,
                                function_name: func_name.clone(),
                                description: format!(
                                    "Dead code function `{}` contains storage operations but is never called from any `#[contractimpl]` function.",
                                    func_name
                                ),
                            });
                        }
                    }
                }
                Item::Const(const_item) => {
                    let const_name = const_item.ident.to_string();
                    // Check if this const contains storage operations
                    let mut v = StorageVisitor {
                        has_storage_ops: false,
                    };
                    v.visit_item_const(const_item);
                    if v.has_storage_ops {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line: const_item.span().start().line,
                            function_name: const_name.clone(),
                            description: format!(
                                "Dead code constant `{}` contains storage operations but is never referenced from any `#[contractimpl]` function.",
                                const_name
                            ),
                        });
                    }
                }
                _ => {}
            }
        }

        out
    }
}

struct ReferenceVisitor<'a> {
    referenced_functions: &'a mut std::collections::HashSet<String>,
}

impl<'a> Visit<'a> for ReferenceVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        // Look for function calls like `some_function()`
        if let Expr::Path(path) = &*i.receiver {
            if let Some(segment) = path.path.segments.last() {
                self.referenced_functions.insert(segment.ident.to_string());
            }
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_call(&mut self, i: &'a syn::ExprCall) {
        // Look for function calls like `some_function()`
        if let Expr::Path(path) = &*i.func {
            if let Some(segment) = path.path.segments.last() {
                self.referenced_functions.insert(segment.ident.to_string());
            }
        }
        visit::visit_expr_call(self, i);
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
        _ => false,
    }
}

struct StorageVisitor {
    has_storage_ops: bool,
}

impl<'a> Visit<'a> for StorageVisitor {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        // Check for storage operations: set, get, has
        if matches!(i.method.to_string().as_str(), "set" | "get" | "has")
            && receiver_chain_contains_storage(&i.receiver)
        {
            self.has_storage_ops = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_call(&mut self, i: &'a syn::ExprCall) {
        // Check for storage function calls
        if let Expr::Path(path) = &*i.func {
            if let Some(segment) = path.path.segments.last() {
                if segment.ident == "storage_set"
                    || segment.ident == "storage_get"
                    || segment.ident == "storage_has"
                {
                    self.has_storage_ops = true;
                }
            }
        }
        visit::visit_expr_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(DeadStorageCodeCheck.run(&file, src))
    }

    #[test]
    fn flags_dead_storage_function() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

// Dead function with storage operations
fn helper(env: Env) {
    env.storage().persistent().set(&"key", &123);
}

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        // doesn't call helper
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "helper");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_function_is_called() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

// Function with storage operations
fn helper(env: Env) {
    env.storage().persistent().set(&"key", &123);
}

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        helper(env); // called here
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_dead_storage_const() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

// Dead const with storage operations
const HELPER: i32 = {
    let env = Env::default();
    env.storage().persistent().set(&"key", &123);
    42
};

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        // doesn't use HELPER
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "HELPER");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }
}
