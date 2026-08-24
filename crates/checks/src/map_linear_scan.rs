//! Map iterated over via `keys()` for linear scan instead of direct key lookup.
//!
//! Iterating over `map.keys()` to find a specific key is an O(n) operation that
//! should be O(1). This suggests the developer is using the wrong data structure
//! or should use `map.get(key)` directly.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprMethodCall, File};

const CHECK_NAME: &str = "map-linear-scan";

struct MapScanVisitor<'a> {
    fn_name: String,
    in_keys_loop: bool,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for MapScanVisitor<'ast> {
    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        let is_keys_loop = if let Expr::MethodCall(mc) = &*i.iter {
            mc.method == "keys"
        } else {
            false
        };

        if is_keys_loop {
            let old_in_keys_loop = self.in_keys_loop;
            self.in_keys_loop = true;
            visit::visit_expr_for_loop(self, i);
            self.in_keys_loop = old_in_keys_loop;
        } else {
            visit::visit_expr_for_loop(self, i);
        }
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.in_keys_loop && i.method == "get" {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Iterating over `map.keys()` and then calling `map.get(key)` in `{}` is O(n). \
                     Use `map.get(key)` directly for O(1) lookup instead.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct MapLinearScanCheck;

impl Check for MapLinearScanCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = MapScanVisitor {
                fn_name,
                in_keys_loop: false,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_map_keys_linear_scan() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Map};
pub struct C;
#[contractimpl]
impl C {
    pub fn find_key(env: Env, m: Map<u32, u32>, target: u32) {
        for key in m.keys() {
            if let Some(val) = m.get(key) {
                if val == target {
                    break;
                }
            }
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MapLinearScanCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn no_finding_direct_get() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Map};
pub struct C;
#[contractimpl]
impl C {
    pub fn find_key(env: Env, m: Map<u32, u32>, target: u32) {
        if let Some(val) = m.get(target) {
            // found it
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MapLinearScanCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_keys_without_get() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Map};
pub struct C;
#[contractimpl]
impl C {
    pub fn count_keys(env: Env, m: Map<u32, u32>) {
        let mut count = 0u32;
        for key in m.keys() {
            count += 1;
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = MapLinearScanCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
