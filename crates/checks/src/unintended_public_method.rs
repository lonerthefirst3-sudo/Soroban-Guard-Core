//! Flags `pub fn` methods in `#[contractimpl]` blocks that are not intended as entrypoints.

use crate::util::is_contractimpl;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{File, ImplItem, Item};

const CHECK_NAME: &str = "unintended-public-method";

/// Flags `#[contractimpl]` impl blocks where internal helper methods (names starting with `_` or containing `internal` or `helper`) are also marked `pub`.
pub struct UnintendedPublicMethodCheck;

impl Check for UnintendedPublicMethodCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // Find all #[contractimpl] impl blocks
        for item in &file.items {
            if let Item::Impl(item_impl) = item {
                if is_contractimpl(item_impl) {
                    // Check each function in the impl block
                    for impl_item in &item_impl.items {
                        if let ImplItem::Fn(func) = impl_item {
                            // Check if it's public and has a suspicious name
                            if matches!(func.vis, syn::Visibility::Public(_)) {
                                let func_name = func.sig.ident.to_string();
                                // Check for names that suggest internal/helper functions
                                if func_name.starts_with('_')
                                    || func_name.contains("internal")
                                    || func_name.contains("helper")
                                    || func_name.contains("_helper")
                                    || func_name.contains("_internal")
                                {
                                    out.push(Finding {
                                        check_name: CHECK_NAME.to_string(),
                                        severity: Severity::Low,
                                        file_path: String::new(),
                                        line: func.span().start().line,
                                        function_name: func_name.clone(),
                                        description: format!(
                                            "Public method `{}` in `#[contractimpl]` block appears to be an internal helper function. All methods in `#[contractimpl]` blocks are exposed as entrypoints, so this may unintentionally expose internal functionality.",
                                            func_name
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
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

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(UnintendedPublicMethodCheck.run(&file, src))
    }

    #[test]
    fn flags_unintended_public_helper() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        // do something
    }
    
    // This is an internal helper but marked public
    pub fn _helper(env: Env) {
        // internal logic
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "_helper");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_for_intended_entrypoints() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        // do something
    }
    
    pub fn transfer(env: Env) {
        // intended entrypoint
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_internal_named_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn main(env: Env) {
        // do something
    }
    
    pub fn internal_logic(env: Env) {
        // internal logic
    }
    
    pub fn helper_function(env: Env) {
        // helper logic
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].function_name, "internal_logic");
        assert_eq!(hits[1].function_name, "helper_function");
        Ok(())
    }
}
