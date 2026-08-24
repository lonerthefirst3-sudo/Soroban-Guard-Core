//! Missing `#[contract]` attribute on struct used in `#[contractimpl]`.
//!
//! A struct used as the target of a `#[contractimpl]` impl block must itself be
//! annotated with `#[contract]`. If missing, the Soroban SDK will not register
//! the contract correctly.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{Item, ItemImpl, ItemStruct};

const CHECK_NAME: &str = "missing-contract-attr";

/// Flags structs used in `#[contractimpl]` impl blocks that lack `#[contract]` attribute.
pub struct MissingContractAttrCheck;

impl Check for MissingContractAttrCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &syn::File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // Collect struct names from #[contractimpl] impl blocks
        let mut contractimpl_structs = std::collections::HashSet::new();
        for item in &file.items {
            if let Item::Impl(item_impl) = item {
                if is_contractimpl(item_impl) {
                    if let syn::Type::Path(tp) = &*item_impl.self_ty {
                        if let Some(ident) = tp.path.get_ident() {
                            contractimpl_structs.insert(ident.to_string());
                        }
                    }
                }
            }
        }

        // Check each struct for #[contract] attribute
        for item in &file.items {
            if let Item::Struct(item_struct) = item {
                let struct_name = item_struct.ident.to_string();
                if contractimpl_structs.contains(&struct_name) {
                    if !has_contract_attr(item_struct) {
                        let line = item_struct.ident.span().start().line;
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line,
                            function_name: struct_name.clone(),
                            description: format!(
                                "Struct `{struct_name}` is used in `#[contractimpl]` but lacks \
                                 `#[contract]` attribute. The Soroban SDK will not register the \
                                 contract correctly."
                            ),
                        });
                    }
                }
            }
        }

        out
    }
}

fn is_contractimpl(item_impl: &ItemImpl) -> bool {
    item_impl
        .attrs
        .iter()
        .any(|attr| path_is_contractimpl(attr.path()))
}

fn path_is_contractimpl(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|s| s.ident == "contractimpl")
}

fn has_contract_attr(item_struct: &ItemStruct) -> bool {
    item_struct
        .attrs
        .iter()
        .any(|attr| path_is_contract(attr.path()))
}

fn path_is_contract(path: &syn::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|s| s.ident == "contract")
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_missing_contract_attr() {
        let code = r#"
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn test(env: Env) {}
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MissingContractAttrCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].function_name, "MyContract");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn allows_contract_with_attr() {
        let code = r#"
#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn test(env: Env) {}
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MissingContractAttrCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_structs_without_contractimpl() {
        let code = r#"
pub struct UnusedStruct;

#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn test(env: Env) {}
}
        "#;
        let file = parse_file(code).unwrap();
        let check = MissingContractAttrCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}
