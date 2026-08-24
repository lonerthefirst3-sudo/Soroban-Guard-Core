//! `impl` blocks for `#[contract]` structs that are missing `#[contractimpl]`.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{File, ImplItem, Item, Type, Visibility};

const CHECK_NAME: &str = "missing-contractimpl";

pub struct MissingContractimplCheck;

impl Check for MissingContractimplCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        // Pass 1: collect struct names annotated with #[contract].
        let contract_structs: Vec<String> = file
            .items
            .iter()
            .filter_map(|item| {
                let Item::Struct(s) = item else { return None };
                let has_contract = s.attrs.iter().any(|a| {
                    a.path()
                        .segments
                        .last()
                        .is_some_and(|seg| seg.ident == "contract")
                });
                has_contract.then(|| s.ident.to_string())
            })
            .collect();

        if contract_structs.is_empty() {
            return vec![];
        }

        // Pass 2: find impl blocks for those structs that lack #[contractimpl] and have pub fns.
        let mut out = Vec::new();
        for item in &file.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };
            // Skip trait impls.
            if item_impl.trait_.is_some() {
                continue;
            }
            // Already has contractimpl — fine.
            if crate::util::is_contractimpl(item_impl) {
                continue;
            }
            // Check self type matches a #[contract] struct.
            let self_name = impl_self_type_name(&item_impl.self_ty);
            if !contract_structs.iter().any(|n| *n == self_name) {
                continue;
            }
            // Has at least one pub fn?
            let has_pub_fn = item_impl.items.iter().any(|i| {
                if let ImplItem::Fn(f) = i {
                    matches!(f.vis, Visibility::Public(_))
                } else {
                    false
                }
            });
            if !has_pub_fn {
                continue;
            }
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: item_impl.impl_token.span().start().line,
                function_name: String::new(),
                description: format!(
                    "`impl {self_name}` has public methods but is missing `#[contractimpl]`. \
                     These methods will not be exposed as contract entrypoints."
                ),
            });
        }
        out
    }
}

fn impl_self_type_name(ty: &Type) -> String {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_impl_without_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, Env};
#[contract]
pub struct MyContract;
impl MyContract {
    pub fn hello(env: Env) { let _ = env; }
}
"#,
        )?;
        let hits = MissingContractimplCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("MyContract"));
        Ok(())
    }

    #[test]
    fn no_finding_when_contractimpl_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract]
pub struct MyContract;
#[contractimpl]
impl MyContract {
    pub fn hello(env: Env) { let _ = env; }
}
"#,
        )?;
        let hits = MissingContractimplCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_non_contract_struct() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;
pub struct Helper;
impl Helper {
    pub fn do_thing(env: Env) { let _ = env; }
}
"#,
        )?;
        let hits = MissingContractimplCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_when_only_private_fns() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, Env};
#[contract]
pub struct MyContract;
impl MyContract {
    fn internal(env: Env) { let _ = env; }
}
"#,
        )?;
        let hits = MissingContractimplCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
