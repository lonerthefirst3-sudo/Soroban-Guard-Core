//! Detects same logical key written to multiple storage tiers.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "mixed-storage-tiers";

/// Flags functions where the same string literal key is passed to `set`/`get` on
/// more than one storage tier (`persistent`, `instance`, `temporary`).
pub struct MixedStorageTiersCheck;

impl Check for MixedStorageTiersCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = StorageTierVisitor {
                fn_name: fn_name.clone(),
                key_tiers: HashMap::new(),
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct StorageTierVisitor<'a> {
    fn_name: String,
    key_tiers: HashMap<String, Vec<(String, usize)>>, // key -> [(tier, line), ...]
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for StorageTierVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        let method_name = i.method.to_string();
        if matches!(method_name.as_str(), "set" | "get" | "remove") {
            if let Some((tier, key)) = extract_storage_tier_and_key(&i.receiver, &i.args) {
                let line = i.span().start().line;
                self.key_tiers
                    .entry(key.clone())
                    .or_insert_with(Vec::new)
                    .push((tier, line));
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

impl<'a> Drop for StorageTierVisitor<'a> {
    fn drop(&mut self) {
        for (key, tiers) in &self.key_tiers {
            let unique_tiers: std::collections::HashSet<_> =
                tiers.iter().map(|(t, _)| t.as_str()).collect();
            if unique_tiers.len() > 1 {
                for (tier, line) in tiers {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: *line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Key `{}` is accessed via multiple storage tiers ({}). \
                             Reads from one tier will not see writes to another, causing data \
                             consistency bugs.",
                            key,
                            unique_tiers.iter().copied().collect::<Vec<_>>().join(", ")
                        ),
                    });
                }
            }
        }
    }
}

fn extract_storage_tier_and_key(
    receiver: &Expr,
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<(String, String)> {
    let tier = extract_tier_from_receiver(receiver)?;
    let key = extract_key_from_args(args)?;
    Some((tier, key))
}

fn extract_tier_from_receiver(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => {
            let method = m.method.to_string();
            if matches!(method.as_str(), "persistent" | "instance" | "temporary") {
                return Some(method);
            }
            extract_tier_from_receiver(&m.receiver)
        }
        Expr::Field(f) => extract_tier_from_receiver(&f.base),
        _ => None,
    }
}

fn extract_key_from_args(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<String> {
    args.iter().next().and_then(|arg| match arg {
        Expr::Lit(lit_expr) => match &lit_expr.lit {
            Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        Expr::Reference(r) => match &*r.expr {
            Expr::Lit(lit_expr) => match &lit_expr.lit {
                Lit::Str(s) => Some(s.value()),
                _ => None,
            },
            Expr::Path(p) => {
                // Try to extract from const references like &KEY
                p.path.segments.last().map(|s| s.ident.to_string())
            }
            _ => None,
        },
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_same_key_in_multiple_tiers() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn bad(env: Env) {
        env.storage().persistent().set("key", &1u32);
        env.storage().instance().set("key", &2u32);
    }
}
"#,
        )?;
        let hits = MixedStorageTiersCheck.run(&file, "");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_different_keys() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn good(env: Env) {
        env.storage().persistent().set("key1", &1u32);
        env.storage().instance().set("key2", &2u32);
    }
}
"#,
        )?;
        let hits = MixedStorageTiersCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_same_key_same_tier() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn good(env: Env) {
        env.storage().persistent().set("key", &1u32);
        env.storage().persistent().get("key");
    }
}
"#,
        )?;
        let hits = MixedStorageTiersCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
