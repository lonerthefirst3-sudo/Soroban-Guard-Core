//! Detects storage key prefix collisions between distinct data domains.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "key-prefix-collision";

/// Flags pairs of string-literal keys where one is a prefix of another.
pub struct KeyPrefixCollisionCheck;

impl Check for KeyPrefixCollisionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = KeyVisitor {
                fn_name: fn_name.clone(),
                keys: Vec::new(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn extract_string_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(l) => {
            if let Lit::Str(s) = &l.lit {
                Some(s.value())
            } else {
                None
            }
        }
        Expr::Reference(r) => extract_string_literal(&r.expr),
        _ => None,
    }
}

fn is_storage_key_call(m: &ExprMethodCall) -> bool {
    matches!(
        m.method.to_string().as_str(),
        "set" | "get" | "has" | "remove"
    )
}

struct KeyVisitor<'a> {
    fn_name: String,
    keys: Vec<(String, usize)>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for KeyVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_key_call(i) {
            if let Some(arg) = i.args.first() {
                if let Some(key) = extract_string_literal(arg) {
                    let line = i.span().start().line;

                    for (existing_key, existing_line) in &self.keys {
                        if key != *existing_key
                            && (key.starts_with(existing_key) || existing_key.starts_with(&key))
                        {
                            self.out.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::Medium,
                                    file_path: String::new(),
                                    line,
                                    function_name: self.fn_name.clone(),
                                    description: format!(
                                        "Storage key prefix collision detected in `{}`: \
                                         \"{}\" (line {}) and \"{}\" (line {}). \
                                         One key is a prefix of the other, which can cause collisions \
                                         with partial key matching. Use clearly separated namespaces.",
                                        self.fn_name, existing_key, existing_line, key, line
                                    ),
                                });
                        }
                    }

                    self.keys.push((key, line));
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

    #[test]
    fn flags_prefix_collision() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().persistent().set(&"balance", &100u32);
        env.storage().persistent().set(&"balance_locked", &50u32);
    }
}
"#,
        )?;
        let hits = KeyPrefixCollisionCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("prefix collision"));
        Ok(())
    }

    #[test]
    fn passes_distinct_keys() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().persistent().set(&"balance", &100u32);
        env.storage().persistent().set(&"owner", &"addr");
    }
}
"#,
        )?;
        let hits = KeyPrefixCollisionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_reverse_prefix() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().persistent().set(&"user_data_extra", &100u32);
        env.storage().persistent().set(&"user_data", &50u32);
    }
}
"#,
        )?;
        let hits = KeyPrefixCollisionCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_same_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().persistent().set(&"balance", &100u32);
        env.storage().persistent().get(&"balance");
    }
}
"#,
        )?;
        let hits = KeyPrefixCollisionCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
