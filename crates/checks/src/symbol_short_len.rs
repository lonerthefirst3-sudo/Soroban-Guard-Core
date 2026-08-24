//! Detects symbol_short! macro used with strings longer than 9 characters.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMacro, File};

const CHECK_NAME: &str = "symbol-short-len";

/// Flags `symbol_short!(s)` macro invocations where the string literal `s` has length > 9.
pub struct SymbolShortLenCheck;

impl Check for SymbolShortLenCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let mut visitor = SymbolShortVisitor { out: &mut out };
        visitor.visit_file(file);
        out
    }
}

struct SymbolShortVisitor<'a> {
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for SymbolShortVisitor<'a> {
    fn visit_expr_macro(&mut self, i: &ExprMacro) {
        if let Some(last_seg) = i.mac.path.segments.last() {
            if last_seg.ident == "symbol_short" {
                if let Some(len) = extract_string_len_from_macro(&i.mac.tokens) {
                    if len > 9 {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: String::new(),
                            description: format!(
                                "`symbol_short!` macro invocation uses a string of length {}. \
                                 `symbol_short!` only supports strings up to 9 characters. \
                                 Longer strings cause compile-time panic in debug builds and \
                                 undefined behavior in release builds.",
                                len
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_macro(self, i);
    }
}

fn extract_string_len_from_macro(tokens: &proc_macro2::TokenStream) -> Option<usize> {
    let mut iter = tokens.clone().into_iter();
    while let Some(token) = iter.next() {
        match token {
            proc_macro2::TokenTree::Literal(lit) => {
                let lit_str = lit.to_string();
                if lit_str.starts_with('"') && lit_str.ends_with('"') {
                    let content = &lit_str[1..lit_str.len() - 1];
                    return Some(content.len());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_symbol_short_too_long() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn test(env: Env) {
        let _ = symbol_short!("toolongkey");
    }
}
"#,
        )?;
        let hits = SymbolShortLenCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_symbol_short_valid_length() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn test(env: Env) {
        let _ = symbol_short!("key");
    }
}
"#,
        )?;
        let hits = SymbolShortLenCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_symbol_short_exactly_9_chars() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn test(env: Env) {
        let _ = symbol_short!("123456789");
    }
}
"#,
        )?;
        let hits = SymbolShortLenCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
