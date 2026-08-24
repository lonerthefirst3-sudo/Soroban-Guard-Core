//! Detects large hardcoded byte arrays passed to `Bytes::from_slice` / `Bytes::from_array`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprArray, ExprCall, ExprLit, ExprMethodCall, ExprReference, File, Lit};

const CHECK_NAME: &str = "hardcoded-bytes";

pub struct HardcodedBytesCheck;

impl Check for HardcodedBytesCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = BytesVisitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct BytesVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for BytesVisitor<'a> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        if is_hardcoded_bytes_constructor(i) {
            if let Some(len) = hardcoded_array_len(i) {
                if len > 32 {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "`Bytes::from_slice` or `Bytes::from_array` in `{}` uses a hardcoded byte array with {} elements. Store large constants in contract storage or pass them as parameters instead of embedding them in contract logic.",
                            self.fn_name,
                            len
                        ),
                    });
                }
            }
        }
        visit::visit_expr_call(self, i);
    }
}

fn is_hardcoded_bytes_constructor(call: &ExprCall) -> bool {
    let Expr::Path(path) = &*call.func else {
        return false;
    };
    let segs = &path.path.segments;
    if segs.len() != 2 {
        return false;
    }
    let mut iter = segs.iter();
    let first = iter.next().unwrap();
    let second = iter.next().unwrap();
    if first.ident != "Bytes" {
        return false;
    }
    matches!(second.ident.to_string().as_str(), "from_slice" | "from_array")
}

fn hardcoded_array_len(call: &ExprCall) -> Option<usize> {
    let Some(arg2) = call.args.iter().nth(1) else {
        return None;
    };
    let Expr::Reference(reference) = arg2 else {
        return None;
    };
    let Expr::Array(array) = &*reference.expr else {
        return None;
    };
    Some(array.elems.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(HardcodedBytesCheck.run(&file, src))
    }

    #[test]
    fn flags_large_hardcoded_bytes_array() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Bytes, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let _ = Bytes::from_slice(&env, &[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn does_not_flag_32_byte_array() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Bytes, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let _ = Bytes::from_array(&env, &[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
