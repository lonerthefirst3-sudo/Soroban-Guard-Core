//! Flags unsafe `Val` conversions on `invoke_contract` results.
//!
//! `env.invoke_contract(...)` returns a `Val`. Converting it via:
//!   - `.try_into_val(...).unwrap()` / `.expect(...)` — panics on type mismatch
//!   - `.into_val(...)` directly — silently produces wrong data on type mismatch
//!
//! Both patterns cause panics or type confusion when the callee returns unexpected data.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "val-unchecked-convert";

pub struct ValUncheckedConvertCheck;

impl Check for ValUncheckedConvertCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ValConvertVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns the conversion method name if this is an unsafe Val conversion on an invoke result.
fn unsafe_val_convert(m: &ExprMethodCall) -> Option<&'static str> {
    let method = m.method.to_string();
    match method.as_str() {
        // .try_into_val(...).unwrap() or .expect(...)
        "unwrap" | "expect" => {
            if let Expr::MethodCall(inner) = &*m.receiver {
                if inner.method == "try_into_val" && receiver_is_invoke(&inner.receiver) {
                    return Some("try_into_val");
                }
            }
            None
        }
        // .into_val(...) directly on invoke result — infallible cast, type confusion
        "into_val" if receiver_is_invoke(&m.receiver) => Some("into_val"),
        _ => None,
    }
}

fn receiver_is_invoke(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "invoke_contract" || receiver_is_invoke(&m.receiver),
        _ => false,
    }
}

struct ValConvertVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ValConvertVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if let Some(conv) = unsafe_val_convert(i) {
            let detail = if conv == "into_val" {
                format!(
                    "`{}` calls `.into_val()` directly on an `invoke_contract` result. \
                     An unexpected return type causes silent type confusion. \
                     Use `.try_into_val()` and handle the `Result` explicitly.",
                    self.fn_name
                )
            } else {
                format!(
                    "`{}` calls `.try_into_val().unwrap()` on an `invoke_contract` result. \
                     A type mismatch will panic at runtime. \
                     Use `match` or `?` to handle the conversion error.",
                    self.fn_name
                )
            };
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: detail,
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        ValUncheckedConvertCheck.run(&parse_file(src).unwrap(), src)
    }

    const PRELUDE: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val};
#[contract] pub struct C;
#[contractimpl]
impl C {
"#;

    #[test]
    fn flags_try_into_val_unwrap() {
        let src = format!(
            "{PRELUDE}    pub fn f(env: Env, c: Address) -> i128 {{\
             env.invoke_contract::<Val>(&c, &Symbol::short(\"g\"), soroban_sdk::vec![&env]).try_into_val(&env).unwrap() }}\n}}"
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert!(hits[0].description.contains("try_into_val"));
    }

    #[test]
    fn flags_try_into_val_expect() {
        let src = format!(
            "{PRELUDE}    pub fn f(env: Env, c: Address) -> i128 {{\
             env.invoke_contract::<Val>(&c, &Symbol::short(\"g\"), soroban_sdk::vec![&env]).try_into_val(&env).expect(\"bad\") }}\n}}"
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("try_into_val"));
    }

    #[test]
    fn flags_into_val_direct() {
        let src = format!(
            "{PRELUDE}    pub fn f(env: Env, c: Address) -> i128 {{\
             env.invoke_contract::<Val>(&c, &Symbol::short(\"g\"), soroban_sdk::vec![&env]).into_val(&env) }}\n}}"
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("into_val()"));
    }

    #[test]
    fn passes_try_into_val_match() {
        let src = format!(
            "{PRELUDE}    pub fn f(env: Env, c: Address) -> Option<i128> {{\
             match env.invoke_contract::<Val>(&c, &Symbol::short(\"g\"), soroban_sdk::vec![&env]).try_into_val(&env) {{\
             Ok(v) => Some(v), Err(_) => None }} }}\n}}"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn passes_try_into_val_question_mark() {
        let src = format!(
            "{PRELUDE}    pub fn f(env: Env, c: Address) -> Result<i128, soroban_sdk::Error> {{\
             let v: i128 = env.invoke_contract::<Val>(&c, &Symbol::short(\"g\"), soroban_sdk::vec![&env]).try_into_val(&env)?;\
             Ok(v) }}\n}}"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let src = r#"
use soroban_sdk::{Address, Env, Symbol, Val};
pub struct C;
impl C {
    pub fn f(env: Env, c: Address) -> i128 {
        env.invoke_contract::<Val>(&c, &Symbol::short("g"), soroban_sdk::vec![&env]).try_into_val(&env).unwrap()
    }
}
"#;
        assert!(run(src).is_empty());
    }
}
