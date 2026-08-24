//! Detects `decimals()` returning a hardcoded literal while other functions in the
//! same contract use hardcoded divisor/multiplier literals inconsistent with it.
//!
//! Off-chain clients rely on `decimals()` to scale balances. If the declared value
//! disagrees with the scaling constants used in arithmetic, displayed balances will
//! be wrong.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, File, Lit, Stmt};

const CHECK_NAME: &str = "decimals-mismatch";

pub struct DecimalsMismatchCheck;

impl Check for DecimalsMismatchCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let methods: Vec<_> = contractimpl_functions(file).into_iter().collect();

        // Find `decimals()` returning a literal integer.
        let declared = methods.iter().find_map(|m| {
            if m.sig.ident != "decimals" {
                return None;
            }
            // Only consider functions with no meaningful parameters (just Env).
            let param_count = m.sig.inputs.len();
            if param_count > 1 {
                return None;
            }
            extract_single_literal_return(&m.block)
        });

        let declared_decimals = match declared {
            Some(d) => d,
            None => return out,
        };

        // Collect all power-of-10 literals used in other functions as divisors/multipliers.
        for method in &methods {
            if method.sig.ident == "decimals" {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            let mut scan = LiteralScan::default();
            scan.visit_block(&method.block);

            for (line, lit_val) in scan.power_of_10_literals {
                // Compute implied decimals from the literal (e.g. 1_000_000 → 6).
                if let Some(implied) = implied_decimals(lit_val) {
                    if implied != declared_decimals {
                        out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line,
                            function_name: fn_name.clone(),
                            description: format!(
                                "Function `{fn_name}` uses a scaling constant `{lit_val}` \
                                 implying {implied} decimals, but `decimals()` returns \
                                 {declared_decimals}. Off-chain clients will misread balances."
                            ),
                        });
                    }
                }
            }
        }
        out
    }
}

/// Extract the single integer literal returned by a simple function body.
/// Handles `{ 7 }`, `{ return 7; }`, and `-> u32 { 7u32 }`.
fn extract_single_literal_return(block: &syn::Block) -> Option<u64> {
    // Tail expression: `{ 7 }`
    if let Some(Expr::Lit(ExprLit {
        lit: Lit::Int(i), ..
    })) = block.stmts.iter().find_map(|s| {
        if let Stmt::Expr(e, _) = s {
            Some(e)
        } else {
            None
        }
    }) {
        return i.base10_parse::<u64>().ok();
    }
    // `return 7;`
    for stmt in &block.stmts {
        if let Stmt::Expr(Expr::Return(r), _) = stmt {
            if let Some(Expr::Lit(ExprLit {
                lit: Lit::Int(i), ..
            })) = r.expr.as_deref()
            {
                return i.base10_parse::<u64>().ok();
            }
        }
    }
    None
}

/// Return the number of decimal places implied by a power-of-10 literal.
fn implied_decimals(val: u64) -> Option<u64> {
    if val == 0 {
        return None;
    }
    let mut v = val;
    let mut exp = 0u64;
    while v.is_multiple_of(10) {
        v /= 10;
        exp += 1;
    }
    if v == 1 && exp > 0 {
        Some(exp)
    } else {
        None
    }
}

#[derive(Default)]
struct LiteralScan {
    /// (line, value) for each power-of-10 integer literal found.
    power_of_10_literals: Vec<(usize, u64)>,
}

impl<'ast> Visit<'ast> for LiteralScan {
    fn visit_expr_lit(&mut self, i: &'ast ExprLit) {
        if let Lit::Int(n) = &i.lit {
            if let Ok(val) = n.base10_parse::<u64>() {
                if implied_decimals(val).is_some() {
                    self.power_of_10_literals.push((i.span().start().line, val));
                }
            }
        }
        visit::visit_expr_lit(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_mismatch_between_decimals_and_divisor() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn decimals(_env: Env) -> u32 { 7 }
    pub fn balance(env: Env, addr: Address) -> i128 {
        let raw: i128 = env.storage().instance().get(&addr).unwrap_or(0);
        raw / 1_000_000  // implies 6 decimals, but decimals() says 7
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = DecimalsMismatchCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_consistent() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn decimals(_env: Env) -> u32 { 7 }
    pub fn balance(env: Env, addr: Address) -> i128 {
        let raw: i128 = env.storage().instance().get(&addr).unwrap_or(0);
        raw / 10_000_000  // implies 7 decimals — matches
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = DecimalsMismatchCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn no_decimals_fn_no_finding() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn balance(env: Env, addr: Address) -> i128 {
        let raw: i128 = env.storage().instance().get(&addr).unwrap_or(0);
        raw / 1_000_000
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = DecimalsMismatchCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
