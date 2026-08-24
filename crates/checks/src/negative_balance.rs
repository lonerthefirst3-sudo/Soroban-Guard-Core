//! i128 subtraction result stored without underflow guard.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Block, Expr, ExprBinary, ExprMethodCall, File};

const CHECK_NAME: &str = "negative-balance";

/// Flags `BinOp::Sub` expressions in `#[contractimpl]` functions where the result
/// is passed directly to `env.storage()...set(...)` without a preceding `>=` or `>`
/// comparison involving the same operands.
pub struct NegativeBalanceCheck;

impl Check for NegativeBalanceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = SubtractionVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_storage_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"),
        Expr::Field(f) => {
            let member_str = match &f.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(idx) => idx.index.to_string(),
            };
            format!("{}.{}", expr_to_string(&f.base), member_str)
        }
        _ => String::new(),
    }
}



struct SubtractionVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for SubtractionVisitor<'ast> {
    fn visit_block(&mut self, i: &'ast Block) {
        // Only process the top-level block, not nested blocks
        // Collect all comparisons in this block and nested blocks
        let mut comp_finder = AllComparisonsFinder {
            comparisons: Vec::new(),
        };
        comp_finder.visit_block(i);

        // Check each statement for storage set calls with subtraction
        for stmt in &i.stmts {
            let mut set_finder = SetWithSubFinder {
                subs: Vec::new(),
            };
            set_finder.visit_stmt(stmt);

            for (sub_expr, line) in set_finder.subs {
                let left_str = expr_to_string(&sub_expr.left);
                let right_str = expr_to_string(&sub_expr.right);
                
                // Check if there's a matching comparison anywhere in the function
                let has_guard = !left_str.is_empty() && !right_str.is_empty() && 
                    comp_finder.comparisons.iter().any(|(l, r)| {
                        (l == &left_str && r == &right_str) || (l == &right_str && r == &left_str)
                    });

                if !has_guard {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` stores the result of a subtraction directly to \
                             storage without checking that the minuend is >= the subtrahend. \
                             This can produce negative balances, allowing overdrafts.",
                            self.fn_name
                        ),
                    });
                }
            }
        }

        // Don't call visit_block recursively - we've already processed all statements
    }
}

struct AllComparisonsFinder {
    comparisons: Vec<(String, String)>,
}

impl<'ast> Visit<'ast> for AllComparisonsFinder {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Ge(_) | BinOp::Gt(_)) {
            let left_str = expr_to_string(&i.left);
            let right_str = expr_to_string(&i.right);
            if !left_str.is_empty() && !right_str.is_empty() {
                self.comparisons.push((left_str, right_str));
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

struct SetWithSubFinder {
    subs: Vec<(&'static ExprBinary, usize)>,
}

impl<'ast> Visit<'ast> for SetWithSubFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_set_call(i) {
            // Check if any argument is a subtraction
            for arg in &i.args {
                let mut sub_finder = SubFinder {
                    subs: Vec::new(),
                };
                sub_finder.visit_expr(arg);
                for (sub_expr, line) in sub_finder.subs {
                    // SAFETY: We're storing a reference to an expression from the AST.
                    // This is safe because the AST is owned by the File and lives for the
                    // duration of the check.
                    self.subs.push((unsafe { std::mem::transmute(sub_expr) }, line));
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct SubFinder {
    subs: Vec<(&'static ExprBinary, usize)>,
}

impl<'ast> Visit<'ast> for SubFinder {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Sub(_)) {
            let line = i.span().start().line;
            // SAFETY: Same as above
            self.subs.push((unsafe { std::mem::transmute(i) }, line));
        }
        visit::visit_expr_binary(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_subtraction_stored_without_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn withdraw(env: Env, amount: i128) {
        let balance: i128 = 100;
        env.storage().instance().set(&Symbol::new(&env, "bal"), &(balance - amount));
    }
}
"#,
        )?;
        let hits = NegativeBalanceCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "withdraw");
        Ok(())
    }

    #[test]
    fn passes_with_ge_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn withdraw(env: Env, amount: i128) {
        let balance: i128 = 100;
        if balance >= amount {
            env.storage().instance().set(&Symbol::new(&env, "bal"), &(balance - amount));
        }
    }
}
"#,
        )?;
        let hits = NegativeBalanceCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_with_gt_guard() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn withdraw(env: Env, amount: i128) {
        let balance: i128 = 100;
        if balance > amount {
            env.storage().instance().set(&Symbol::new(&env, "bal"), &(balance - amount));
        }
    }
}
"#,
        )?;
        let hits = NegativeBalanceCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

impl C {
    pub fn withdraw(env: Env, amount: i128) {
        let balance: i128 = 100;
        env.storage().instance().set(&Symbol::new(&env, "bal"), &(balance - amount));
    }
}
"#,
        )?;
        let hits = NegativeBalanceCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
