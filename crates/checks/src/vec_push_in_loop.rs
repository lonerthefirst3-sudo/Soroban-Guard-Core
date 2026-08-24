//! `push_back` on a `soroban_sdk::Vec` inside a loop without a length guard.
//!
//! Calling `push_back` inside a loop driven by user-controlled input without a
//! `len()` / `size` comparison guard causes unbounded memory growth in the
//! Soroban host, which can exhaust the contract's resource budget and cause DoS.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ExprForLoop, ExprLoop, ExprMethodCall, ExprWhile, File};

const CHECK_NAME: &str = "vec-push-in-loop";

/// Returns true if the block contains a `len()` or `size()` method call,
/// indicating a length guard is present.
fn block_has_len_guard(block: &Block) -> bool {
    struct LenFinder(bool);
    impl<'ast> Visit<'ast> for LenFinder {
        fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
            if matches!(i.method.to_string().as_str(), "len" | "size") {
                self.0 = true;
            }
            visit::visit_expr_method_call(self, i);
        }
    }
    let mut f = LenFinder(false);
    f.visit_block(block);
    f.0
}

struct PushInLoopVisitor<'a> {
    fn_name: String,
    /// Stack of loop body blocks; each entry records whether that loop body
    /// contains a len guard.
    loop_stack: Vec<bool>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for PushInLoopVisitor<'ast> {
    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        self.loop_stack.push(block_has_len_guard(&i.body));
        visit::visit_expr_for_loop(self, i);
        self.loop_stack.pop();
    }

    fn visit_expr_while(&mut self, i: &'ast ExprWhile) {
        self.loop_stack.push(block_has_len_guard(&i.body));
        visit::visit_expr_while(self, i);
        self.loop_stack.pop();
    }

    fn visit_expr_loop(&mut self, i: &'ast ExprLoop) {
        self.loop_stack.push(block_has_len_guard(&i.body));
        visit::visit_expr_loop(self, i);
        self.loop_stack.pop();
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "push_back" {
            // Only flag if we are inside at least one loop that has no len guard.
            let unguarded = self.loop_stack.iter().any(|guarded| !guarded);
            if unguarded {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "`push_back` is called inside a loop in `{}` without a `len()` guard. \
                         Unbounded growth exhausts the Soroban host resource budget and can \
                         cause a DoS. Add a maximum-length check before pushing.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct VecPushInLoopCheck;

impl Check for VecPushInLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = PushInLoopVisitor {
                fn_name,
                loop_stack: Vec::new(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_push_back_in_for_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn collect(env: Env, items: Vec<u32>, extra: u32) {
        let mut out: Vec<u32> = Vec::new(&env);
        for item in items {
            out.push_back(item);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecPushInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_push_back_in_while_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn fill(env: Env, n: u32) {
        let mut v: Vec<u32> = Vec::new(&env);
        let mut i = 0u32;
        while i < n {
            v.push_back(i);
            i += 1;
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecPushInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn no_finding_when_len_guard_present() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
const MAX: u32 = 100;
#[contractimpl]
impl C {
    pub fn collect(env: Env, items: Vec<u32>) {
        let mut out: Vec<u32> = Vec::new(&env);
        for item in items {
            if out.len() >= MAX { break; }
            out.push_back(item);
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecPushInLoopCheck.run(&file, "");
        assert!(hits.is_empty(), "{hits:?}");
        Ok(())
    }

    #[test]
    fn no_finding_outside_loop() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn add_one(env: Env, val: u32) {
        let mut v: Vec<u32> = Vec::new(&env);
        v.push_back(val);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecPushInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_push_back_in_loop_block() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn run(env: Env, n: u32) {
        let mut v: Vec<u32> = Vec::new(&env);
        let mut i = 0u32;
        loop {
            if i >= n { break; }
            v.push_back(i);
            i += 1;
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecPushInLoopCheck.run(&file, "");
        // loop body has no len() call, so it should be flagged
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
