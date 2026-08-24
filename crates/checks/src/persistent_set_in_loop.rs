//! Persistent storage set() inside loops without extend_ttl.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "persistent-set-in-loop";

/// Flags `env.storage().persistent().set(...)` calls inside loop bodies
/// that are not accompanied by an `extend_ttl` call in the same loop body.
pub struct PersistentSetInLoopCheck;

impl Check for PersistentSetInLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = LoopVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
                in_loop: false,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "persistent" {
                return true;
            }
            receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

fn is_persistent_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_persistent(&m.receiver)
}

fn is_persistent_extend_ttl_call(m: &ExprMethodCall) -> bool {
    m.method == "extend_ttl" && receiver_chain_contains_persistent(&m.receiver)
}

struct LoopVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
    in_loop: bool,
}

impl<'ast> Visit<'ast> for LoopVisitor<'ast> {
    fn visit_block(&mut self, i: &'ast Block) {
        if self.in_loop {
            // We're already in a loop; check for set/extend_ttl in this block
            let mut has_set = false;
            let mut has_extend_ttl = false;

            for stmt in &i.stmts {
                let mut stmt_visitor = StmtVisitor {
                    has_set: &mut has_set,
                    has_extend_ttl: &mut has_extend_ttl,
                };
                stmt_visitor.visit_stmt(stmt);
            }

            if has_set && !has_extend_ttl {
                // Find the line of the first set call
                for stmt in &i.stmts {
                    let mut line_finder = FirstSetLineFinder { line: None };
                    line_finder.visit_stmt(stmt);
                    if let Some(line) = line_finder.line {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` calls `env.storage().persistent().set()` inside a \
                                 loop without calling `extend_ttl()` in the same loop body. \
                                 Each persistent write should be paired with `extend_ttl()` to \
                                 ensure consistent TTL across entries.",
                                self.fn_name
                            ),
                        });
                        break;
                    }
                }
            }
        }

        // Visit loop bodies with in_loop = true
        let was_in_loop = self.in_loop;
        for stmt in &i.stmts {
            match stmt {
                Stmt::Expr(Expr::ForLoop(fl), _) => {
                    self.in_loop = true;
                    self.visit_block(&fl.body);
                    self.in_loop = was_in_loop;
                }
                Stmt::Expr(Expr::While(wl), _) => {
                    self.in_loop = true;
                    self.visit_block(&wl.body);
                    self.in_loop = was_in_loop;
                }
                Stmt::Expr(Expr::Loop(l), _) => {
                    self.in_loop = true;
                    self.visit_block(&l.body);
                    self.in_loop = was_in_loop;
                }
                _ => {
                    self.visit_stmt(stmt);
                }
            }
        }
    }
}

struct StmtVisitor<'a> {
    has_set: &'a mut bool,
    has_extend_ttl: &'a mut bool,
}

impl<'ast> Visit<'ast> for StmtVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_persistent_set_call(i) {
            *self.has_set = true;
        }
        if is_persistent_extend_ttl_call(i) {
            *self.has_extend_ttl = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct FirstSetLineFinder {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstSetLineFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_persistent_set_call(i) {
            self.line = Some(i.span().start().line);
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
    fn flags_persistent_set_in_for_loop_without_extend_ttl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn batch_set(env: Env, keys: Vec<Symbol>, values: Vec<u32>) {
        for i in 0..keys.len() {
            env.storage().persistent().set(&keys[i], &values[i]);
        }
    }
}
"#,
        )?;
        let hits = PersistentSetInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "batch_set");
        Ok(())
    }

    #[test]
    fn passes_when_extend_ttl_present_in_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn batch_set(env: Env, keys: Vec<Symbol>, values: Vec<u32>) {
        for i in 0..keys.len() {
            env.storage().persistent().set(&keys[i], &values[i]);
            env.storage().persistent().extend_ttl(&keys[i], 100, 200);
        }
    }
}
"#,
        )?;
        let hits = PersistentSetInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_persistent_set_in_while_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn loop_set(env: Env, key: Symbol, value: u32) {
        let mut i = 0;
        while i < 10 {
            env.storage().persistent().set(&key, &value);
            i += 1;
        }
    }
}
"#,
        )?;
        let hits = PersistentSetInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_persistent_set_outside_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_once(env: Env, key: Symbol, value: u32) {
        env.storage().persistent().set(&key, &value);
    }
}
"#,
        )?;
        let hits = PersistentSetInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
