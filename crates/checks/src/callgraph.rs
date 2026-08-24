//! Call graph for analyzing interprocedural control flow.
//!
//! This module provides a file-local call graph that enables checks to see function calls
//! across procedure boundaries. It resolves direct function calls and method calls from raw
//! `syn` AST without type information.
//!
//! # Limitations
//!
//! - **No trait resolution**: Calls through trait objects (`dyn Trait`), generics, or `Box<dyn Fn>` are not resolved.
//! - **No external crate calls**: Only resolves calls to functions defined in this file.
//! - **Method calls limited**: Only self-method calls (`self.helper()`) are resolved, not calls on other values.
//! - **No recursive loop detection in individual checks**: Recursive functions are handled (BFS/DFS track visited), but checks must guard against infinite loops if they traverse the graph multiple times per function.

use std::collections::{HashMap, HashSet, VecDeque};
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprCall, ExprMethodCall, File, ImplItem, Item};

/// A file-local call graph mapping function names to the functions they directly call.
pub struct CallGraph {
    edges: HashMap<String, Vec<String>>,
}

impl CallGraph {
    /// Build a call graph from a parsed file.
    ///
    /// Collects every function defined in the file (free `fn` items and `ImplItem::Fn` in all `impl` blocks)
    /// and records edges for direct function calls and self-method calls.
    pub fn build(file: &File) -> Self {
        let registry = collect_fn_registry(file);
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();

        for (name, block) in &registry {
            let mut scanner = CallScanner::new(&registry);
            scanner.visit_block(block);
            let callees: Vec<String> = scanner.calls.into_iter().collect();
            edges.insert(name.clone(), callees);
        }

        CallGraph { edges }
    }

    /// Return all functions transitively reachable from `start`, including `start` itself.
    ///
    /// Uses BFS to traverse the call graph, stopping at functions not in the registry (external calls).
    /// Guards against infinite loops in recursive/mutually-recursive functions by tracking visited nodes.
    pub fn reachable_from(&self, start: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(start.to_string());
        queue.push_back(start.to_string());

        while let Some(name) = queue.pop_front() {
            if let Some(callees) = self.edges.get(&name) {
                for callee in callees {
                    if self.edges.contains_key(callee) && visited.insert(callee.clone()) {
                        queue.push_back(callee.clone());
                    }
                }
            }
        }

        visited
    }

    /// Return the direct callees of a function, or None if the function is not in the graph.
    pub fn direct_callees(&self, name: &str) -> Option<&Vec<String>> {
        self.edges.get(name)
    }

    /// Check if there is an edge from `from` to `to`.
    pub fn has_edge(&self, from: &str, to: &str) -> bool {
        self.edges
            .get(from)
            .map(|callees| callees.contains(&to.to_string()))
            .unwrap_or(false)
    }
}

/// Collect every function defined in this file: free `fn` items and all `ImplItem::Fn` in any `impl` block.
fn collect_fn_registry(file: &File) -> HashMap<String, &Block> {
    let mut registry = HashMap::new();
    for item in &file.items {
        match item {
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(f) = impl_item {
                        registry.insert(f.sig.ident.to_string(), &f.block);
                    }
                }
            }
            Item::Fn(f) => {
                registry.insert(f.sig.ident.to_string(), &f.block);
            }
            _ => {}
        }
    }
    registry
}

/// Walk a function body and record edges to directly called functions.
struct CallScanner {
    /// Functions known to exist in the file.
    fn_registry: HashSet<String>,
    /// Functions called from this function body (deduplicated).
    calls: HashSet<String>,
}

impl CallScanner {
    fn new(registry: &HashMap<String, &Block>) -> Self {
        CallScanner {
            fn_registry: registry.keys().cloned().collect(),
            calls: HashSet::new(),
        }
    }
}

impl<'ast> Visit<'ast> for CallScanner {
    fn visit_expr_call(&mut self, i: &'ast ExprCall) {
        if let Expr::Path(p) = &*i.func {
            if let Some(seg) = p.path.segments.last() {
                let name = seg.ident.to_string();
                if self.fn_registry.contains(&name) {
                    self.calls.insert(name);
                }
            }
        }
        visit::visit_expr_call(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if let Expr::Path(p) = &*i.receiver {
            if p.path.is_ident("self") {
                let method_name = i.method.to_string();
                if self.fn_registry.contains(&method_name) {
                    self.calls.insert(method_name);
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn builds_simple_call_graph() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn caller() {
    callee();
}

fn callee() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        assert!(graph.has_edge("caller", "callee"));
        assert!(!graph.has_edge("callee", "caller"));
        Ok(())
    }

    #[test]
    fn reachable_from_single_hop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn a() {
    b();
}

fn b() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert_eq!(reachable.len(), 2);
        Ok(())
    }

    #[test]
    fn reachable_from_multi_hop_chain() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn a() {
    b();
}

fn b() {
    c();
}

fn c() {
    d();
}

fn d() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert!(reachable.contains("c"));
        assert!(reachable.contains("d"));
        assert_eq!(reachable.len(), 4);
        Ok(())
    }

    #[test]
    fn handles_mutual_recursion() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn a() {
    b();
}

fn b() {
    a();
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert_eq!(reachable.len(), 2);
        Ok(())
    }

    #[test]
    fn handles_self_recursion() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn fib(n: i32) {
    if n > 1 {
        fib(n - 1);
        fib(n - 2);
    }
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("fib");
        assert!(reachable.contains("fib"));
        assert_eq!(reachable.len(), 1);
        Ok(())
    }

    #[test]
    fn resolves_self_method_calls_in_impl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct Contract;

impl Contract {
    pub fn public_method(&self) {
        self.helper();
    }

    fn helper(&self) {
    }
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        assert!(graph.has_edge("public_method", "helper"));
        Ok(())
    }

    #[test]
    fn ignores_calls_to_external_functions() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn my_fn() {
    external_fn();
    my_other_fn();
}

fn my_other_fn() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let direct_calls = graph.direct_callees("my_fn").unwrap();
        assert!(direct_calls.contains(&"my_other_fn".to_string()));
        assert!(!direct_calls.contains(&"external_fn".to_string()));
        Ok(())
    }

    #[test]
    fn multi_impl_blocks() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct Contract;

impl Contract {
    pub fn public_method(&self) {
        self.helper_a();
    }

    fn helper_a(&self) {
        self.helper_b();
    }
}

impl Contract {
    fn helper_b(&self) {
    }
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("public_method");
        assert!(reachable.contains("public_method"));
        assert!(reachable.contains("helper_a"));
        assert!(reachable.contains("helper_b"));
        Ok(())
    }

    #[test]
    fn diamond_dependency() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn a() {
    b();
    c();
}

fn b() {
    d();
}

fn c() {
    d();
}

fn d() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("a");
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert!(reachable.contains("c"));
        assert!(reachable.contains("d"));
        assert_eq!(reachable.len(), 4);
        Ok(())
    }

    #[test]
    fn ignores_non_self_method_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
pub struct Contract;

impl Contract {
    pub fn public_method(&self) {
        let other = Contract;
        other.helper();
    }

    fn helper(&self) {
    }
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let direct_calls = graph.direct_callees("public_method").unwrap();
        assert!(!direct_calls.contains(&"helper".to_string()));
        Ok(())
    }

    #[test]
    fn reachable_from_nonexistent_function() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn a() {
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("nonexistent");
        assert!(reachable.contains("nonexistent"));
        assert_eq!(reachable.len(), 1);
        Ok(())
    }

    #[test]
    fn collects_all_functions() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
fn free_fn() {
}

pub struct Contract;

impl Contract {
    pub fn public_method(&self) {
    }

    fn private_method(&self) {
    }
}

impl Display for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
    }
}
"#,
        )?;
        let graph = CallGraph::build(&file);
        let reachable = graph.reachable_from("free_fn");
        assert!(graph.direct_callees("free_fn").is_some());
        assert!(graph.direct_callees("public_method").is_some());
        assert!(graph.direct_callees("private_method").is_some());
        Ok(())
    }
}
