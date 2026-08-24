//! Withdrawal aggregate bypass static check.
//! Matches when a per-call periodic limit is imposed via a guard/assertion
//! but no accumulator/timestamp state is read/written to store the usage over time.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{File, ImplItem, Item};

use std::collections::{HashMap, HashSet, VecDeque};

const CHECK_NAME: &str = "withdrawal-aggregate-bypass";

pub struct WithdrawalAggregateBypassCheck;

impl Check for WithdrawalAggregateBypassCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Collect all defined functions in the file
        let mut defined_fns = HashMap::new();
        for item in &file.items {
            if let Item::Impl(item_impl) = item {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(m) = impl_item {
                        let name = m.sig.ident.to_string();
                        defined_fns.insert(name, (&m.block, &m.sig));
                    }
                }
            } else if let Item::Fn(f) = item {
                let name = f.sig.ident.to_string();
                defined_fns.insert(name, (&f.block, &f.sig));
            }
        }

        // 2. Build direct call map and accumulator check map
        let mut call_map = HashMap::new();
        let mut touches_accum = HashMap::new();

        let defined_names: HashSet<String> = defined_fns.keys().cloned().collect();

        for (name, (block, _sig)) in &defined_fns {
            let mut visitor = CallVisitor {
                defined_fns: defined_names.clone(),
                calls: HashSet::new(),
                touches_storage_accumulator: false,
            };
            visitor.visit_block(block);
            call_map.insert(name.clone(), visitor.calls);
            touches_accum.insert(name.clone(), visitor.touches_storage_accumulator);
        }

        // 3. Inspect contractimpl entrypoints for periodic caps
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Gather parameter names
            let params = get_param_names(&method.sig);
            if params.is_empty() {
                continue;
            }

            // Check if there is a periodic keyword in the function context
            let mut context_scanner = PeriodicContextScanner { found: false };
            context_scanner.visit_block(&method.block);
            let has_periodic_context = is_periodic_name(&fn_name) || context_scanner.found;

            if !has_periodic_context {
                continue;
            }

            // Check for per-call amount cap compared to parameters
            let mut cap_detector = CapDetector {
                params: &params,
                found_cap: false,
            };
            cap_detector.visit_block(&method.block);

            if !cap_detector.found_cap {
                continue;
            }

            // 4. Trace reachable call graph
            let mut reachable = HashSet::new();
            let mut queue = VecDeque::new();
            queue.push_back(fn_name.clone());
            reachable.insert(fn_name.clone());

            while let Some(current) = queue.pop_front() {
                if let Some(calls) = call_map.get(&current) {
                    for callee in calls {
                        if !reachable.contains(callee) {
                            reachable.insert(callee.clone());
                            queue.push_back(callee.clone());
                        }
                    }
                }
            }

            // 5. Verify if any reachable function touches an accumulator
            let mut touches_any_accum = false;
            for r_name in &reachable {
                if *touches_accum.get(r_name).unwrap_or(&false) {
                    touches_any_accum = true;
                    break;
                }
            }

            if !touches_any_accum {
                findings.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: method.sig.ident.span().start().line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` enforces a periodic per-call amount limit but does not read or update \
                         any time-windowed accumulator or timestamp storage key in its call graph. \
                         This allows an attacker to bypass the limit by making multiple calls."
                    ),
                });
            }
        }

        findings
    }
}

fn is_periodic_name(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    s_lower.contains("daily")
        || s_lower.contains("weekly")
        || s_lower.contains("per_period")
        || s_lower.contains("rate_limit")
        || s_lower.contains("per_week")
        || s_lower.contains("per_day")
        || s_lower.contains("limit_period")
        || s_lower.contains("period_limit")
}

fn is_accumulator_name(s: &str) -> bool {
    let s_lower = s.to_lowercase();
    s_lower.contains("total")
        || s_lower.contains("window")
        || s_lower.contains("timestamp")
        || s_lower.contains("time")
        || s_lower.contains("count")
        || s_lower.contains("accum")
        || s_lower.contains("period_start")
        || s_lower.contains("last_withdraw")
        || s_lower.contains("last_call")
}

fn get_param_names(sig: &syn::Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                names.insert(pat_ident.ident.to_string());
            }
        }
    }
    names
}

struct PeriodicContextScanner {
    found: bool,
}

impl<'ast> Visit<'ast> for PeriodicContextScanner {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if is_periodic_name(&ident.to_string()) {
            self.found = true;
        }
    }
    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        if is_periodic_name(&lit.value()) {
            self.found = true;
        }
    }
}

fn references_param(expr: &syn::Expr, params: &HashSet<String>) -> bool {
    struct ParamScanner<'a> {
        params: &'a HashSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for ParamScanner<'_> {
        fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
            if let Some(ident) = i.path.get_ident() {
                if self.params.contains(&ident.to_string()) {
                    self.found = true;
                }
            }
        }
    }
    let mut s = ParamScanner { params, found: false };
    s.visit_expr(expr);
    s.found
}

fn is_comparison_with_param(expr: &syn::Expr, params: &HashSet<String>) -> bool {
    match expr {
        syn::Expr::Binary(bin) => {
            if matches!(
                bin.op,
                syn::BinOp::Lt(_)
                    | syn::BinOp::Le(_)
                    | syn::BinOp::Gt(_)
                    | syn::BinOp::Ge(_)
                    | syn::BinOp::Eq(_)
                    | syn::BinOp::Ne(_)
            ) {
                references_param(&bin.left, params) || references_param(&bin.right, params)
            } else {
                false
            }
        }
        _ => false,
    }
}

struct CapDetector<'a> {
    params: &'a HashSet<String>,
    found_cap: bool,
}

impl<'ast> Visit<'ast> for CapDetector<'_> {
    fn visit_expr_if(&mut self, i: &'ast syn::ExprIf) {
        if is_comparison_with_param(&i.cond, self.params) {
            self.found_cap = true;
        }
        visit::visit_expr_if(self, i);
    }

    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        let macro_name = i.path.segments.last().map(|s| s.ident.to_string());
        if let Some(name) = macro_name {
            if name.starts_with("assert") {
                if let Ok(exprs) = i.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
                    if let Some(first_expr) = exprs.first() {
                        if is_comparison_with_param(first_expr, self.params) {
                            self.found_cap = true;
                        }
                    }
                }
            }
        }
        visit::visit_macro(self, i);
    }
}

struct CallVisitor {
    defined_fns: HashSet<String>,
    calls: HashSet<String>,
    touches_storage_accumulator: bool,
}

fn receiver_chain_contains_storage(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        syn::Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn receiver_chain_contains_ledger(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => {
            if m.method == "ledger" {
                return true;
            }
            receiver_chain_contains_ledger(&m.receiver)
        }
        syn::Expr::Field(f) => receiver_chain_contains_ledger(&f.base),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*i.func {
            if let Some(last_seg) = p.path.segments.last() {
                let name = last_seg.ident.to_string();
                if self.defined_fns.contains(&name) {
                    self.calls.insert(name);
                }
            }
        }
        visit::visit_expr_call(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let method_name = i.method.to_string();
        if self.defined_fns.contains(&method_name) {
            self.calls.insert(method_name.clone());
        }

        // Check for accumulator storage access
        if receiver_chain_contains_storage(&i.receiver)
            && matches!(method_name.as_str(), "get" | "set" | "has" | "remove" | "update" | "append")
        {
            struct AccumulatorDetector {
                found: bool,
            }
            impl<'ast> Visit<'ast> for AccumulatorDetector {
                fn visit_ident(&mut self, ident: &'ast syn::Ident) {
                    if is_accumulator_name(&ident.to_string()) {
                        self.found = true;
                    }
                }
                fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
                    if is_accumulator_name(&lit.value()) {
                        self.found = true;
                    }
                }
            }
            let mut det = AccumulatorDetector { found: false };
            for arg in &i.args {
                det.visit_expr(arg);
            }
            if det.found {
                self.touches_storage_accumulator = true;
            }
        }

        // Check for ledger.timestamp() call
        if method_name == "timestamp" && receiver_chain_contains_ledger(&i.receiver) {
            self.touches_storage_accumulator = true;
        }

        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_path(&mut self, i: &'ast syn::ExprPath) {
        if let Some(last_seg) = i.path.segments.last() {
            let name = last_seg.ident.to_string();
            if self.defined_fns.contains(&name) {
                self.calls.insert(name);
            }
        }
        visit::visit_expr_path(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        WithdrawalAggregateBypassCheck.run(&file, src)
    }

    #[test]
    fn flags_vulnerable_direct() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn withdraw_daily(env: Env, amount: i128) {
        let daily_limit = 1000;
        assert!(amount <= daily_limit);
        // Does not touch any accumulator
    }
}
        "#;
        let findings = run_on_src(src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].function_name, "withdraw_daily");
    }

    #[test]
    fn ignores_safe_direct() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn withdraw_daily(env: Env, amount: i128) {
        let daily_limit = 1000;
        assert!(amount <= daily_limit);
        let mut total = env.storage().instance().get(&Symbol::new(&env, "total")).unwrap_or(0);
        total += amount;
        env.storage().instance().set(&Symbol::new(&env, "total"), &total);
    }
}
        "#;
        let findings = run_on_src(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_safe_via_helper() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn withdraw_daily(env: Env, amount: i128) {
        let daily_limit = 1000;
        assert!(amount <= daily_limit);
        Self::update_total(&env, amount);
    }
}

impl MyContract {
    fn update_total(env: &Env, amount: i128) {
        let mut total = env.storage().instance().get(&Symbol::new(&env, "total")).unwrap_or(0);
        total += amount;
        env.storage().instance().set(&Symbol::new(&env, "total"), &total);
    }
}
        "#;
        let findings = run_on_src(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_vulnerable_with_unrelated_helper() {
        let src = r#"
#[contractimpl]
impl MyContract {
    pub fn withdraw_daily(env: Env, amount: i128) {
        let daily_limit = 1000;
        assert!(amount <= daily_limit);
        Self::unrelated_helper(&env);
    }
}

impl MyContract {
    fn unrelated_helper(env: &Env) {
        // Does not touch accumulator
    }
}
        "#;
        let findings = run_on_src(src);
        assert_eq!(findings.len(), 1);
    }
}
