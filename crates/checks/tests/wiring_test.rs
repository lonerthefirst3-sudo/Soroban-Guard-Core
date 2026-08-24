use std::collections::HashMap;
use std::path::Path;

#[test]
fn wiring_test_all_checks_are_registered() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let lib_path = Path::new(manifest_dir).join("src/lib.rs");
    let content = std::fs::read_to_string(lib_path).expect("read lib.rs");

    let mut mods = Vec::new();
    let mut uses = Vec::new();
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub mod ") {
            if let Some(name) = rest.strip_suffix(';') {
                mods.push(name.to_string());
            }
        } else if line.starts_with("mod ") {
            let name = line.strip_prefix("mod ").unwrap().strip_suffix(';').unwrap();
            if !matches!(name, "cfg" | "provenance" | "util") {
                panic!("unexpected private mod declaration: {name}");
            }
        } else if let Some(rest) = line.strip_prefix("pub use ") {
            if let Some((mod_name, check_name)) = rest.strip_suffix(';').and_then(|s| s.split_once("::")) {
                uses.push((mod_name.to_string(), check_name.to_string()));
            }
        } else if let Some(rest) = line.strip_prefix("Box::new(") {
            let check = rest.strip_suffix("),").or_else(|| rest.strip_suffix(')')).unwrap_or(rest).to_string();
            entries.push(check);
        }
    }

    let infrastructure = ["cfg", "provenance", "util", "callgraph"];

    let check_mods: Vec<_> = mods.into_iter().filter(|m| !infrastructure.contains(&m.as_str())).collect();
    let check_uses: Vec<_> = uses.into_iter().filter(|(m, _)| !infrastructure.contains(&m.as_str())).collect();

    let mut missing_uses = Vec::new();
    let mut missing_entries = Vec::new();
    let mut extra_entries = Vec::new();

    let use_map: HashMap<_, _> = check_uses.into_iter().map(|(m, c)| (m, c)).collect();
    let entry_set: std::collections::HashSet<_> = entries.iter().cloned().collect();

    for mod_name in &check_mods {
        if let Some(check_name) = use_map.get(mod_name) {
            if !entry_set.contains(check_name.as_str()) {
                missing_entries.push((mod_name.clone(), check_name.clone()));
            }
        } else {
            missing_uses.push(mod_name.clone());
        }
    }

    let use_check_names: std::collections::HashSet<_> = use_map.values().cloned().collect();
    for entry in &entries {
        if !use_check_names.contains(entry.as_str()) {
            extra_entries.push(entry.clone());
        }
    }

    if !missing_uses.is_empty() || !missing_entries.is_empty() || !extra_entries.is_empty() {
        let mut msg = String::new();
        if !missing_uses.is_empty() {
            msg.push_str("\nCheck modules without pub use:\n");
            for m in &missing_uses {
                msg.push_str(&format!("  - {m}\n"));
            }
        }
        if !missing_entries.is_empty() {
            msg.push_str("\nChecks declared but not registered in default_checks():\n");
            for (m, c) in &missing_entries {
                msg.push_str(&format!("  - {m} -> {c}\n"));
            }
        }
        if !extra_entries.is_empty() {
            msg.push_str("\nEntries in default_checks() without matching pub use:\n");
            for e in &extra_entries {
                msg.push_str(&format!("  - {e}\n"));
            }
        }
        panic!("Wiring test failed:{msg}");
    }
}
