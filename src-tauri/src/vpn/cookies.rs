//! 极简 Cookie 罐：只按名字保存（本工具只访问同一个 WebVPN 站点），落盘复用。

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Default, Clone)]
pub struct CookieJar {
    pub map: BTreeMap<String, String>,
}

impl CookieJar {
    pub fn load(file: &Path) -> Self {
        let mut jar = Self::default();
        if let Ok(s) = std::fs::read_to_string(file) {
            if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(&s) {
                jar.map = map;
            }
        }
        jar
    }

    pub fn save(&self, file: &Path) {
        if let Ok(s) = serde_json::to_string_pretty(&self.map) {
            let _ = std::fs::write(file, s);
        }
    }

    pub fn set_from_response(&mut self, lines: &[String]) {
        for line in lines {
            let first = line.split(';').next().unwrap_or("");
            let Some(eq) = first.find('=') else { continue };
            if eq == 0 {
                continue;
            }
            let name = first[..eq].trim();
            let value = first[eq + 1..].trim();
            if name.is_empty() {
                continue;
            }
            let attrs = line[first.len()..].to_lowercase();
            if attrs.contains("max-age=0") {
                self.map.remove(name);
            } else {
                self.map.insert(name.to_string(), value.to_string());
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        self.map.get(name)
    }

    pub fn header(&self) -> String {
        self.map
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn names(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
}
