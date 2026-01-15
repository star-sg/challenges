use actix_web::{web, App, HttpResponse, HttpServer, Result};
use actix_files as fs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;

#[derive(Debug, Deserialize)]
struct WishRequest {
    name: String,
    wish: String,
    template: Option<String>,
}

#[derive(Debug, Serialize)]
struct WishResponse {
    message: String,
    rendered: String,
}

struct ChristmasTemplateEngine {
    variables: HashMap<String, String>,
}

impl ChristmasTemplateEngine {
    fn new() -> Self {
        let mut variables = HashMap::new();
        variables.insert("santa".to_string(), "🎅".to_string());
        variables.insert("tree".to_string(), "🎄".to_string());
        variables.insert("gift".to_string(), "🎁".to_string());
        variables.insert("snowman".to_string(), "⛄".to_string());
        variables.insert("star".to_string(), "⭐".to_string());
        variables.insert("bell".to_string(), "🔔".to_string());
        
        Self { variables }
    }

    fn set_variable(&mut self, key: String, value: String) {
        self.variables.insert(key, value);
    }

    fn render(&self, template: &str) -> Result<String, String> {
        let mut result = template.to_string();

        if self.is_suspicious(template) {
            return Err("Suspicious template detected! Santa's security elves are watching! 🎅🚨".to_string());
        }
        
        // Handle variable substitution {{variable}}
        let var_regex = Regex::new(r"\{\{([^}]+)\}\}").unwrap();
        for cap in var_regex.captures_iter(template) {
            let expr = cap.get(1).unwrap().as_str().trim();
            let value = self.evaluate_expression(expr)?;
            result = result.replace(&cap[0], &value);
        }

        // Handle special expressions {$north_pole expr$}
        let magic_regex = Regex::new(r"\{\$north_pole\s+(.+?)\$\}").unwrap();
        for cap in magic_regex.captures_iter(template) {
            let expr = cap.get(1).unwrap().as_str().trim();
            let value = self.evaluate_special(expr)?;
            result = result.replace(&cap[0], &value);
        }

        Ok(result)
    }

    fn is_suspicious(&self, template: &str) -> bool {
        let suspicious_patterns = [
            "exec", "system", "command", "shell",
            "eval", "import", "require",
            "FLAG", "flag", "secret",
            "/proc", "/etc/passwd",
            "cat ", "ls ", "wget", "curl"
        ];
        
        for pattern in suspicious_patterns {
            if template.contains(pattern) {
                return true;
            }
        }
        false
    }

    fn evaluate_expression(&self, expr: &str) -> Result<String, String> {
        if let Some(value) = self.variables.get(expr) {
            return Ok(value.clone());
        }

        if expr.contains('.') {
            let parts: Vec<&str> = expr.split('.').collect();
            if parts.len() == 2 {
                if let Some(value) = self.variables.get(parts[0]) {
                    return self.apply_filter(value, parts[1]);
                }
            }
        }

        Err(format!("Unknown variable: {}", expr))
    }

    fn apply_filter(&self, value: &str, filter: &str) -> Result<String, String> {
        match filter {
            "upper" => Ok(value.to_uppercase()),
            "lower" => Ok(value.to_lowercase()),
            "reverse" => Ok(value.chars().rev().collect()),
            "len" => Ok(value.len().to_string()),
            _ => Err(format!("Unknown filter: {}", filter)),
        }
    }

    fn evaluate_special(&self, expr: &str) -> Result<String, String> {
        if expr.starts_with("env.") || expr.starts_with("getenv.") {
            let parts: Vec<&str> = expr.split('.').collect();
            if parts.len() >= 2 {
                let env_var = parts[1..].join(".");
                return Ok(std::env::var(&env_var).unwrap_or_else(|_| "Not found".to_string()));
            }
        }

        if expr.starts_with("read:") || expr.starts_with("file:") {
            let filepath = if expr.starts_with("read:") {
                &expr[5..]
            } else {
                &expr[5..]
            };
            return match std::fs::read_to_string(filepath) {
                Ok(content) => Ok(content),
                Err(e) => Err(format!("Cannot read file: {}", e)),
            };
        }

        if expr.starts_with("run:") || expr.starts_with("cmd:") {
            let command = if expr.starts_with("run:") {
                &expr[4..]
            } else {
                &expr[4..]
            };
            return match self.execute_command(command) {
                Ok(output) => Ok(output),
                Err(e) => Err(format!("Command failed: {}", e)),
            };
        }

        if expr.contains('+') || expr.contains('-') || expr.contains('*') {
            return self.evaluate_math(expr);
        }

        Err(format!("Unknown special expression: {}", expr))
    }

    fn execute_command(&self, command: &str) -> Result<String, String> {
        use std::process::Command;
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    fn evaluate_math(&self, expr: &str) -> Result<String, String> {
        let expr = expr.replace(" ", "");
        
        if let Some(pos) = expr.find('+') {
            let (left, right) = expr.split_at(pos);
            let right = &right[1..];
            if let (Ok(a), Ok(b)) = (left.parse::<i64>(), right.parse::<i64>()) {
                return Ok((a + b).to_string());
            }
        }

        if let Some(pos) = expr.find('*') {
            let (left, right) = expr.split_at(pos);
            let right = &right[1..];
            if let (Ok(a), Ok(b)) = (left.parse::<i64>(), right.parse::<i64>()) {
                return Ok((a * b).to_string());
            }
        }

        Err("Invalid math expression".to_string())
    }
}

async fn index() -> Result<HttpResponse> {
    let html = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| {
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Santa's Wishlist 🎅</title>
    <style>
        body {
            font-family: 'Georgia', serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 50px;
            text-align: center;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        h1 { font-size: 3em; margin-bottom: 20px; }
        input, textarea {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: none;
            border-radius: 8px;
            font-size: 16px;
        }
        button {
            background: #d4001a;
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            cursor: pointer;
            margin-top: 15px;
        }
        button:hover { background: #a80015; }
        .result {
            margin-top: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            display: none;
        }
        .examples {
            text-align: left;
            margin-top: 20px;
            font-size: 0.9em;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎄 Santa's Wishlist 🎄</h1>
        <p>Make your Christmas wish and let Santa's magic template engine process it!</p>
        
        <form id="wishForm">
            <input type="text" id="name" placeholder="Your name" required>
            <textarea id="wish" rows="4" placeholder="Your Christmas wish" required></textarea>
            <textarea id="template" rows="6" placeholder="Custom template (optional - try our template syntax!)">Dear {{santa}}, my name is {{name}} and I wish for {{wish}}! {{tree}}{{gift}}</textarea>
            <button type="submit">Send Wish 🎁</button>
        </form>

        <div class="examples">
            <strong>Try these template expressions:</strong><br>
            • {{santa}} {{tree}} {{gift}} - Christmas emojis<br>
            • {{name.upper}} - Transform your name<br>
            • {{wish.len}} - Count characters<br>
            <br>
            <em>Hint: There might be more powerful template features hidden in Santa's workshop... 🎅✨</em>
        </div>

        <div class="result" id="result"></div>
    </div>

    <script>
        document.getElementById('wishForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const wish = document.getElementById('wish').value;
            const template = document.getElementById('template').value;

            const response = await fetch('/wish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, wish, template: template || null })
            });

            const data = await response.json();
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = `<strong>${data.message}</strong><br><br><pre>${data.rendered}</pre>`;
            resultDiv.style.display = 'block';
        });
    </script>
</body>
</html>"#.to_string()
        });
    
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn make_wish(wish_req: web::Json<WishRequest>) -> Result<HttpResponse> {
    let mut engine = ChristmasTemplateEngine::new();

    engine.set_variable("name".to_string(), wish_req.name.clone());
    engine.set_variable("wish".to_string(), wish_req.wish.clone());

    let template = wish_req.template.as_ref().map(|s| s.as_str()).unwrap_or(
        "Dear {{santa}}, my name is {{name}} and I wish for {{wish}}! {{tree}}{{gift}}"
    );

    // Render the template
    let rendered = match engine.render(template) {
        Ok(result) => result,
        Err(e) => format!("Template error: {}", e),
    };

    let response = WishResponse {
        message: "Your wish has been sent to Santa!".to_string(),
        rendered,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("🎄 Santa's Wishlist Server Starting...");
    println!("🎅 Server running on http://0.0.0.0:8080");

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/wish", web::post().to(make_wish))
            .service(fs::Files::new("/static", "./static").show_files_listing())
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
