//! 代理地址解析与归一化
//!
//! 第三方代理供应商常见的几种代理串格式：
//! 1. `hostname:port:username:password`
//! 2. `username:password:hostname:port`
//! 3. `username:password@hostname:port`
//! 4. `hostname:port@username:password`
//! 5. 标准 URL：`http://host:port`、`https://host:port`、`socks5://host:port`
//!    （以及 5 中带认证的 `scheme://user:pass@host:port`）
//!
//! `reqwest::Proxy::all` 仅接受标准 URL，因此本模块负责把上述任意一种格式
//! 归一化为 `scheme://[user:pass@]host:port`。
//!
//! - 未提供协议时默认使用 `http`
//! - 支持的协议白名单：`http`、`https`、`socks4`、`socks4a`、`socks5`、`socks5h`
//! - 用户名 / 密码中如包含 `@`、`:`、`/`、`?`、`#` 等字符会做百分号编码
//!
//! 解析失败返回错误信息，便于上层日志记录。

/// 把任意常见格式的代理串归一化为标准 URL
pub fn normalize_proxy_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("代理地址为空".to_string());
    }

    // 1. 提取 scheme
    let (scheme, body) = match raw.find("://") {
        Some(i) => {
            let s = raw[..i].to_ascii_lowercase();
            (s, raw[i + 3..].to_string())
        }
        None => ("http".to_string(), raw.to_string()),
    };

    if !is_supported_scheme(&scheme) {
        return Err(format!("不支持的代理协议: {}", scheme));
    }

    let body = body.trim().trim_end_matches('/');
    if body.is_empty() {
        return Err("代理地址主体为空".to_string());
    }

    // 2. 处理含 '@' 的两种形态
    if body.contains('@') {
        // 取最后一个 '@'（防止用户密码里的 '@' 干扰）：
        // 我们启发式地认为右半边更可能是 host:port
        let (left, right) = split_last_at(body);

        let right_is_hp = is_host_port(right);
        let left_is_hp = is_host_port(left);

        let (auth, host_port) = if right_is_hp && !left_is_hp {
            // 标准形态：user:pass@host:port
            (left, right)
        } else if left_is_hp && !right_is_hp {
            // 反向形态：host:port@user:pass
            (right, left)
        } else if right_is_hp && left_is_hp {
            // 两边都像 host:port，按"右边是 host"的标准约定处理
            (left, right)
        } else {
            return Err(format!("无法解析代理地址（缺少有效的 host:port）: {}", raw));
        };

        let (user, pass) = parse_user_pass(auth)?;
        let (host, port) = parse_host_port(host_port)?;
        return Ok(format_url(&scheme, Some((&user, &pass)), &host, port));
    }

    // 3. 不含 '@'：可能是 host:port、host:port:user:pass、user:pass:host:port
    let segments: Vec<&str> = body.split(':').collect();
    match segments.len() {
        2 => {
            let (host, port) = parse_host_port(body)?;
            Ok(format_url(&scheme, None, &host, port))
        }
        4 => {
            let p2 = segments[1].parse::<u16>().ok();
            let p4 = segments[3].parse::<u16>().ok();

            let (host, port, user, pass) = match (p2, p4) {
                (Some(p), None) => (segments[0], p, segments[2], segments[3]),
                (None, Some(p)) => (segments[2], p, segments[0], segments[1]),
                (Some(p2v), Some(p4v)) => {
                    // 两个位置都能解析为端口号，按字段长相再判断一次：
                    // 如果第 1 段长得像 hostname（含字母或点），认为是 host:port:user:pass
                    if looks_like_host(segments[0]) && !looks_like_host(segments[2]) {
                        (segments[0], p2v, segments[2], segments[3])
                    } else if looks_like_host(segments[2]) && !looks_like_host(segments[0]) {
                        (segments[2], p4v, segments[0], segments[1])
                    } else {
                        // 仍然无法判定时，遵循文档优先约定：host:port:user:pass
                        (segments[0], p2v, segments[2], segments[3])
                    }
                }
                (None, None) => {
                    return Err(format!("4 段格式中找不到合法端口号: {}", raw));
                }
            };

            if host.is_empty() || user.is_empty() {
                return Err(format!("4 段格式中存在空字段: {}", raw));
            }
            Ok(format_url(&scheme, Some((user, pass)), host, port))
        }
        _ => Err(format!(
            "无法识别的代理格式: {}（仅支持 host:port、user:pass@host:port、host:port:user:pass、user:pass:host:port、host:port@user:pass）",
            raw
        )),
    }
}

fn is_supported_scheme(s: &str) -> bool {
    matches!(s, "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h")
}

fn split_last_at(s: &str) -> (&str, &str) {
    // splitn 从左切，rsplitn 从右切：用 rsplitn(2, '@') 取最后一个 '@'
    let mut it = s.rsplitn(2, '@');
    let right = it.next().unwrap_or("");
    let left = it.next().unwrap_or("");
    (left, right)
}

fn is_host_port(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return false;
    }
    !parts[0].is_empty() && parts[1].parse::<u16>().is_ok()
}

fn parse_host_port(s: &str) -> Result<(String, u16), String> {
    let mut it = s.splitn(2, ':');
    let host = it.next().ok_or_else(|| format!("缺少 host: {}", s))?;
    let port_str = it.next().ok_or_else(|| format!("缺少 port: {}", s))?;
    if host.is_empty() {
        return Err(format!("host 为空: {}", s));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("端口号非法: {}", port_str))?;
    Ok((host.to_string(), port))
}

fn parse_user_pass(s: &str) -> Result<(String, String), String> {
    let mut it = s.splitn(2, ':');
    let user = it.next().unwrap_or("");
    let pass = it.next().unwrap_or("");
    if user.is_empty() {
        return Err(format!("代理用户名为空: {}", s));
    }
    Ok((user.to_string(), pass.to_string()))
}

fn looks_like_host(s: &str) -> bool {
    s.contains('.') || s.chars().any(|c| c.is_ascii_alphabetic())
}

/// 对 user/pass 做最小必要的百分号编码，避免 `@` `:` `/` `?` `#` 等字符破坏 URL 结构
fn percent_encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b;
        let needs_encode = matches!(
            c,
            b'@' | b':' | b'/' | b'?' | b'#' | b'[' | b']' | b'%' | b' '
        ) || c < 0x21
            || c > 0x7E;
        if needs_encode {
            out.push_str(&format!("%{:02X}", c));
        } else {
            out.push(c as char);
        }
    }
    out
}

fn format_url(scheme: &str, auth: Option<(&str, &str)>, host: &str, port: u16) -> String {
    match auth {
        Some((u, p)) if !u.is_empty() => {
            let u_enc = percent_encode_userinfo(u);
            let p_enc = percent_encode_userinfo(p);
            if p.is_empty() {
                format!("{}://{}@{}:{}", scheme, u_enc, host, port)
            } else {
                format!("{}://{}:{}@{}:{}", scheme, u_enc, p_enc, host, port)
            }
        }
        _ => format!("{}://{}:{}", scheme, host, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_http_with_scheme() {
        assert_eq!(
            normalize_proxy_url("http://127.0.0.1:7890").unwrap(),
            "http://127.0.0.1:7890"
        );
    }

    #[test]
    fn standard_socks5_with_scheme() {
        assert_eq!(
            normalize_proxy_url("socks5://example.com:1080").unwrap(),
            "socks5://example.com:1080"
        );
    }

    #[test]
    fn host_port_only() {
        assert_eq!(
            normalize_proxy_url("127.0.0.1:7890").unwrap(),
            "http://127.0.0.1:7890"
        );
    }

    #[test]
    fn host_port_user_pass() {
        assert_eq!(
            normalize_proxy_url("proxy.example.com:8080:alice:s3cret").unwrap(),
            "http://alice:s3cret@proxy.example.com:8080"
        );
    }

    #[test]
    fn user_pass_host_port() {
        assert_eq!(
            normalize_proxy_url("alice:s3cret:proxy.example.com:8080").unwrap(),
            "http://alice:s3cret@proxy.example.com:8080"
        );
    }

    #[test]
    fn user_pass_at_host_port() {
        assert_eq!(
            normalize_proxy_url("alice:s3cret@proxy.example.com:8080").unwrap(),
            "http://alice:s3cret@proxy.example.com:8080"
        );
    }

    #[test]
    fn host_port_at_user_pass() {
        assert_eq!(
            normalize_proxy_url("proxy.example.com:8080@alice:s3cret").unwrap(),
            "http://alice:s3cret@proxy.example.com:8080"
        );
    }

    #[test]
    fn socks5_with_user_pass_at() {
        assert_eq!(
            normalize_proxy_url("socks5://alice:s3cret@proxy.example.com:1080").unwrap(),
            "socks5://alice:s3cret@proxy.example.com:1080"
        );
    }

    #[test]
    fn socks5_with_4_segment_format() {
        assert_eq!(
            normalize_proxy_url("socks5://proxy.example.com:1080:alice:s3cret").unwrap(),
            "socks5://alice:s3cret@proxy.example.com:1080"
        );
    }

    #[test]
    fn percent_encodes_special_chars() {
        let out = normalize_proxy_url("alice:p@ss:word@proxy.example.com:8080").unwrap();
        // 'p@ss:word' 中的 '@' 和 ':' 必须编码（splitn(2,'@') 已确保最右 '@' 切分）
        // 这里实际密码是 "p@ss:word"
        assert!(out.contains("p%40ss%3Aword"), "got {}", out);
        assert!(out.ends_with("@proxy.example.com:8080"), "got {}", out);
    }

    #[test]
    fn ipv4_host_port_user_pass() {
        assert_eq!(
            normalize_proxy_url("203.0.113.5:31337:alice:s3cret").unwrap(),
            "http://alice:s3cret@203.0.113.5:31337"
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(normalize_proxy_url("   ").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(normalize_proxy_url("ftp://host:21").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(normalize_proxy_url("not-a-proxy").is_err());
    }

    #[test]
    fn rejects_4_segment_no_port() {
        assert!(normalize_proxy_url("a:b:c:d").is_err());
    }
}
