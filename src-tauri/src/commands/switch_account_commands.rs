use crate::commands::patch_commands::{detect_windsurf_path_internal, apply_seamless_patch_internal};
use crate::repository::DataStore;
use crate::utils::errors::{AppError, AppResult};
use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;
use std::path::PathBuf;

// ==================== 切号进度事件（Tauri Event） ====================
//
// 前端 AccountCard.vue 通过 listen("switch-progress", ...) 订阅此事件并驱动进度弹窗。
// 维护守则：
// - `percent` 必须单调非递减（除非 phase=error）；前端依赖此假设做动画插值。
// - `step` 是稳定的枚举键（前端按 key 标记 checklist），文案放在 `label`。
// - `phase`:
//     "running" = 正在执行该阶段（前端条纹动画）
//     "success" = 全流程成功（percent=100，前端 1 秒后自动关闭）
//     "error"   = 失败（前端保持弹窗、展示 error label + "关闭"按钮）
// - 任何 early return 都必须先 emit phase=error，否则前端会卡在最后一次 running 状态。
#[derive(Clone, Serialize)]
struct SwitchProgressPayload {
    /// 阶段稳定键（与前端 checklist 顺序一一对应）
    step: &'static str,
    /// 人类可读阶段描述（允许带上下文变量）
    label: String,
    /// 0 ~ 100；error 时保留当前阶段的百分比，方便前端定位失败节点
    percent: u8,
    /// "running" | "success" | "error"
    phase: &'static str,
}

/// 封装事件发送；忽略发送错误（窗口已关闭等非致命情况）
fn emit_switch_progress(
    app: &AppHandle,
    step: &'static str,
    label: impl Into<String>,
    percent: u8,
    phase: &'static str,
) {
    let payload = SwitchProgressPayload {
        step,
        label: label.into(),
        percent,
        phase,
    };
    if let Err(e) = app.emit("switch-progress", &payload) {
        warn!("Failed to emit switch-progress event: {:?}", e);
    }
}

#[cfg(target_os = "windows")]
use winreg::{RegKey, enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS}};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Serialize, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    expires_in: String,
    token_type: String,
    refresh_token: String,
    id_token: String,
    user_id: String,
    project_id: String,
}

/// 使用refresh_token获取新的access_token
async fn refresh_access_token(refresh_token: &str) -> AppResult<GoogleTokenResponse> {
    // 使用专门用于 googleapis 的 HTTP 客户端（支持代理）
    let client = crate::services::get_google_api_client();
    
    // Google Token API
    let url = "https://securetoken.googleapis.com/v1/token";
    
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    
    let response = client
        .post(&format!("{}?key={}", url, crate::services::auth_service::FIREBASE_API_KEY))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Client-Version", "Chrome/JsCore/11.0.0/FirebaseCore-web")
        .header("Origin", "https://windsurf.com")
        .header("Referer", "https://windsurf.com/")
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Network(e.to_string()))?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("Failed to refresh token: {}", error_text);
        return Err(AppError::ApiRequest(format!("Failed to refresh token: {}", error_text)));
    }
    
    let token_response = response.json::<GoogleTokenResponse>().await
        .map_err(|e| AppError::Network(e.to_string()))?;
    
    Ok(token_response)
}

/// 序列化Protobuf字符串（field 1, wire type 2）
fn serialize_protobuf_string(value: &str) -> Vec<u8> {
    if value.is_empty() {
        return vec![];
    }
    
    let value_bytes = value.as_bytes();
    let value_length = value_bytes.len();
    
    // Field 1, wire type 2 (length-delimited): (1 << 3) | 2 = 0x0A
    let mut result = vec![0x0A];
    
    // Encode length as varint
    let mut length = value_length;
    while length > 127 {
        result.push((length as u8 & 0x7F) | 0x80);
        length >>= 7;
    }
    result.push(length as u8 & 0x7F);
    
    // Append value bytes
    result.extend_from_slice(value_bytes);
    result
}

/// 反序列化Protobuf响应获取auth_token
fn deserialize_protobuf_response(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    
    let mut pos = 0;
    while pos < data.len() {
        // Read field tag
        let tag = data[pos];
        pos += 1;
        
        // Get wire type (low 3 bits)
        let wire_type = tag & 0x07;
        let field_number = tag >> 3;
        
        // If it's length-delimited type (wire_type = 2)
        if wire_type == 2 {
            // Read varint length
            let mut length = 0;
            let mut shift = 0;
            while pos < data.len() {
                let byte = data[pos];
                pos += 1;
                length |= ((byte & 0x7F) as usize) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            
            // Read string content
            if pos + length <= data.len() {
                if let Ok(value) = std::str::from_utf8(&data[pos..pos + length]) {
                    // auth_token is typically field 1
                    if field_number == 1 && !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
                pos += length;
            }
        } else if wire_type == 0 {
            // Skip varint field
            while pos < data.len() {
                if data[pos] & 0x80 == 0 {
                    pos += 1;
                    break;
                }
                pos += 1;
            }
        } else {
            // Skip other types
            break;
        }
    }
    
    None
}

/// 使用access_token获取auth_token
async fn get_auth_token(access_token: &str) -> AppResult<String> {
    let client = reqwest::Client::new();
    
    // Windsurf GetOneTimeAuthToken endpoint
    let url = "https://web-backend.windsurf.com/exa.seat_management_pb.SeatManagementService/GetOneTimeAuthToken";
    
    // Serialize request as Protobuf
    let request_data = serialize_protobuf_string(access_token);
    
    let response = client
        .post(url)
        .header("Content-Type", "application/proto")
        .header("Accept", "application/proto")
        .header("User-Agent", "Windsurf/1.4.2")
        .body(request_data)
        .send()
        .await
        .map_err(|e| AppError::Network(e.to_string()))?;
    
    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("Failed to get auth token: {}", error_text);
        return Err(AppError::ApiRequest(format!("Failed to get auth token: {}", error_text)));
    }
    
    // Deserialize response
    let response_bytes = response.bytes().await
        .map_err(|e| AppError::Network(e.to_string()))?;
    
    let auth_token = deserialize_protobuf_response(&response_bytes)
        .ok_or_else(|| AppError::ApiRequest("Failed to parse auth token from response".to_string()))?;
    
    info!("Successfully obtained auth token");
    Ok(auth_token)
}

/// 根据客户端类型获取 protocol URI scheme 和数据目录名
fn get_client_uri_config(client_type: &str) -> (&'static str, &'static str) {
    match client_type {
        "windsurf-next" => ("windsurf-next", "Windsurf - Next"),
        _ => ("windsurf", "Windsurf"),
    }
}

/// 触发Windsurf回调URL以完成登录
async fn trigger_windsurf_callback(auth_token: &str, client_type: &str) -> AppResult<()> {
    let (scheme, _) = get_client_uri_config(client_type);
    
    // 生成state参数
    let state = Uuid::new_v4().to_string();
    
    // 构建URL
    // {scheme}://codeium.windsurf#access_token=<auth_token>&state=<state>&token_type=Bearer
    let params = [
        ("access_token", auth_token),
        ("state", &state),
        ("token_type", "Bearer"),
    ];
    
    let fragment = serde_urlencoded::to_string(&params)
        .map_err(|e| AppError::ApiRequest(format!("Failed to encode URL parameters: {}", e)))?;
    
    let callback_url = format!("{}://codeium.windsurf#{}", scheme, fragment);
    
    info!("Triggering Windsurf callback: {}", callback_url);
    
    // 使用系统默认程序打开URL（触发Windsurf处理）
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        // 使用 PowerShell 的 Start-Process 来正确处理包含特殊字符的 URL
        Command::new("powershell")
            .args(&["-NoProfile", "-Command", &format!("Start-Process '{}'", callback_url)])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| AppError::FileOperation(format!("Failed to open URL: {}", e)))?;
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        Command::new("open")
            .arg(&callback_url)
            .spawn()
            .map_err(|e| AppError::FileOperation(format!("Failed to open URL: {}", e)))?;
    }
    
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        Command::new("xdg-open")
            .arg(&callback_url)
            .spawn()
            .map_err(|e| AppError::FileOperation(format!("Failed to open URL: {}", e)))?;
    }
    
    info!("Successfully triggered Windsurf callback");
    Ok(())
}


/// 一键切换账号命令（简化版：使用回调URL登录）
///
/// 进度事件：整个流程通过 `emit_switch_progress` 向前端持续上报 `switch-progress` 事件
/// （见本文件头部的 SwitchProgressPayload 文档）。前端 AccountCard.vue 通过 listen 订阅。
#[tauri::command]
pub async fn switch_account(
    app: AppHandle,
    id: String,
    data_store: State<'_, Arc<DataStore>>,
) -> Result<Value, String> {
    // 设置开关：safe_storage_inject_enabled = true 时走加密注入路径
    // （仅 Windows 实现，跳过 OAuth deep link，不会撞 too many free user accounts）
    if let Ok(s) = data_store.get_settings().await {
        if s.safe_storage_inject_enabled {
            info!("Settings.safe_storage_inject_enabled = true, dispatching to inject path");
            return switch_account_via_safe_storage(app, id, data_store).await;
        }
    }

    info!("Switching account: {}", id);
    emit_switch_progress(&app, "preparing", "开始切换账号...", 5, "running");
    
    let account_id = Uuid::parse_str(&id).map_err(|e| {
        emit_switch_progress(&app, "preparing", format!("账号ID无效: {}", e), 5, "error");
        e.to_string()
    })?;
    
    // 获取账号信息
    let account = data_store
        .get_account(account_id)
        .await
        .map_err(|e| {
            emit_switch_progress(&app, "preparing", format!("读取账号失败: {}", e), 5, "error");
            e.to_string()
        })?;
    
    // Step 1~2: 根据账号体系分流获取 access_token / auth_token
    //
    // - Firebase 账号：refresh_token → Google access_token → GetOneTimeAuthToken → one-time auth_token
    // - Devin 账号：account.token (devin-session-token$...) 直接作为 GetOneTimeAuthToken 的 auth_token 入参；
    //   由 AuthContext 自动附带 4 个 Devin 扩展 header 完成鉴权，无 Google OAuth 环节
    let (access_token, expires_in, auth_token) = if account.is_devin_account() {
        use crate::services::{AuthContext, WindsurfService};
        info!("[Devin] Using session-token based one-time auth token flow");
        emit_switch_progress(&app, "fetch_access", "使用 Devin session token 认证...", 15, "running");

        let ctx = AuthContext::from_account(&account).map_err(|e| {
            emit_switch_progress(&app, "fetch_access", format!("Devin 认证上下文构建失败: {}", e), 15, "error");
            e.to_string()
        })?;
        let windsurf = WindsurfService::new();
        emit_switch_progress(&app, "fetch_auth", "正在获取 one-time auth_token...", 35, "running");
        let auth_token = match windsurf.get_one_time_auth_token(&ctx).await {
            Ok(token) => {
                info!("[Devin] Successfully obtained one-time auth token");
                token
            }
            Err(e) => {
                error!("[Devin] Failed to get one-time auth token: {:?}", e);
                emit_switch_progress(&app, "fetch_auth", format!("获取 auth_token 失败: {}", e), 35, "error");
                return Ok(json!({
                    "success": false,
                    "error": format!("获取auth_token失败: {}", e)
                }));
            }
        };

        // Devin session_token 对外层 update_account_token 仅作占位写入（值不变），
        // expires_in 取 account 现有远期伪值，缺失则默认 30 天
        let access_token = account.token.clone().unwrap_or_default();
        let expires_in = account
            .token_expires_at
            .map(|t| (t - Utc::now()).num_seconds().max(0).to_string())
            .unwrap_or_else(|| "2592000".to_string());
        (access_token, expires_in, auth_token)
    } else {
        // Firebase 分支：必须有 refresh_token 才能换 Google access_token
        emit_switch_progress(&app, "fetch_access", "正在准备 access_token...", 15, "running");
        if account.refresh_token.is_none() || account.refresh_token.as_ref().unwrap().is_empty() {
            emit_switch_progress(&app, "fetch_access", "账号没有 refresh_token，请先登录", 15, "error");
            return Ok(json!({
                "success": false,
                "error": "账号没有refresh_token，请先登录"
            }));
        }

        let refresh_token = account.refresh_token.clone().unwrap();

        // Step 1: 检查本地token是否有效
        let (access_token, expires_in) = if let (Some(token), Some(expires_at)) = (&account.token, &account.token_expires_at) {
            // 检查token是否还有至少5分钟有效期
            let now = Utc::now();
            let buffer = chrono::Duration::minutes(5);
            if *expires_at > now + buffer {
                info!("Using cached access token, expires at: {}", expires_at);
                let remaining_seconds = (*expires_at - now).num_seconds();
                (token.clone(), remaining_seconds.to_string())
            } else {
                info!("Token expired or expiring soon, refreshing...");
                let token_response = match refresh_access_token(&refresh_token).await {
                    Ok(resp) => resp,
                    Err(e) => {
                        error!("Failed to refresh access token: {:?}", e);
                        emit_switch_progress(&app, "fetch_access", format!("刷新 access_token 失败: {}", e), 15, "error");
                        return Ok(json!({
                            "success": false,
                            "error": format!("获取access_token失败: {}", e)
                        }));
                    }
                };
                (token_response.access_token, token_response.expires_in)
            }
        } else {
            // 没有本地token，需要刷新
            info!("No cached token, refreshing access token...");
            let token_response = match refresh_access_token(&refresh_token).await {
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to refresh access token: {:?}", e);
                    emit_switch_progress(&app, "fetch_access", format!("刷新 access_token 失败: {}", e), 15, "error");
                    return Ok(json!({
                        "success": false,
                        "error": format!("获取access_token失败: {}", e)
                    }));
                }
            };
            (token_response.access_token, token_response.expires_in)
        };

        // Step 2: 获取auth_token
        info!("Getting auth token...");
        emit_switch_progress(&app, "fetch_auth", "正在获取 one-time auth_token...", 35, "running");
        let auth_token = match get_auth_token(&access_token).await {
            Ok(token) => token,
            Err(e) => {
                error!("Failed to get auth token: {:?}", e);
                emit_switch_progress(&app, "fetch_auth", format!("获取 auth_token 失败: {}", e), 35, "error");
                return Ok(json!({
                    "success": false,
                    "error": format!("获取auth_token失败: {}", e)
                }));
            }
        };

        (access_token, expires_in, auth_token)
    };
    
    // 读取设置：客户端类型 + 无感换号状态
    let settings = data_store.get_settings().await.map_err(|e| e.to_string())?;
    let client_type = settings.windsurf_client_type.clone();
    let mut seamless_patch_active = settings.seamless_switch_enabled;
    let mut auto_enabled_seamless = false;
    
    // 如果无感换号未启用，尝试自动启用
    if !seamless_patch_active {
        info!("Seamless switch not enabled, attempting auto-enable...");
        emit_switch_progress(&app, "auto_patch", "尝试自动启用无感换号补丁...", 55, "running");
    } else {
        // 已启用时也 emit 一次，让前端 checklist 的该步骤显示为"已启用（跳过）"
        emit_switch_progress(&app, "auto_patch", "无感换号已启用，跳过补丁应用", 55, "running");
    }
    if !seamless_patch_active {
        
        // Step A: 检测或使用已有的客户端路径
        let windsurf_path = settings.windsurf_path.as_ref()
            .filter(|p| !p.is_empty())
            .cloned()
            .or_else(|| {
                info!("No windsurf path configured, auto-detecting...");
                match detect_windsurf_path_internal(&client_type) {
                    Ok(path) => {
                        info!("Auto-detected windsurf path: {}", path);
                        Some(path)
                    }
                    Err(e) => {
                        warn!("Failed to auto-detect windsurf path: {}", e);
                        None
                    }
                }
            });
        
        // Step B: 如果有路径，自动应用无感换号补丁
        if let Some(ref path) = windsurf_path {
            info!("Auto-applying seamless patch at: {}", path);
            match apply_seamless_patch_internal(path, &data_store).await {
                Ok(result) => {
                    let success = result.get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if success {
                        seamless_patch_active = true;
                        auto_enabled_seamless = true;
                        info!("Seamless patch auto-applied successfully");
                    }
                }
                Err(e) => {
                    warn!("Failed to auto-apply seamless patch: {}", e);
                }
            }
        }
    }
    
    // Step 3: 尝试重置机器ID（可能需要管理员权限）
    info!("Attempting to reset machine ID...");
    emit_switch_progress(&app, "reset_mid", "重置机器 ID...", 70, "running");
    // 切号流程内**不能杀** Windsurf——后面 trigger_windsurf_callback 还需要它在线
    // 接收 windsurf://...#access_token=... 这条 deep link，杀了就等于切号失败。
    // 所以这里传 kill_running_process=false，state.vscdb / storage.json 写不进去（被锁）
    // 只 warn 不 abort，保住切号主路径。
    let reset_result = reset_machine_id_internal(&client_type, false).await;
    let machine_id_reset = match reset_result {
        Ok(_) => {
            info!("Machine ID reset successful");
            true
        },
        Err(e) => {
            warn!("Failed to reset machine ID: {:?}", e);
            warn!("重置机器ID失败，可能需要管理员权限。但切换账号仍可继续。");
            false
        }
    };
    
    // Step 4: 触发客户端回调URL以自动登录
    info!("Triggering {} callback...", client_type);
    emit_switch_progress(&app, "callback", format!("触发 {} 登录...", client_type), 85, "running");
    if let Err(e) = trigger_windsurf_callback(&auth_token, &client_type).await {
        error!("Failed to trigger callback: {:?}", e);
        emit_switch_progress(&app, "callback", format!("触发登录失败: {}", e), 85, "error");
        return Ok(json!({
            "success": false,
            "error": format!("触发Windsurf登录失败: {}", e)
        }));
    }
    
    // 更新账号的token信息
    emit_switch_progress(&app, "finalize", "保存账号状态...", 95, "running");
    let expires_at = Utc::now() + chrono::Duration::seconds(expires_in.parse::<i64>().unwrap_or(3600));
    if let Err(e) = data_store.update_account_token(
        account_id,
        access_token.clone(),
        expires_at
    ).await {
        error!("Failed to update account token: {:?}", e);
    }
    
    info!("Successfully triggered Windsurf login for account");
    
    let (_, client_display) = get_client_uri_config(&client_type);
    
    let message = if auto_enabled_seamless {
        if machine_id_reset {
            format!("已自动启用无感换号并切换账号，{}已重启", client_display)
        } else {
            format!("已自动启用无感换号并切换账号，{}已重启（机器ID未重置）", client_display)
        }
    } else if seamless_patch_active {
        if machine_id_reset {
            format!("已通过无感换号切换账号并重置机器ID，{}无需重启", client_display)
        } else {
            format!("已通过无感换号切换账号，{}无需重启（机器ID未重置）", client_display)
        }
    } else if machine_id_reset {
        format!("已触发{}登录并重置机器ID", client_display)
    } else {
        format!("已触发{}登录（未重置机器ID，可能需要管理员权限）", client_display)
    };
    
    emit_switch_progress(&app, "done", "切换完成", 100, "success");

    Ok(json!({
        "success": true,
        "message": message,
        "auth_token": auth_token,
        "machine_id_reset": machine_id_reset,
        "seamless_patch_active": seamless_patch_active,
        "auto_enabled_seamless": auto_enabled_seamless
    }))
}

/// 根据 client_type 推导 Windsurf 进程名（Windows 上带 .exe，类 Unix 上去 .exe）
fn windsurf_process_name(client_type: &str) -> &'static str {
    match client_type {
        "windsurf-next" => "Windsurf - Next.exe",
        _ => "Windsurf.exe",
    }
}

/// 检测 Windsurf / Windsurf - Next 进程是否在运行（用于重置机器 ID 前先结束进程）
fn is_windsurf_running(process_name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        use std::process::Command;
        let output = Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "/FI",
                &format!("IMAGENAME eq {}", process_name),
                "/NH",
                "/FO",
                "CSV",
            ])
            .output();
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout).contains(process_name),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Command;
        let clean = process_name.trim_end_matches(".exe");
        match Command::new("pgrep").args(["-f", clean]).output() {
            Ok(out) => !out.stdout.is_empty(),
            Err(_) => false,
        }
    }
}

/// 强制结束 Windsurf / Windsurf - Next 进程，避免 state.vscdb / storage.json 被锁
fn kill_windsurf(process_name: &str) {
    #[cfg(target_os = "windows")]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        use std::process::Command;
        let _ = Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/F", "/IM", process_name])
            .output();
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::process::Command;
        let clean = process_name.trim_end_matches(".exe");
        let _ = Command::new("pkill").args(["-f", clean]).output();
    }
    // 给系统留出释放文件句柄的时间
    std::thread::sleep(std::time::Duration::from_millis(1200));
}

/// 更新 `%APPDATA%\Windsurf\User\globalStorage\state.vscdb` 里的 `codeium.installationId`。
///
/// Windsurf 后端"too many free user accounts for this device"判定以 `codeium.installationId`
/// 为 primary key，仅重写 `storage.json` 里的 telemetry ID 和注册表 `MachineGuid` 是不够的，
/// 必须把这条指纹一起换新，否则切号还会被后端以同设备为由拒绝登录。
///
/// 字段结构参考（逆向自 account-switch-demo/README.md）：
/// ```json
/// {
///   "codeium.installationId": "<uuid>",
///   "apiServerUrl": "https://server.self-serve.windsurf.com",
///   "codeium.hasOneTimeUpdatedUnspecifiedMode": true
/// }
/// ```
fn reset_state_vscdb_installation_id(state_db_path: &std::path::Path) -> AppResult<Option<String>> {
    if !state_db_path.exists() {
        info!(
            "state.vscdb not found at {:?}, skipping installationId reset",
            state_db_path
        );
        return Ok(None);
    }

    let connection = rusqlite::Connection::open(state_db_path).map_err(|e| {
        AppError::Database(format!(
            "打开 state.vscdb 失败（可能 Windsurf 仍在运行占用文件）: {}. 路径: {:?}",
            e, state_db_path
        ))
    })?;

    // 处理 "database is locked"：最多等 3 秒
    let _ = connection.busy_timeout(std::time::Duration::from_secs(3));

    let raw_value: Option<String> = connection
        .query_row(
            "SELECT value FROM ItemTable WHERE key = 'codeium.windsurf'",
            [],
            |row| row.get(0),
        )
        .ok();

    let new_installation_id = Uuid::new_v4().to_string().to_lowercase();

    let new_value = match raw_value {
        Some(existing) => {
            let mut parsed: Value = serde_json::from_str(&existing).unwrap_or_else(|e| {
                warn!(
                    "codeium.windsurf value 不是合法 JSON，整体改写: {}",
                    e
                );
                json!({})
            });
            parsed["codeium.installationId"] = json!(new_installation_id);
            parsed.to_string()
        }
        None => {
            // key 不存在时，按官方格式补一份最小结构
            json!({
                "codeium.installationId": new_installation_id,
            })
            .to_string()
        }
    };

    connection
        .execute(
            "INSERT INTO ItemTable (key, value) VALUES ('codeium.windsurf', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&new_value],
        )
        .map_err(|e| {
            AppError::Database(format!(
                "写入 state.vscdb 失败: {}. 请确保 Windsurf 已完全关闭再重试",
                e
            ))
        })?;

    info!(
        "Updated codeium.installationId in {:?} to: {}",
        state_db_path, new_installation_id
    );
    Ok(Some(new_installation_id))
}

/// 内部重置机器ID函数
///
/// `kill_running_process` 控制是否在重置前主动结束 Windsurf 进程：
/// - `true`（用户主动点"重置机器 ID"按钮）：杀掉 Windsurf 以避免 storage.json /
///   state.vscdb 被锁，所有写失败都按错误抛出。
/// - `false`（"一键换号"流程内调用）：**不能杀** Windsurf，否则随后的
///   `windsurf://...#access_token=...` deep link 没有 URI handler 接收，切号会失败。
///   此时所有可能因文件被锁或权限问题失败的写入都按 best-effort 处理（warn 后继续），
///   不阻断切号主流程。
async fn reset_machine_id_internal(client_type: &str, kill_running_process: bool) -> AppResult<()> {
    use std::fs;
    use rand::Rng;
    
    // 生成新的机器ID（符合VSCode格式）
    let mut rng = rand::thread_rng();
    
    // machineId: 64位hex字符串（256位）
    let machine_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let new_machine_id = hex::encode(&machine_bytes);
    
    // macMachineId: 32位hex字符串（MD5格式）
    let new_mac_machine_id = format!("{:032x}", rng.gen::<u128>());
    
    // sqmId: UUID格式，不带括号
    let new_sqm_id = Uuid::new_v4().to_string().to_uppercase();
    
    // devDeviceId: 标准UUID格式
    let new_device_id = Uuid::new_v4().to_string().to_lowercase();
    
    // Step 0: Windsurf 运行中会锁住 storage.json / state.vscdb；
    // 但只有用户**主动点重置按钮**才允许杀进程——切号流程里千万不能杀，
    // 否则后续 deep link 没法被接收 → 看起来"账号不登录、不换号"。
    let process_name = windsurf_process_name(client_type);
    if kill_running_process && is_windsurf_running(process_name) {
        info!(
            "Detected running {}, killing it before resetting machine ID",
            process_name
        );
        kill_windsurf(process_name);
    } else if !kill_running_process && is_windsurf_running(process_name) {
        warn!(
            "{} 正在运行，本次只对未锁定的字段做 best-effort 重置；要彻底重置 installationId 请先关闭 Windsurf 再单独点击\"重置机器 ID\"",
            process_name
        );
    }

    // 更新storage.json
    let (_, data_dir_name) = get_client_uri_config(client_type);
    let mut storage_path = directories::BaseDirs::new()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("C:/Users/Default/AppData/Roaming"));
    storage_path.push(data_dir_name);
    storage_path.push("User");
    storage_path.push("globalStorage");
    storage_path.push("storage.json");
    
    if storage_path.exists() {
        let storage_write_result: AppResult<()> = (|| {
            let content = fs::read_to_string(&storage_path)
                .map_err(|e| AppError::FileOperation(format!(
                    "读取 storage.json 失败: {} (os error {:?})",
                    e,
                    e.raw_os_error()
                )))?;
            let mut storage: Value = serde_json::from_str(&content)
                .map_err(AppError::Serialization)?;

            storage["telemetry.machineId"] = json!(new_machine_id);
            storage["telemetry.macMachineId"] = json!(new_mac_machine_id);
            storage["telemetry.sqmId"] = json!(new_sqm_id);
            storage["telemetry.devDeviceId"] = json!(new_device_id);
            // 清掉 firstSession/lastSession 日期，降低 Windsurf 后端"老设备"嫌疑
            if let Some(obj) = storage.as_object_mut() {
                obj.remove("telemetry.firstSessionDate");
                obj.remove("telemetry.lastSessionDate");
                obj.remove("telemetry.currentSessionDate");
            }

            let updated = serde_json::to_string_pretty(&storage)
                .map_err(AppError::Serialization)?;
            fs::write(&storage_path, updated)
                .map_err(|e| {
                    let os = e.raw_os_error();
                    let hint = match os {
                        Some(32) => "文件被占用：请先完全退出 Windsurf（含托盘进程）",
                        Some(5) => "权限不足：请右键以管理员身份运行账号管理器",
                        _ => "请确认 Windsurf 已关闭 & 账号管理器有写入权限",
                    };
                    AppError::FileOperation(format!(
                        "写入 storage.json 失败: {} (os error {:?})。{}",
                        e, os, hint
                    ))
                })?;

            info!("Updated storage.json with new machine IDs");
            Ok(())
        })();

        if let Err(e) = storage_write_result {
            if kill_running_process {
                // 用户主动点重置：写失败必须显式报错
                return Err(e);
            } else {
                // 切号 best-effort：写不进去不阻断流程
                warn!("(best-effort) storage.json 重置跳过: {:?}", e);
            }
        }
    } else {
        warn!("storage.json not found at {:?}", storage_path);
    }

    // 更新 state.vscdb 里的 codeium.installationId（Windsurf 后端主要看的指纹）
    let mut state_db_path = directories::BaseDirs::new()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("C:/Users/Default/AppData/Roaming"));
    state_db_path.push(data_dir_name);
    state_db_path.push("User");
    state_db_path.push("globalStorage");
    state_db_path.push("state.vscdb");
    match reset_state_vscdb_installation_id(&state_db_path) {
        Ok(Some(new_id)) => info!("codeium.installationId reset 成功: {}", new_id),
        Ok(None) => info!("state.vscdb 未找到，跳过 installationId 重置"),
        Err(e) => {
            warn!("Failed to reset codeium.installationId: {:?}", e);
            if kill_running_process {
                // 用户主动点重置：state.vscdb 写失败必须报错让用户知情
                return Err(e);
            } else {
                // 切号 best-effort：state.vscdb 通常被运行中的 Windsurf 锁住，
                // 这里写不进去是正常的；不能阻断后面的 deep link 切号步骤
                warn!("(best-effort) installationId 未能在切号同步重置（Windsurf 运行中锁库属正常），如需彻底重置请先关闭 Windsurf 再点\"重置机器 ID\"");
            }
        }
    }
    
    // Windows特定：更新注册表（程序启动时已要求管理员权限）
    #[cfg(target_os = "windows")]
    {
        // 只更新 HKEY_LOCAL_MACHINE 下的 Cryptography MachineGuid（需要管理员权限）
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        
        // 生成新的GUID（不带大括号的格式）
        let new_machine_guid = Uuid::new_v4().to_string().to_uppercase();
        
        match hklm.open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Cryptography",
            KEY_ALL_ACCESS
        ) {
            Ok(crypto_key) => {
                match crypto_key.set_value("MachineGuid", &new_machine_guid) {
                    Ok(()) => {
                        info!("Updated HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid to: {}", new_machine_guid);
                        Ok(())
                    }
                    Err(e) => {
                        let msg = format!("Failed to update MachineGuid: {}. 确保以管理员权限运行", e);
                        error!("{}", msg);
                        Err(AppError::FileOperation(msg))
                    }
                }
            }
            Err(e) => {
                let msg = format!("Failed to open HKLM\\SOFTWARE\\Microsoft\\Cryptography: {}. 需要管理员权限", e);
                error!("{}", msg);
                Err(AppError::FileOperation(msg))
            }
        }
    }
    
    // macOS特定：尝试重置系统级机器标识
    #[cfg(target_os = "macos")]
    {
        // macOS 的硬件 UUID 无法修改，但可以尝试重置一些软件级别的标识
        // 注意：某些操作可能需要 sudo 权限
        
        // 尝试删除客户端的本地缓存标识文件
        let home = std::env::var("HOME").unwrap_or_default();
        let cache_paths = vec![
            format!("{}/.config/{}/machineid", home, data_dir_name),
            format!("{}/Library/Application Support/{}/.installerId", home, data_dir_name),
        ];
        
        for cache_path in cache_paths {
            let path = PathBuf::from(&cache_path);
            if path.exists() {
                match fs::remove_file(&path) {
                    Ok(()) => info!("Removed cache file: {}", cache_path),
                    Err(e) => warn!("Failed to remove {}: {}", cache_path, e),
                }
            }
        }
        
        // 尝试重置系统级 machine-id（需要 sudo 权限）
        // /var/lib/dbus/machine-id 在 macOS 上通常不存在
        // 但某些应用可能会读取 IOPlatformUUID
        
        info!("macOS machine ID reset completed (software level only)");
        Ok(())
    }
    
    // Linux特定：尝试重置 /etc/machine-id 和 /var/lib/dbus/machine-id
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        
        // 生成新的 machine-id（32位hex字符串）
        let new_linux_machine_id = format!("{:032x}", rand::thread_rng().gen::<u128>());
        
        // 尝试更新 /etc/machine-id（需要 root 权限）
        let etc_machine_id = PathBuf::from("/etc/machine-id");
        if etc_machine_id.exists() {
            match fs::write(&etc_machine_id, format!("{}\n", new_linux_machine_id)) {
                Ok(()) => {
                    info!("Updated /etc/machine-id to: {}", new_linux_machine_id);
                }
                Err(e) => {
                    warn!("Failed to update /etc/machine-id: {}. 需要 sudo 权限", e);
                    // 尝试使用 sudo
                    let result = Command::new("sudo")
                        .args(["bash", "-c", &format!("echo '{}' > /etc/machine-id", new_linux_machine_id)])
                        .output();
                    match result {
                        Ok(output) if output.status.success() => {
                            info!("Updated /etc/machine-id via sudo");
                        }
                        _ => {
                            warn!("Could not update /etc/machine-id even with sudo");
                        }
                    }
                }
            }
        }
        
        // 尝试更新 /var/lib/dbus/machine-id（通常是 /etc/machine-id 的符号链接）
        let dbus_machine_id = PathBuf::from("/var/lib/dbus/machine-id");
        if dbus_machine_id.exists() && !dbus_machine_id.is_symlink() {
            match fs::write(&dbus_machine_id, format!("{}\n", new_linux_machine_id)) {
                Ok(()) => {
                    info!("Updated /var/lib/dbus/machine-id");
                }
                Err(e) => {
                    warn!("Failed to update /var/lib/dbus/machine-id: {}", e);
                }
            }
        }
        
        // 尝试删除客户端的本地缓存标识文件
        let home = std::env::var("HOME").unwrap_or_default();
        let cache_paths = vec![
            format!("{}/.config/{}/machineid", home, data_dir_name),
            format!("{}/.local/share/{}/.installerId", home, data_dir_name),
        ];
        
        for cache_path in cache_paths {
            let path = PathBuf::from(&cache_path);
            if path.exists() {
                match fs::remove_file(&path) {
                    Ok(()) => info!("Removed cache file: {}", cache_path),
                    Err(e) => warn!("Failed to remove {}: {}", cache_path, e),
                }
            }
        }
        
        info!("Linux machine ID reset completed");
        Ok(())
    }
}

/// 重置机器ID命令（供前端调用）
#[tauri::command]
pub async fn reset_machine_id(
    data_store: State<'_, Arc<DataStore>>,
) -> Result<Value, String> {
    let client_type = match data_store.get_settings().await {
        Ok(s) => s.windsurf_client_type,
        Err(_) => "windsurf".to_string(),
    };

    // 事前做一次管理员权限预检，帮用户提前识别出"注册表写失败"的真正原因
    #[cfg(target_os = "windows")]
    let admin_hint = if !is_elevated() {
        Some("未检测到管理员权限：若重置注册表 MachineGuid 失败，请关闭程序后右键→以管理员身份运行")
    } else {
        None
    };
    #[cfg(not(target_os = "windows"))]
    let admin_hint: Option<&str> = None;

    // 用户主动点"重置机器 ID"按钮 → 允许杀 Windsurf 以便能成功改 state.vscdb /
    // storage.json，重置后用户自己再启动 Windsurf 切号即可。
    match reset_machine_id_internal(&client_type, true).await {
        Ok(()) => Ok(json!({
            "success": true,
            "message": match admin_hint {
                Some(hint) => format!("机器ID重置成功。提示：{}", hint),
                None => "机器ID重置成功".to_string(),
            }
        })),
        Err(e) => Ok(json!({
            "success": false,
            "message": match admin_hint {
                Some(hint) => format!("机器ID重置失败: {}\n{}", e, hint),
                None => format!("机器ID重置失败: {}", e),
            }
        }))
    }
}

#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    use std::ptr;
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::handleapi::CloseHandle;
    
    unsafe {
        let mut token_handle: HANDLE = ptr::null_mut();
        
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token_handle
        ) == 0 {
            return false;
        }
        
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size
        );
        
        CloseHandle(token_handle);
        
        result != 0 && elevation.TokenIsElevated != 0
    }
}

/// 检查应用程序是否以管理员/root权限运行
#[tauri::command]
pub async fn check_admin_privileges() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        Ok(is_elevated())
    }
    
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // Unix系统：检查 euid 是否为 0 (root)
        Ok(is_root())
    }
}

/// 检查是否以 root 权限运行 (Unix)
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ============================================================================
// 加密注入模式（safe_storage_inject）
// ============================================================================
//
// 这条路径完全跳过 windsurf://...#access_token=... deep link，复刻 Electron
// safeStorage 的同源加密把账号 apiKey 直接写进 state.vscdb：
//
//   1. 杀掉 Windsurf 进程（避免 SQLite/Local State 被锁）
//   2. 重置 storage.json telemetry IDs + state.vscdb 的 codeium.installationId
//      + 注册表 MachineGuid（reset_machine_id_internal kill=true 路径）
//   3. 从 %APPDATA%\Windsurf\Local State 解 DPAPI 拿出 32 字节 master key
//   4. 用 AES-256-GCM 加密两块密文并以 Buffer JSON 形式写入：
//        - secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}
//        - secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.apiServerUrl"}
//      同时把明文的 windsurfAuthStatus 和 codeium.windsurf 也一起写
//   5. 调起 Windsurf（用户配置的 windsurf_path 或 auto-detect 的路径）
//
// 优点：完全不向 Windsurf 后端发 RegisterUser 请求 → 不会撞 too many free
// 限制：必须先有该账号的 apiKey（Devin = devin-session-token，Firebase = windsurf_api_key）
//       Windsurf safeStorage 加密格式如有变动需要适配
// 参考：jlcodes99/cockpit-tools 的 windsurf_instance.rs

const WINDSURF_AUTH_STATUS_KEY: &str = "windsurfAuthStatus";
const WINDSURF_EXTENSION_STATE_KEY: &str = "codeium.windsurf";
const WINDSURF_SESSIONS_SECRET_KEY: &str =
    r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.sessions"}"#;
const WINDSURF_API_SERVER_SECRET_KEY: &str =
    r#"secret://{"extensionId":"codeium.windsurf","key":"windsurf_auth.apiServerUrl"}"#;
const WINDSURF_DEFAULT_API_SERVER_URL: &str = "https://server.codeium.com";

/// 返回 Windsurf userData 根目录（包含 Local State / User/globalStorage 等）
fn get_windsurf_data_root(client_type: &str) -> PathBuf {
    let (_, data_dir_name) = get_client_uri_config(client_type);
    let mut root = directories::BaseDirs::new()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("C:/Users/Default/AppData/Roaming"));
    root.push(data_dir_name);
    root
}

/// 根据账号体系决定写进 sessions/windsurfAuthStatus 的 apiKey 字段。
///
/// - Devin 账号：`account.token` 自身就是 `devin-session-token$<JWT>`，可直接当 apiKey 用
/// - Firebase 账号：用 GetCurrentUser 拿到的 `windsurf_api_key`（UUID 格式）
fn resolve_inject_api_key(account: &crate::models::account::Account) -> AppResult<String> {
    if account.is_devin_account() {
        let token = account
            .token
            .clone()
            .ok_or_else(|| AppError::ApiRequest(
                "Devin 账号缺少 session-token，请先刷新登录".to_string()
            ))?;
        if token.is_empty() {
            return Err(AppError::ApiRequest(
                "Devin 账号 session-token 为空".to_string()
            ));
        }
        Ok(token)
    } else {
        account
            .windsurf_api_key
            .clone()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| AppError::ApiRequest(
                "Firebase 账号缺少 windsurf_api_key（请先刷新一次账号信息以从 GetCurrentUser 拉取）".to_string()
            ))
    }
}

/// 把账号通过 Electron safeStorage 加密注入到 state.vscdb。
///
/// 此函数**会主动 taskkill** Windsurf 进程并写文件，调用方需保证调用前后做好提示。
async fn inject_account_via_safe_storage(
    client_type: &str,
    account: &crate::models::account::Account,
) -> AppResult<()> {
    use crate::utils::electron_safe_storage::{encode_buffer_json, encrypt_v10, get_windows_master_key};

    info!("[Inject][1/8] 进入加密注入流程: client={} account={} email={}",
        client_type, account.id, account.email);

    // 1) 解析 apiKey + 用户标识（用于 sessions.account.label / windsurfAuthStatus.name）
    let api_key = resolve_inject_api_key(account)?;
    info!(
        "[Inject][2/8] apiKey 解析成功: kind={} length={} prefix={}",
        if account.is_devin_account() { "devin-session-token" } else { "windsurf_api_key" },
        api_key.len(),
        if api_key.len() >= 8 { &api_key[..8] } else { "<short>" },
    );
    let api_server_url = WINDSURF_DEFAULT_API_SERVER_URL.to_string();
    let label = if !account.nickname.is_empty() {
        account.nickname.clone()
    } else {
        account.email.clone()
    };

    // 2) 杀掉 Windsurf 进程（写 state.vscdb 必须独占文件）
    let process_name = windsurf_process_name(client_type);
    if is_windsurf_running(process_name) {
        info!("[Inject][3/8] 检测到 {} 进程在跑，taskkill 中…", process_name);
        kill_windsurf(process_name);
        info!("[Inject][3/8] {} 已结束（含 1.2s 句柄释放等待）", process_name);
    } else {
        info!("[Inject][3/8] {} 进程未运行，跳过 kill", process_name);
    }

    // 3) 同步重置 storage.json + codeium.installationId（reset_machine_id_internal kill=true 路径）
    info!("[Inject][4/8] 重置机器 ID（storage.json + state.vscdb installationId + 注册表 MachineGuid）…");
    if let Err(e) = reset_machine_id_internal(client_type, true).await {
        warn!("[Inject][4/8] reset_machine_id_internal 报错（继续注入，best-effort）: {:?}", e);
    } else {
        info!("[Inject][4/8] 机器 ID 重置完成");
    }

    // 4) 拼出 state.vscdb 路径
    let data_root = get_windsurf_data_root(client_type);
    let mut state_db_path = data_root.clone();
    state_db_path.push("User");
    state_db_path.push("globalStorage");
    state_db_path.push("state.vscdb");
    info!("[Inject][5/8] state.vscdb 路径: {}", state_db_path.display());
    if !state_db_path.exists() {
        return Err(AppError::FileOperation(format!(
            "state.vscdb 不存在: {:?}\n请先启动一次 Windsurf 让它生成本地存储",
            state_db_path
        )));
    }

    // 5) 取出 Electron os_crypt master key
    info!("[Inject][6/8] 调用 DPAPI 解密 Local State.os_crypt.encrypted_key …");
    let master_key = get_windows_master_key(&data_root)?;
    info!(
        "[Inject][6/8] DPAPI 解出 master key: {} bytes (期望 32)",
        master_key.len()
    );

    // 6) 构造并加密 sessions / apiServerUrl
    let session_id = Uuid::new_v4().to_string();
    let sessions_payload = json!([{
        "id": session_id,
        "accessToken": api_key,
        "account": {
            "label": label,
            "id": label,
        },
        "scopes": [],
    }]);
    let sessions_plain = sessions_payload.to_string();
    info!(
        "[Inject][7/8] 加密 sessions：明文 {} bytes / session_id={} / label={}",
        sessions_plain.len(), session_id, label
    );
    let sessions_encrypted = encrypt_v10(&master_key, sessions_plain.as_bytes())?;
    info!(
        "[Inject][7/8] AES-256-GCM 加密完成 sessions：密文 {} bytes (含 v10 prefix + 12B nonce + tag)",
        sessions_encrypted.len()
    );
    let sessions_buffer_json = encode_buffer_json(&sessions_encrypted);

    let api_server_encrypted = encrypt_v10(&master_key, api_server_url.as_bytes())?;
    info!(
        "[Inject][7/8] AES-256-GCM 加密完成 apiServerUrl：明文 {} bytes -> 密文 {} bytes",
        api_server_url.len(), api_server_encrypted.len()
    );
    let api_server_buffer_json = encode_buffer_json(&api_server_encrypted);

    // 7) 构造明文 windsurfAuthStatus + codeium.windsurf
    let auth_status_plain = json!({
        "apiKey": api_key,
        "name": label,
        "email": account.email,
        "apiServerUrl": api_server_url,
    })
    .to_string();

    // 8) 一次事务写入四个 key
    info!("[Inject][8/8] 打开 SQLite 连接 → state.vscdb …");
    let conn = rusqlite::Connection::open(&state_db_path)
        .map_err(|e| AppError::Database(format!("打开 state.vscdb 失败: {}", e)))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(3));

    let upsert_sql = "INSERT INTO ItemTable (key, value) VALUES (?1, ?2) \
                      ON CONFLICT(key) DO UPDATE SET value = excluded.value";

    let n = conn.execute(upsert_sql, (WINDSURF_AUTH_STATUS_KEY, &auth_status_plain))
        .map_err(|e| AppError::Database(format!("写入 windsurfAuthStatus 失败: {}", e)))?;
    info!("[Inject][8/8] UPSERT windsurfAuthStatus 完成 (rows={}, value={} bytes)",
        n, auth_status_plain.len());

    let n = conn.execute(upsert_sql, (WINDSURF_SESSIONS_SECRET_KEY, &sessions_buffer_json))
        .map_err(|e| AppError::Database(format!("写入 windsurf_auth.sessions 失败: {}", e)))?;
    info!("[Inject][8/8] UPSERT windsurf_auth.sessions 完成 (rows={}, value={} bytes)",
        n, sessions_buffer_json.len());

    let n = conn.execute(upsert_sql, (WINDSURF_API_SERVER_SECRET_KEY, &api_server_buffer_json))
        .map_err(|e| AppError::Database(format!("写入 windsurf_auth.apiServerUrl 失败: {}", e)))?;
    info!("[Inject][8/8] UPSERT windsurf_auth.apiServerUrl 完成 (rows={}, value={} bytes)",
        n, api_server_buffer_json.len());

    // codeium.windsurf 是个明文 JSON，原本含 codeium.installationId（reset_machine_id 已经更新过），
    // 这里把 apiServerUrl 也补上（cockpit-tools 的做法），让 Windsurf 启动时直接读到正确 server。
    let existing_extension_state: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1",
            [WINDSURF_EXTENSION_STATE_KEY],
            |row| row.get(0),
        )
        .ok();
    let mut extension_state: Value = existing_extension_state
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = extension_state.as_object_mut() {
        obj.insert("apiServerUrl".to_string(), Value::String(api_server_url.clone()));
    }
    let extension_state_str = extension_state.to_string();
    conn.execute(upsert_sql, (WINDSURF_EXTENSION_STATE_KEY, &extension_state_str))
        .map_err(|e| AppError::Database(format!("写入 codeium.windsurf 失败: {}", e)))?;

    info!("Safe-storage inject 写入完成（4 keys）：path={:?}", state_db_path);
    Ok(())
}

/// 写完 state.vscdb 后调起 Windsurf；找不到路径只 warn 不 abort。
fn relaunch_windsurf(client_type: &str, configured_path: Option<&str>) {
    let path = configured_path
        .filter(|p| !p.is_empty())
        .map(|s| s.to_string())
        .or_else(|| detect_windsurf_path_internal(client_type).ok());
    let Some(path) = path else {
        warn!("找不到 Windsurf 安装路径，跳过自动启动；请手动启动 Windsurf 完成切号");
        return;
    };

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let exe = format!("{}\\Windsurf.exe", path.trim_end_matches('\\'));
        match Command::new(&exe)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            Ok(_) => info!("Windsurf 已重新启动: {}", exe),
            Err(e) => warn!("启动 Windsurf 失败: {} ({})", exe, e),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
    }
}

/// 加密注入模式的一键换号
///
/// 与 `switch_account` 的 OAuth 路径并行存在；由 settings.safe_storage_inject_enabled 决定使用哪条
#[tauri::command]
pub async fn switch_account_via_safe_storage(
    app: AppHandle,
    id: String,
    data_store: State<'_, Arc<DataStore>>,
) -> Result<Value, String> {
    info!("[Inject] Switching account via safe-storage: {}", id);
    emit_switch_progress(&app, "preparing", "开始切换账号（加密注入模式）...", 5, "running");

    let account_id = Uuid::parse_str(&id).map_err(|e| {
        emit_switch_progress(&app, "preparing", format!("账号ID无效: {}", e), 5, "error");
        e.to_string()
    })?;

    let account = data_store
        .get_account(account_id)
        .await
        .map_err(|e| {
            emit_switch_progress(&app, "preparing", format!("读取账号失败: {}", e), 5, "error");
            e.to_string()
        })?;

    let settings = data_store.get_settings().await.map_err(|e| e.to_string())?;
    let client_type = settings.windsurf_client_type.clone();

    emit_switch_progress(&app, "fetch_access", "校验账号 apiKey...", 20, "running");
    if let Err(e) = resolve_inject_api_key(&account) {
        emit_switch_progress(&app, "fetch_access", format!("apiKey 不可用: {}", e), 20, "error");
        return Ok(json!({
            "success": false,
            "error": e.to_string(),
        }));
    }

    emit_switch_progress(&app, "reset_mid", "结束 Windsurf + 重置机器 ID + 加密注入...", 60, "running");
    if let Err(e) = inject_account_via_safe_storage(&client_type, &account).await {
        error!("[Inject] safe-storage inject 失败: {:?}", e);
        emit_switch_progress(&app, "reset_mid", format!("加密注入失败: {}", e), 60, "error");
        return Ok(json!({
            "success": false,
            "error": format!("加密注入失败: {}", e),
        }));
    }

    emit_switch_progress(&app, "callback", "重新启动 Windsurf...", 88, "running");
    relaunch_windsurf(&client_type, settings.windsurf_path.as_deref());

    emit_switch_progress(&app, "finalize", "保存账号状态...", 96, "running");
    if let Some(token) = account.token.clone() {
        let expires_at = account
            .token_expires_at
            .unwrap_or_else(|| Utc::now() + chrono::Duration::days(30));
        if let Err(e) = data_store
            .update_account_token(account_id, token, expires_at)
            .await
        {
            warn!("[Inject] update_account_token 失败（忽略）: {:?}", e);
        }
    }

    emit_switch_progress(&app, "done", "切换完成", 100, "success");
    Ok(json!({
        "success": true,
        "message": "已通过加密注入切换账号并重启 Windsurf（无需 OAuth 回调）",
        "mode": "safe_storage_inject",
    }))
}
