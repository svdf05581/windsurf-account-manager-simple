mod models;
mod repository;
mod services;
mod commands;
mod utils;

use repository::DataStore;
use commands::{AutoResetStore, ResetRecordStore};
use std::sync::Arc;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logger();
    log::info!("=== windsurf-account-manager started (log level=info) ===");

    
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        // 自动更新能力（静默检查 + 下载 + 安装）：
        // - endpoints / pubkey 在 tauri.conf.json 的 plugins.updater 中配置
        // - 前端通过 @tauri-apps/plugin-updater 触发 check / downloadAndInstall
        .plugin(tauri_plugin_updater::Builder::new().build())
        // 更新完成后需要调用 process.relaunch() 重启应用以加载新版本
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // 初始化数据存储
            let store = DataStore::new(app.handle())
                .expect("Failed to initialize data store");
            let store = Arc::new(store);
            
            // 将数据存储注入到应用状态
            app.manage(store.clone());
            
            // 初始化自动重置配置存储
            let auto_reset_store = AutoResetStore::new(app.handle())
                .expect("Failed to initialize auto reset store");
            app.manage(Arc::new(auto_reset_store));
            
            // 初始化重置记录存储
            let reset_record_store = ResetRecordStore::new(app.handle())
                .expect("Failed to initialize reset record store");
            app.manage(Arc::new(reset_record_store));
            
            // 初始化代理配置
            let store_for_proxy = store.clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(settings) = store_for_proxy.get_settings().await {
                    if settings.proxy_enabled || settings.proxy_url.is_some() {
                        println!("[Init] Loading proxy config: enabled={}, url={:?}", 
                            settings.proxy_enabled, settings.proxy_url);
                        services::update_proxy_config(
                            settings.proxy_enabled,
                            settings.proxy_url
                        );
                    }
                }
            });
            
            // 获取版本号并设置窗口标题
            let version = app.package_info().version.to_string();
            if let Some(window) = app.get_webview_window("main") {
                let title = format!("windsurf-account-manager-simple v{}", version);
                window.set_title(&title).ok();
            }
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 日志命令
            get_log_file_path,
            // 账号管理命令
            commands::add_account,
            commands::add_account_by_refresh_token,
            commands::get_all_accounts,
            commands::get_account,
            commands::update_account,
            commands::delete_account,
            commands::delete_accounts_batch,
            commands::search_accounts,
            commands::filter_accounts_by_group,
            commands::filter_accounts_by_tags,
            
            // API操作命令
            commands::login_account,
            commands::refresh_token,
            commands::get_plan_status,
            commands::reset_credits,
            commands::update_seats,
            commands::get_billing,
            commands::update_plan,
            commands::cancel_subscription,
            commands::resume_subscription,
            commands::get_account_info,
            commands::get_current_user,
            commands::batch_reset_credits,
            commands::batch_refresh_tokens,
            commands::get_team_credit_entries,
            commands::get_trial_payment_link,
            commands::get_team_config,
            commands::update_team_config,
            commands::get_cascade_model_configs,
            commands::get_command_model_configs,
            commands::get_team_organizational_controls,
            commands::upsert_team_organizational_controls,
            commands::get_available_mcp_plugins,
            commands::delete_windsurf_user,
            // Pro 试用资格检查
            commands::check_pro_trial_eligibility,
            commands::get_account_valid_token,
            // 用户API密钥管理
            commands::get_api_key_summary,
            commands::delete_api_key,
            commands::register_user_api_key,
            // 第三方API Provider Key管理
            commands::get_set_user_api_provider_keys,
            commands::set_user_api_provider_key,
            commands::delete_user_api_provider_key,
            // 迁移 / 开发者主密钥 / 排行榜
            commands::migrate_api_key,
            commands::get_primary_api_key_for_devs,
            commands::get_global_leaderboard_api_key,
            commands::get_leaderboard,
            
            // 支付相关命令
            commands::generate_virtual_card,
            commands::open_payment_window,
            commands::inject_card_info,
            commands::validate_card_number,
            commands::auto_fill_payment_form,
            commands::get_trial_payment_link_enhanced,
            commands::open_external_link,
            commands::open_external_link_incognito,
            commands::inject_auto_submit_script,
            commands::close_payment_window,
            commands::get_success_bins,
            commands::add_success_bin,
            commands::clear_success_bins,
            commands::get_random_success_bin,
            commands::reset_test_mode_progress,
            commands::get_test_mode_progress,
            
            // Protobuf解析API命令（返回解析后的数据）
            commands::get_current_user_parsed,
            commands::get_billing_parsed,
            commands::batch_get_users_parsed,

            // Analytics 分析命令
            commands::get_account_analytics,

            // 设置管理命令
            commands::get_settings,
            commands::update_settings,
            commands::get_groups,
            commands::add_group,
            commands::delete_group,
            commands::rename_group,
            commands::get_tags,
            commands::add_tag,
            commands::update_tag,
            commands::delete_tag,
            commands::batch_update_account_tags,
            commands::get_logs,
            commands::clear_logs,
            commands::get_stats,
            commands::export_data,
            
            // 切号相关命令
            commands::switch_account,
            commands::switch_account_via_safe_storage,
            commands::reset_machine_id,
            commands::check_admin_privileges,
            
            // Windsurf信息命令
            commands::get_current_windsurf_info,
            
            // 应用信息命令
            commands::get_app_version,
            commands::get_app_title,
            commands::reset_http_client,
            
            // 无感换号补丁命令
            commands::get_windsurf_path,
            commands::apply_seamless_patch,
            commands::restore_seamless_patch,
            commands::check_patch_status,
            commands::validate_windsurf_path,
            
            // 伟哥(寸止)命令
            commands::check_cunzhi_status,
            commands::install_cunzhi,
            commands::uninstall_cunzhi,
            
            // 数据备份命令
            commands::create_backup,
            commands::list_backups,
            commands::restore_backup,
            commands::delete_backup,
            commands::export_data_to_file,
            commands::import_data_from_file,
            commands::get_data_directory,
            
            // 排序命令
            commands::get_sorted_accounts,
            commands::update_accounts_order,
            commands::update_sort_config,
            commands::get_sort_config,
            
            // 团队管理命令
            commands::get_team_members,
            commands::invite_team_members,
            commands::remove_team_member,
            commands::revoke_invitation,
            commands::get_pending_invitations,
            commands::get_my_pending_invitation,
            commands::accept_invitation,
            commands::reject_invitation,
            commands::request_team_access,
            commands::approve_team_join_request,
            // 自动充值管理
            commands::get_credit_top_up_settings,
            commands::update_credit_top_up_settings,
            // 成员权限管理
            commands::update_codeium_access,
            commands::add_user_role,
            commands::remove_user_role,
            commands::transfer_subscription,
            
            // 自动重置命令
            commands::get_auto_reset_configs,
            commands::add_auto_reset_config,
            commands::update_auto_reset_config,
            commands::delete_auto_reset_config,
            commands::check_and_auto_reset,
            commands::force_reset_config,
            commands::get_reset_records,
            commands::get_reset_stats,
            commands::clear_reset_records,

            // Devin Session 账密登录
            commands::devin_check_connections,
            commands::devin_password_login,
            commands::devin_windsurf_post_auth,
            commands::add_account_by_devin_login,
            commands::add_account_by_devin_with_org,
            commands::refresh_devin_session,
            commands::add_account_by_devin_session_token,
            commands::add_account_by_devin_auth1_token,
            // Firebase ↔ Devin 账号互转
            commands::convert_account_to_devin,
            commands::convert_account_to_firebase,

            // 登录流派智能嗅探（方案 B：自动嗅探 + 统一入口）
            commands::devin_check_user_login_method,
            commands::sniff_login_method,

            // Devin 邮箱注册 / 无密码邮件登录 / 忘记密码（Windsurf 侧 _devin-auth 通道）
            commands::devin_email_start,
            commands::devin_email_complete,
            commands::devin_password_reset_start,
            commands::devin_password_reset_complete,
            commands::add_account_by_devin_register,
            commands::add_account_by_devin_email_login,

            // Devin 原生站点（app.devin.ai）注册通道：独立端口 /api/auth1/*，注册后自动桥接 Windsurf
            commands::devin_app_check_connections,
            commands::devin_app_email_start,
            commands::devin_app_email_complete,
            commands::add_account_by_devin_native_register,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// 初始化日志：默认 info 级别 + 同时写到 stderr 与 `<UserData>/windsurf-account-manager/app.log`。
///
/// 由于 release 构建走 `windows_subsystem = "windows"`，stderr 被分离，单纯的 env_logger
/// 在 GUI 下"日志看不见"。这里同时写文件，用户可通过日志面板的"打开日志文件夹"按钮直接打开。
/// 文件按 5MB 简单滚动（写满后归档为 app.log.1，再开新 app.log），最多保留 3 份历史。
fn init_logger() {
    use std::io::Write;
    use std::sync::Mutex;

    struct DualWriter {
        stderr: std::io::Stderr,
        file: Mutex<Option<std::fs::File>>,
    }
    impl Write for DualWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.stderr.write_all(buf);
            if let Ok(mut guard) = self.file.lock() {
                if let Some(f) = guard.as_mut() {
                    let _ = f.write_all(buf);
                }
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let _ = self.stderr.flush();
            if let Ok(mut guard) = self.file.lock() {
                if let Some(f) = guard.as_mut() {
                    let _ = f.flush();
                }
            }
            Ok(())
        }
    }

    let log_file_path = log_file_path();
    let file = log_file_path.as_ref().and_then(|p| {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        rotate_log_if_needed(p);
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
    });

    let dual = DualWriter {
        stderr: std::io::stderr(),
        file: Mutex::new(file),
    };

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(
            "info,hyper=warn,reqwest=warn,rustls=warn,h2=warn,tower=warn,tao=warn,wry=warn",
        ),
    )
    .format_timestamp_millis()
    .target(env_logger::Target::Pipe(Box::new(dual)))
    .init();

    if let Some(p) = log_file_path {
        log::info!("Log file: {}", p.display());
    }
}

/// 返回日志文件路径：`<UserData>/windsurf-account-manager/app.log`
fn log_file_path() -> Option<std::path::PathBuf> {
    directories::BaseDirs::new().map(|dirs| {
        let mut p = dirs.data_dir().to_path_buf();
        p.push("windsurf-account-manager");
        p.push("app.log");
        p
    })
}

/// 简易文件滚动：app.log > 5MB 时改名为 app.log.1，最多保留 .1 / .2 / .3 三份历史
fn rotate_log_if_needed(p: &std::path::Path) {
    const MAX_SIZE: u64 = 5 * 1024 * 1024;
    let size = match std::fs::metadata(p) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    if size < MAX_SIZE {
        return;
    }
    let with_ext = |n: u32| {
        let mut owned = p.to_path_buf();
        owned.set_extension(format!("log.{}", n));
        owned
    };
    let _ = std::fs::remove_file(with_ext(3));
    let _ = std::fs::rename(with_ext(2), with_ext(3));
    let _ = std::fs::rename(with_ext(1), with_ext(2));
    let mut log_1 = p.to_path_buf();
    log_1.set_extension("log.1");
    let _ = std::fs::rename(p, &log_1);
}

/// 暴露给前端的命令：返回当前日志文件路径
#[tauri::command]
fn get_log_file_path() -> Option<String> {
    log_file_path().map(|p| p.to_string_lossy().to_string())
}
