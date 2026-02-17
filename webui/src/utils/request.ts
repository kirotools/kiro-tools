// 探测环境
const isTauri = false; // Force web mode


// 命令到 API 的映射
const COMMAND_MAPPING: Record<string, { url: string; method: 'GET' | 'POST' | 'DELETE' | 'PATCH' }> = {
  // Accounts
  'list_accounts': { url: '/api/accounts', method: 'GET' },
  'get_current_account': { url: '/api/accounts/current', method: 'GET' },
  'switch_account': { url: '/api/accounts/switch', method: 'POST' },
  'add_account': { url: '/api/accounts', method: 'POST' },
  'delete_account': { url: '/api/accounts/:accountId', method: 'DELETE' },
  'delete_accounts': { url: '/api/accounts/bulk-delete', method: 'POST' },
  'fetch_account_quota': { url: '/api/accounts/:accountId/quota', method: 'GET' },
  'refresh_account_quota': { url: '/api/accounts/:accountId/quota', method: 'GET' },
  'refresh_all_quotas': { url: '/api/accounts/refresh', method: 'POST' },
  'reorder_accounts': { url: '/api/accounts/reorder', method: 'POST' },
  'toggle_proxy_status': { url: '/api/accounts/:accountId/toggle-proxy', method: 'POST' },
  'update_account_label': { url: '/api/accounts/:accountId/label', method: 'POST' },
  'export_accounts': { url: '/api/accounts/export', method: 'POST' },
  'import_accounts': { url: '/api/accounts/import', method: 'POST' },

  // Proxy Control & Status
  'get_proxy_status': { url: '/api/proxy/status', method: 'GET' },
  'start_proxy_service': { url: '/api/proxy/start', method: 'POST' },
  'stop_proxy_service': { url: '/api/proxy/stop', method: 'POST' },
  'update_model_mapping': { url: '/api/proxy/mapping', method: 'POST' },
  'generate_api_key': { url: '/api/proxy/api-key/generate', method: 'POST' },
  'clear_proxy_session_bindings': { url: '/api/proxy/session-bindings/clear', method: 'POST' },
  'clear_proxy_rate_limit': { url: '/api/proxy/rate-limits/:accountId', method: 'DELETE' },
  'clear_all_proxy_rate_limits': { url: '/api/proxy/rate-limits', method: 'DELETE' },
  'check_proxy_health': { url: '/api/proxy/health-check/trigger', method: 'POST' },
  'get_preferred_account': { url: '/api/proxy/preferred-account', method: 'GET' },
  'set_preferred_account': { url: '/api/proxy/preferred-account', method: 'POST' },
  'load_config': { url: '/api/config', method: 'GET' },
  'save_config': { url: '/api/config', method: 'POST' },
  'get_proxy_stats': { url: '/api/proxy/stats', method: 'GET' },
  'list_proxy_models': { url: '/api/proxy/models', method: 'GET' },
  'set_proxy_monitor_enabled': { url: '/api/proxy/monitor/toggle', method: 'POST' },

  // Logs & Monitoring
  'get_proxy_logs_filtered': { url: '/api/logs', method: 'GET' },
  'get_proxy_logs_count_filtered': { url: '/api/logs/count', method: 'GET' },
  'clear_proxy_logs': { url: '/api/logs/clear', method: 'POST' },
  'get_proxy_log_detail': { url: '/api/logs/:logId', method: 'GET' },

  // Debug Console
  'enable_debug_console': { url: '/api/debug/enable', method: 'POST' },
  'disable_debug_console': { url: '/api/debug/disable', method: 'POST' },
  'is_debug_console_enabled': { url: '/api/debug/enabled', method: 'GET' },
  'get_debug_console_logs': { url: '/api/debug/logs', method: 'GET' },
  'clear_debug_console_logs': { url: '/api/debug/logs/clear', method: 'POST' },

  // CLI Sync
  'get_cli_sync_status': { url: '/api/proxy/cli/status', method: 'POST' },
  'execute_cli_sync': { url: '/api/proxy/cli/sync', method: 'POST' },
  'execute_cli_restore': { url: '/api/proxy/cli/restore', method: 'POST' },
  'get_cli_config_content': { url: '/api/proxy/cli/config', method: 'POST' },

  // OpenCode Sync
  'get_opencode_sync_status': { url: '/api/proxy/opencode/status', method: 'POST' },
  'execute_opencode_sync': { url: '/api/proxy/opencode/sync', method: 'POST' },
  'execute_opencode_restore': { url: '/api/proxy/opencode/restore', method: 'POST' },
  'get_opencode_config_content': { url: '/api/proxy/opencode/config', method: 'POST' },

  // Kiro Quota & Droid Sync
  'get_kiro_quota': { url: '/api/proxy/kiro/quota', method: 'POST' },
  'get_droid_sync_status': { url: '/api/proxy/droid/status', method: 'POST' },
  'execute_droid_sync': { url: '/api/proxy/droid/sync', method: 'POST' },
  'execute_droid_restore': { url: '/api/proxy/droid/restore', method: 'POST' },
  'get_droid_config_content': { url: '/api/proxy/droid/config', method: 'POST' },

  // Stats
  'get_token_stats_hourly': { url: '/api/stats/token/hourly', method: 'GET' },
  'get_token_stats_daily': { url: '/api/stats/token/daily', method: 'GET' },
  'get_token_stats_weekly': { url: '/api/stats/token/weekly', method: 'GET' },
  'get_token_stats_by_account': { url: '/api/stats/token/by-account', method: 'GET' },
  'get_token_stats_summary': { url: '/api/stats/token/summary', method: 'GET' },
  'get_token_stats_by_model': { url: '/api/stats/token/by-model', method: 'GET' },
  'get_token_stats_model_trend_hourly': { url: '/api/stats/token/model-trend/hourly', method: 'GET' },
  'get_token_stats_model_trend_daily': { url: '/api/stats/token/model-trend/daily', method: 'GET' },
  'get_token_stats_account_trend_hourly': { url: '/api/stats/token/account-trend/hourly', method: 'GET' },
  'get_token_stats_account_trend_daily': { url: '/api/stats/token/account-trend/daily', method: 'GET' },
  'clear_token_stats': { url: '/api/stats/token/clear', method: 'POST' },

  // System
  'get_data_dir_path': { url: '/api/system/data-dir', method: 'GET' },
  'get_update_settings': { url: '/api/system/updates/settings', method: 'GET' },
  'save_update_settings': { url: '/api/system/updates/save', method: 'POST' },
  'get_http_api_settings': { url: '/api/system/http-api/settings', method: 'GET' },
  'save_http_api_settings': { url: '/api/system/http-api/settings', method: 'POST' },

  // Cloudflared
  'cloudflared_install': { url: '/api/proxy/cloudflared/install', method: 'POST' },
  'cloudflared_start': { url: '/api/proxy/cloudflared/start', method: 'POST' },
  'cloudflared_stop': { url: '/api/proxy/cloudflared/stop', method: 'POST' },
  'cloudflared_get_status': { url: '/api/proxy/cloudflared/status', method: 'GET' },

  // Updates
  'should_check_updates': { url: '/api/system/updates/check-status', method: 'GET' },
  'check_for_updates': { url: '/api/system/updates/check', method: 'POST' },
  'update_last_check_time': { url: '/api/system/updates/touch', method: 'POST' },

  // System Extra & Cache
  'open_data_folder': { url: '/api/system/open-folder', method: 'POST' },
  'clear_kiro_cache': { url: '/api/system/cache/clear', method: 'POST' },
  'get_kiro_cache_paths': { url: '/api/system/cache/paths', method: 'GET' },
  'clear_log_cache': { url: '/api/system/logs/clear-cache', method: 'POST' },
  'show_directory_dialog': { url: '/api/system/dialog/directory', method: 'GET' },

  // Security / IP Management
  'get_ip_access_logs': { url: '/api/security/logs', method: 'GET' },
  'clear_ip_access_logs': { url: '/api/security/logs/clear', method: 'POST' },
  'get_ip_stats': { url: '/api/security/stats', method: 'GET' },
  'get_ip_token_stats': { url: '/api/security/token-stats', method: 'GET' },
  'get_ip_blacklist': { url: '/api/security/blacklist', method: 'GET' },
  'add_ip_to_blacklist': { url: '/api/security/blacklist', method: 'POST' },
  'remove_ip_from_blacklist': { url: '/api/security/blacklist', method: 'DELETE' },
  'clear_ip_blacklist': { url: '/api/security/blacklist/clear', method: 'POST' },
  'check_ip_in_blacklist': { url: '/api/security/blacklist/check', method: 'GET' },
  'get_ip_whitelist': { url: '/api/security/whitelist', method: 'GET' },
  'add_ip_to_whitelist': { url: '/api/security/whitelist', method: 'POST' },
  'remove_ip_from_whitelist': { url: '/api/security/whitelist', method: 'DELETE' },
  'clear_ip_whitelist': { url: '/api/security/whitelist/clear', method: 'POST' },
  'check_ip_in_whitelist': { url: '/api/security/whitelist/check', method: 'GET' },
  'get_security_config': { url: '/api/security/config', method: 'GET' },
  'update_security_config': { url: '/api/security/config', method: 'POST' },
  // User Tokens
  'list_user_tokens': { url: '/api/user-tokens', method: 'GET' },
  'get_user_token_summary': { url: '/api/user-tokens/summary', method: 'GET' },
  'create_user_token': { url: '/api/user-tokens', method: 'POST' },
  'renew_user_token': { url: '/api/user-tokens/:id/renew', method: 'POST' },
  'delete_user_token': { url: '/api/user-tokens/:id', method: 'DELETE' },
  'update_user_token': { url: '/api/user-tokens/:id', method: 'PATCH' },

  // Proxy Pool (Web Mode Fix)
  'get_proxy_pool_config': { url: '/api/proxy/pool/config', method: 'GET' },
  'get_all_account_bindings': { url: '/api/proxy/pool/bindings', method: 'GET' },
  'bind_account_proxy': { url: '/api/proxy/pool/bind', method: 'POST' },
  'unbind_account_proxy': { url: '/api/proxy/pool/unbind', method: 'POST' },
  'get_account_proxy_binding': { url: '/api/proxy/pool/binding/:accountId', method: 'GET' },
};

export async function request<T>(cmd: string, args?: any): Promise<T> {
  // 1. Web 环境：映射到 HTTP API
  const mapping = COMMAND_MAPPING[cmd];
  if (!mapping) {
    console.error(`Command [${cmd}] is not yet mapped for Web mode. Failing.`);
    throw new Error(`Command [${cmd}] not supported in Web mode.`);
  }

  let url = mapping.url;
  // [FIX] 创建 args 副本，用于移除已使用的路径参数
  let bodyArgs = args ? { ...args } : undefined;

  // 通用路径参数处理：替换 :key 为 args[key]
  if (args) {
    Object.keys(args).forEach(key => {
      const placeholder = `:${key}`;
      if (url.includes(placeholder)) {
        url = url.replace(placeholder, encodeURIComponent(String(args[key])));
        // [FIX] 从 body 参数中移除已用于路径的参数
        if (bodyArgs) {
          delete bodyArgs[key];
        }
      }
    });
  }

  const apiKey = typeof window !== 'undefined' ? sessionStorage.getItem('abv_admin_api_key') : null;

  const options: RequestInit = {
    method: mapping.method,
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? {
        'Authorization': `Bearer ${apiKey}`,
        'x-api-key': apiKey
      } : {}),
    },
  };

  if ((mapping.method === 'GET' || mapping.method === 'DELETE') && bodyArgs) {
    const params = new URLSearchParams();
    Object.entries(bodyArgs).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        params.append(key, String(value));
      }
    });
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  } else if ((mapping.method === 'POST' || mapping.method === 'PATCH') && bodyArgs) {
    // [FIX] 如果有 request 包装，提取其内容作为 body
    const body = bodyArgs.request !== undefined ? bodyArgs.request : bodyArgs;
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      if (!isTauri && response.status === 401) {
        // [FIX #1163] 增加防抖锁，避免重复事件导致 UI 抖动
        const now = Date.now();
        const lastAuthError = (window as any)._lastAuthErrorTime || 0;
        if (now - lastAuthError > 2000) {
          (window as any)._lastAuthErrorTime = now;
          window.dispatchEvent(new CustomEvent('abv-unauthorized'));
        }
      }
      const errorData = await response.json().catch(() => ({}));
      const err = errorData.error;
      const errMsg = typeof err === 'object' && err !== null
        ? (typeof err.message === 'string' ? err.message : JSON.stringify(err))
        : (typeof err === 'string' ? err : undefined);
      throw errMsg || `HTTP Error ${response.status}`;
    }

    // 如果是 204 No Content，返回空数组（保持与期望类型一致）
    if (response.status === 204) {
      return [] as unknown as T;
    }

    const text = await response.text();
    if (!text || text.trim() === '') {
      return [] as unknown as T;
    }

    try {
      return JSON.parse(text) as T;
    } catch (e) {
      console.warn(`Failed to parse JSON response for [${cmd}]:`, text);
      return text as unknown as T; // Fallback for plain text responses
    }
  } catch (error) {
    console.error(`Web Fetch Error [${cmd}]:`, error);
    const msg = error instanceof Error ? error.message : (typeof error === 'string' ? error : String(error));
    throw msg;
  }
}
