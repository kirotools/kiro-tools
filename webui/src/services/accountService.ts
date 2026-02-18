import { Account, QuotaData } from '../types/account';
import { request as invoke } from '../utils/request';

export async function listAccounts(): Promise<Account[]> {
    const response = await invoke<any>('list_accounts');
    // 如果返回的是对象格式 { accounts: [...] }, 则取其 accounts 属性
    if (response && typeof response === 'object' && Array.isArray(response.accounts)) {
        return response.accounts;
    }
    // 否则直接返回响应内容（假设为数组）
    return response || [];
}

export async function getCurrentAccount(): Promise<Account | null> {
    return await invoke('get_current_account');
}

export interface AddAccountParams {
    refreshToken?: string;
    credsFile?: string;
    sqliteDb?: string;
    authSource?: string;  // "token" | "creds_file" | "aws_sso"
}

export async function addAccount(params: AddAccountParams): Promise<Account> {
    return await invoke('add_account', params);
}

export async function deleteAccount(accountId: string): Promise<void> {
    return await invoke('delete_account', { accountId });
}

export async function deleteAccounts(accountIds: string[]): Promise<void> {
    return await invoke('delete_accounts', { accountIds });
}

export async function switchAccount(accountId: string): Promise<void> {
    return await invoke('switch_account', { accountId });
}

export async function fetchAccountQuota(accountId: string): Promise<QuotaData> {
    return await invoke('fetch_account_quota', { accountId });
}

export interface RefreshStats {
    total: number;
    success: number;
    failed: number;
    details: string[];
}

export async function refreshAllQuotas(): Promise<RefreshStats> {
    return await invoke('refresh_all_quotas');
}

export async function toggleProxyStatus(accountId: string, enable: boolean, reason?: string): Promise<void> {
    return await invoke('toggle_proxy_status', { accountId, enable, reason });
}

/**
 * 重新排序账号列表
 * @param accountIds 按新顺序排列的账号ID数组
 */
export async function reorderAccounts(accountIds: string[]): Promise<void> {
    return await invoke('reorder_accounts', { accountIds });
}

// 导出账号相关 (支持多来源账号)
export interface ExportAccountItem {
    email: string;
    refresh_token: string;
    auth_source?: string;   // "token" | "creds_file" | "aws_sso"
    auth_type?: string;     // "KiroDesktop" | "AwsSsoOidc"
    creds_data?: any;       // 嵌入的凭证文件内容
}

export interface ExportAccountsResponse {
    accounts: ExportAccountItem[];
}

export async function exportAccounts(accountIds: string[]): Promise<ExportAccountsResponse> {
    return await invoke('export_accounts', { accountIds });
}

// 导入账号相关
export interface ImportAccountItem {
    email?: string;
    refresh_token?: string;
    auth_source?: string;
    auth_type?: string;
    creds_data?: any;
}

export interface ImportAccountsResponse {
    total: number;
    success: number;
    failed: number;
    details: { email?: string; success: boolean; error?: string }[];
}

export async function importAccounts(accounts: ImportAccountItem[]): Promise<ImportAccountsResponse> {
    return await invoke('import_accounts', { accounts });
}

// 更新凭据 (force-replace _creds.json and re-enable disabled account)
export interface UpdateCredentialsParams {
    credsFile?: string;
    sqliteDb?: string;
}

export async function updateAccountCredentials(
    accountId: string,
    params: UpdateCredentialsParams
): Promise<Account> {
    return await invoke('update_account_credentials', { accountId, ...params });
}

// 自定义标签相关
export async function updateAccountLabel(accountId: string, label: string): Promise<void> {
    return await invoke('update_account_label', { accountId, label });
}

