export interface Account {
    id: string;
    email: string;
    name?: string;
    token: TokenData;
    quota?: QuotaData;
    disabled?: boolean;
    disabled_reason?: string;
    disabled_at?: number;
    proxy_disabled?: boolean;
    proxy_disabled_reason?: string;
    proxy_disabled_at?: number;
    protected_models?: string[];
    custom_label?: string;
    created_at: number;
    last_used: number;
}

export interface TokenData {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    expiry_timestamp: number;
    token_type: string;
    email?: string;
}

export interface QuotaData {
    models: ModelQuota[];
    last_updated: number;
    is_forbidden?: boolean;
    subscription_tier?: string;  // 订阅类型: FREE/PRO/PRO+/POWER (e.g. Q_DEVELOPER_STANDALONE_POWER)
}

export interface ModelQuota {
    name: string;
    percentage: number;
    reset_time: string;
    usage_limit?: number;
    current_usage?: number;
}

