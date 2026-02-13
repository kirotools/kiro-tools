import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { Plus, Loader2, CheckCircle2, XCircle, Key, FileJson, Database, ChevronDown } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { AddAccountParams } from '../../services/accountService';

interface AddAccountDialogProps {
    onAdd: (params: AddAccountParams) => Promise<void>;
    showText?: boolean;
}

type AddMethod = 'token' | 'credsFile' | 'sqliteDb';
type Status = 'idle' | 'loading' | 'success' | 'error';

function AddAccountDialog({ onAdd, showText = true }: AddAccountDialogProps) {
    const { t } = useTranslation();
    const [isOpen, setIsOpen] = useState(false);
    const [method, setMethod] = useState<AddMethod>('token');

    // Form values
    const [refreshToken, setRefreshToken] = useState('');
    const [credsFile, setCredsFile] = useState('');
    const [sqliteDb, setSqliteDb] = useState('');

    // UI State
    const [status, setStatus] = useState<Status>('idle');
    const [message, setMessage] = useState('');

    // Reset state when dialog opens
    useEffect(() => {
        if (isOpen) {
            resetState();
        }
    }, [isOpen]);

    const resetState = () => {
        setStatus('idle');
        setMessage('');
        setRefreshToken('');
        setCredsFile('');
        setSqliteDb('');
        setMethod('token');
    };

    const handleSubmit = async () => {
        setStatus('loading');
        setMessage('');

        try {
            let params: AddAccountParams = {};

            if (method === 'token') {
                if (!refreshToken.trim()) {
                    throw new Error(t('accounts.add.token.error_token'));
                }

                // Parse tokens - support batch input
                const input = refreshToken.trim();
                let tokens: string[] = [];

                // Try JSON array
                try {
                    if (input.startsWith('[') && input.endsWith(']')) {
                        const parsed = JSON.parse(input);
                        if (Array.isArray(parsed)) {
                            tokens = parsed
                                .map((item: any) => item.refresh_token || item.refreshToken)
                                .filter((t: any) => typeof t === 'string' && t.length > 20);
                        }
                    }
                } catch (e) {
                    console.debug('JSON parse failed, falling back to regex', e);
                }

                if (tokens.length === 0) {
                    const kiroTokenRegex = /aor[A-Za-z0-9+\/=:\-_]+/g;
                    const matches = input.match(kiroTokenRegex);
                    if (matches) {
                        tokens = matches;
                    }
                }
                
                if (tokens.length === 0 && input.length > 20 && !input.includes(' ') && !input.includes('\n')) {
                    tokens = [input];
                }

                tokens = [...new Set(tokens)];

                if (tokens.length === 0) {
                    throw new Error(t('accounts.add.token.error_token'));
                }

                // Batch add tokens
                let successCount = 0;
                let failCount = 0;

                for (let i = 0; i < tokens.length; i++) {
                    setMessage(t('accounts.add.token.batch_progress', { current: i + 1, total: tokens.length }));
                    try {
                        await onAdd({ refreshToken: tokens[i] });
                        successCount++;
                    } catch (error) {
                        console.error(`Failed to add token ${i + 1}:`, error);
                        failCount++;
                    }
                    await new Promise(r => setTimeout(r, 100));
                }

                if (successCount === tokens.length) {
                    setStatus('success');
                    setMessage(t('accounts.add.token.batch_success', { count: successCount }));
                    setTimeout(() => {
                        setIsOpen(false);
                        resetState();
                    }, 1500);
                } else if (successCount > 0) {
                    setStatus('success');
                    setMessage(t('accounts.add.token.batch_partial', { success: successCount, fail: failCount }));
                } else {
                    throw new Error(t('accounts.add.token.batch_fail'));
                }
                return;

            } else if (method === 'credsFile') {
                if (!credsFile.trim()) {
                    throw new Error(t('accounts.add.creds_file.error_path'));
                }
                params = { credsFile: credsFile.trim() };

            } else if (method === 'sqliteDb') {
                if (!sqliteDb.trim()) {
                    throw new Error(t('accounts.add.sqlite_db.error_path'));
                }
                params = { sqliteDb: sqliteDb.trim() };
            }

            // Single add for file/db methods
            await onAdd(params);
            setStatus('success');
            setMessage(t('accounts.add.success'));
            setTimeout(() => {
                setIsOpen(false);
                resetState();
            }, 1500);

        } catch (error) {
            setStatus('error');
            setMessage(error instanceof Error ? error.message : String(error));
        }
    };

    const methodOptions: { value: AddMethod; label: string; icon: React.ReactNode }[] = [
        { value: 'token', label: t('accounts.add.method.token'), icon: <Key className="w-4 h-4" /> },
        { value: 'credsFile', label: t('accounts.add.method.creds_file'), icon: <FileJson className="w-4 h-4" /> },
        { value: 'sqliteDb', label: t('accounts.add.method.sqlite_db'), icon: <Database className="w-4 h-4" /> },
    ];

    const StatusAlert = () => {
        if (status === 'idle' || !message) return null;

        const styles = {
            loading: 'alert-info',
            success: 'alert-success',
            error: 'alert-error'
        };

        const icons = {
            loading: <Loader2 className="w-5 h-5 animate-spin" />,
            success: <CheckCircle2 className="w-5 h-5" />,
            error: <XCircle className="w-5 h-5" />
        };

        return (
            <div className={`alert ${styles[status]} mb-4 text-sm py-2 shadow-sm`}>
                {icons[status]}
                <span>{message}</span>
            </div>
        );
    };

    return (
        <>
            <button
                className="px-2.5 lg:px-4 py-2 bg-white dark:bg-base-100 text-gray-700 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-base-200 transition-colors flex items-center gap-2 shadow-sm border border-gray-200/50 dark:border-base-300 relative z-[100]"
                onClick={() => setIsOpen(true)}
                title={!showText ? t('accounts.add_account') : undefined}
            >
                <Plus className="w-4 h-4" />
                {showText && <span className="hidden lg:inline">{t('accounts.add_account')}</span>}
            </button>

            {isOpen && createPortal(
                <div
                    className="fixed inset-0 z-[99999] flex items-center justify-center bg-black/50 backdrop-blur-sm"
                    style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0 }}
                >
                    <div className="absolute inset-0 z-[0]" onClick={() => setIsOpen(false)} />

                    <div className="bg-white dark:bg-base-100 text-gray-900 dark:text-base-content rounded-2xl shadow-2xl w-full max-w-lg p-6 relative z-[10] m-4 max-h-[90vh] overflow-y-auto">
                        <h3 className="font-bold text-lg mb-4">{t('accounts.add.title')}</h3>

                        <StatusAlert />

                        <div className="mb-4">
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                {t('accounts.add.method.label')}
                            </label>
                            <div className="relative">
                                <select
                                    value={method}
                                    onChange={(e) => setMethod(e.target.value as AddMethod)}
                                    disabled={status === 'loading' || status === 'success'}
                                    className="w-full px-3 py-2 border border-gray-300 dark:border-base-300 rounded-lg bg-white dark:bg-base-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 appearance-none cursor-pointer"
                                >
                                    {methodOptions.map(opt => (
                                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                                    ))}
                                </select>
                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
                            </div>
                        </div>

                        <div className="min-h-[200px]">
                            {method === 'token' && (
                                <div className="space-y-4 py-2">
                                    <div className="bg-gray-50 dark:bg-base-200 p-4 rounded-lg border border-gray-200 dark:border-base-300">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                                <Key className="w-4 h-4 inline mr-1" />
                                                {t('accounts.add.token.label')}
                                            </span>
                                        </div>
                                        <textarea
                                            className="textarea textarea-bordered w-full h-32 font-mono text-xs leading-relaxed focus:outline-none focus:border-blue-500 transition-colors bg-white dark:bg-base-100 text-gray-900 dark:text-base-content border-gray-300 dark:border-base-300 placeholder:text-gray-400"
                                            placeholder={t('accounts.add.token.placeholder')}
                                            value={refreshToken}
                                            onChange={(e) => setRefreshToken(e.target.value)}
                                            disabled={status === 'loading' || status === 'success'}
                                        />
                                        <p className="text-[10px] text-gray-400 mt-2">
                                            {t('accounts.add.token.hint')}
                                        </p>
                                    </div>
                                </div>
                            )}

                            {method === 'credsFile' && (
                                <div className="space-y-4 py-2">
                                    <div className="bg-gray-50 dark:bg-base-200 p-4 rounded-lg border border-gray-200 dark:border-base-300">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                                <FileJson className="w-4 h-4 inline mr-1" />
                                                {t('accounts.add.creds_file.label')}
                                            </span>
                                        </div>
                                        <input
                                            type="text"
                                            className="input input-bordered w-full font-mono text-sm focus:outline-none focus:border-blue-500 transition-colors bg-white dark:bg-base-100 text-gray-900 dark:text-base-content border-gray-300 dark:border-base-300"
                                            placeholder="~/.aws/sso/cache/kiro-auth-token.json"
                                            value={credsFile}
                                            onChange={(e) => setCredsFile(e.target.value)}
                                            disabled={status === 'loading' || status === 'success'}
                                        />
                                        <p className="text-[10px] text-gray-400 mt-2">
                                            {t('accounts.add.creds_file.hint')}
                                        </p>
                                        <div className="mt-3 text-[10px] text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-base-300 p-2 rounded">
                                            <p className="font-medium mb-1">{t('accounts.add.creds_file.supported')}:</p>
                                            <ul className="list-disc list-inside space-y-0.5">
                                                <li>Kiro IDE: ~/.aws/sso/cache/kiro-auth-token.json</li>
                                                <li>AWS SSO: ~/.aws/sso/cache/*.json</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {method === 'sqliteDb' && (
                                <div className="space-y-4 py-2">
                                    <div className="bg-gray-50 dark:bg-base-200 p-4 rounded-lg border border-gray-200 dark:border-base-300">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                                                <Database className="w-4 h-4 inline mr-1" />
                                                {t('accounts.add.sqlite_db.label')}
                                            </span>
                                        </div>
                                        <input
                                            type="text"
                                            className="input input-bordered w-full font-mono text-sm focus:outline-none focus:border-blue-500 transition-colors bg-white dark:bg-base-100 text-gray-900 dark:text-base-content border-gray-300 dark:border-base-300"
                                            placeholder="~/.local/share/kiro-cli/data.sqlite3"
                                            value={sqliteDb}
                                            onChange={(e) => setSqliteDb(e.target.value)}
                                            disabled={status === 'loading' || status === 'success'}
                                        />
                                        <p className="text-[10px] text-gray-400 mt-2">
                                            {t('accounts.add.sqlite_db.hint')}
                                        </p>
                                        <div className="mt-3 text-[10px] text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-base-300 p-2 rounded">
                                            <p className="font-medium mb-1">{t('accounts.add.sqlite_db.supported')}:</p>
                                            <ul className="list-disc list-inside space-y-0.5">
                                                <li>kiro-cli: ~/.local/share/kiro-cli/data.sqlite3</li>
                                                <li>amazon-q: ~/.local/share/amazon-q/data.sqlite3</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>

                        <div className="flex gap-3 w-full mt-6">
                            <button
                                className="flex-1 px-4 py-2.5 bg-gray-100 dark:bg-base-200 text-gray-700 dark:text-gray-300 font-medium rounded-xl hover:bg-gray-200 dark:hover:bg-base-300 transition-colors focus:outline-none focus:ring-2 focus:ring-200 dark:focus:ring-base-300"
                                onClick={() => setIsOpen(false)}
                                disabled={status === 'success'}
                            >
                                {t('accounts.add.btn_cancel')}
                            </button>
                            <button
                                className="flex-1 px-4 py-2.5 text-white font-medium rounded-xl shadow-md transition-all focus:outline-none focus:ring-2 focus:ring-offset-2 bg-blue-500 hover:bg-blue-600 focus:ring-blue-500 shadow-blue-100 dark:shadow-blue-900/30 flex justify-center items-center gap-2"
                                onClick={handleSubmit}
                                disabled={status === 'loading' || status === 'success'}
                            >
                                {status === 'loading' ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                                {t('accounts.add.btn_confirm')}
                            </button>
                        </div>
                    </div>
                </div>,
                document.body
            )}
        </>
    );
}

export default AddAccountDialog;
