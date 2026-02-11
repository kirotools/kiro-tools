import { useEffect, useState, useRef } from 'react';
import { Maximize2, RefreshCw, Clock, ShieldAlert, Tag, Activity } from 'lucide-react';
import { useViewStore } from '../../stores/useViewStore';
import { useAccountStore } from '../../stores/useAccountStore';
import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import clsx from 'clsx';
import { formatCompactNumber } from '../../utils/format';

import { useConfigStore } from '../../stores/useConfigStore';

interface ProxyRequestLog {
    id: string;
    model?: string;
    input_tokens?: number;
    output_tokens?: number;
    timestamp: number;
    status: number;
    duration: number;
    mapped_model?: string
}

export default function MiniView() {
    const { setMiniView } = useViewStore();
    const { currentAccount, refreshQuota, fetchCurrentAccount } = useAccountStore();
    const { config } = useConfigStore();
    const { t } = useTranslation();
    const [isRefreshing, setIsRefreshing] = useState(false);
    const containerRef = useRef<HTMLDivElement>(null);
    const [appVersion, setAppVersion] = useState('0.0.0');
    const [latestLog, _setLatestLog] = useState<ProxyRequestLog | null>(null);

    // No-op for web-only build
    useEffect(() => {
    }, []);
    // Get app version
    useEffect(() => {
        setAppVersion('1.0.0');
    }, []);

    // Auto-refresh logic based on config
    useEffect(() => {
        if (!config?.auto_refresh || !config?.refresh_interval || config.refresh_interval <= 0) return;

        console.log(`[MiniView] Starting auto-refresh timer: ${config.refresh_interval} mins`);

        const intervalId = setInterval(() => {
            if (!isRefreshing && currentAccount) {
                console.log('[MiniView] Auto-refreshing quota...');
                handleRefresh();
            }
        }, config.refresh_interval * 60 * 1000);

        return () => clearInterval(intervalId);
    }, [config?.auto_refresh, config?.refresh_interval, currentAccount, isRefreshing]);

    // Enter mini mode & Auto-resize based on content
    useEffect(() => {
        // No-op in web mode (no window resizing)
    }, [currentAccount]);

    const handleRefresh = async () => {
        if (!currentAccount || isRefreshing) return;
        setIsRefreshing(true);
        try {
            await refreshQuota(currentAccount.id);
            await fetchCurrentAccount();
        } finally {
            setTimeout(() => setIsRefreshing(false), 800);
        }
    };

    const handleMaximize = async () => {
        setMiniView(false);
    };


        const handleMouseDown = () => {
        // No-op in web mode (no window dragging)
    };


    // Extract specific models to match CurrentAccount.tsx
    const creditModel = currentAccount?.quota?.models.find(m => m.name === 'kiro-credit');

    // Helper to render a model row
    const renderModelRow = (model: any, displayName: string, colorClass: string) => {
        if (!model) return null;

        // Determine status color based on percentage
        const getStatusColor = (p: number) => {
            if (p >= 50) return 'text-emerald-500';
            if (p >= 20) return 'text-amber-500';
            return 'text-rose-500';
        };

        const getBarColor = (p: number) => {
            if (p >= 50) return colorClass === 'cyan' ? 'bg-gradient-to-r from-cyan-400 to-cyan-500' : 'bg-gradient-to-r from-emerald-400 to-emerald-500';
            if (p >= 20) return colorClass === 'cyan' ? 'bg-gradient-to-r from-orange-400 to-orange-500' : 'bg-gradient-to-r from-amber-400 to-amber-500';
            return 'bg-gradient-to-r from-rose-400 to-rose-500';
        };

        return (
            <motion.div
                layout
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-1.5"
            >
                <div className="flex justify-between items-baseline">
                    <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{displayName}</span>
                    <div className="flex items-center gap-2">
                        <span className={clsx("text-xs font-bold", getStatusColor(model.percentage))}>
                            {model.percentage}%
                        </span>
                    </div>
                </div>
                <div className="w-full bg-gray-100 dark:bg-white/10 rounded-full h-1.5 overflow-hidden">
                    <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${model.percentage}%` }}
                        transition={{ duration: 0.8, ease: "easeOut" }}
                        className={clsx("h-full rounded-full shadow-[0_0_8px_currentColor]", getBarColor(model.percentage))}
                    />
                </div>
            </motion.div>
        );
    };

    return (
        <div className="h-screen w-full flex items-center justify-center bg-transparent">
            {/* Main Container - 300px fixed width */}
            <motion.div
                ref={containerRef}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className="w-[300px] flex flex-col bg-white/80 dark:bg-[#121212]/80 backdrop-blur-md shadow-2xl overflow-hidden border-x border-y border-gray-200/50 dark:border-white/10 sm:rounded-2xl"
            >
                {/* Header / Drag Region */}
                <div
                    className="flex-none flex items-center justify-between px-4 py-1 bg-gray-50/50 dark:bg-white/5 border-b border-gray-100 dark:border-white/5 select-none"
                    onMouseDown={handleMouseDown}
                    data-tauri-drag-region
                >
                    <div className="flex items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white overflow-hidden">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)] animate-pulse shrink-0" />
                        <span className="truncate" title={currentAccount?.email}>
                            {currentAccount?.email?.split('@')[0] || 'No Account'}
                        </span>
                    </div>

                    <div
                        className="flex items-center gap-1 no-drag shrink-0"
                        onMouseDown={(e) => e.stopPropagation()}
                    >
                        <button
                            onClick={handleRefresh}
                            className={clsx(
                                "p-2 rounded-lg hover:bg-gray-200/50 dark:hover:bg-white/10 transition-colors",
                                isRefreshing && "animate-spin text-blue-500"
                            )}
                            title={t('common.refresh', 'Refresh')}
                        >
                            <RefreshCw size={14} />
                        </button>
                        <div className="w-px h-3 bg-gray-300 dark:bg-white/20 mx-1" />
                        <button
                            onClick={handleMaximize}
                            className="p-2 rounded-lg hover:bg-gray-200/50 dark:hover:bg-white/10 transition-colors text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
                            title={t('common.maximize', 'Full View')}
                        >
                            <Maximize2 size={14} />
                        </button>
                    </div>
                </div>

                {/* Content Scroll Area */}
                <div className="flex-1 overflow-y-auto overflow-x-hidden p-4 space-y-5 scrollbar-thin scrollbar-track-transparent scrollbar-thumb-gray-200 dark:scrollbar-thumb-white/10">
                    {!currentAccount ? (
                        <div className="h-full flex flex-col items-center justify-center text-center opacity-50 space-y-2">
                            <ShieldAlert size={32} />
                            <p className="text-sm">No account selected</p>
                        </div>
                    ) : (
                        <div className="space-y-5">
                            {/* Account Info Card - Now simplified */}
                            <div className="flex flex-col gap-2">
                                <div className="flex flex-wrap gap-2">
                                    {/* Custom Label */}
                                    {currentAccount.custom_label && (
                                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-md bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400 text-[10px] font-bold shadow-sm shrink-0">
                                            <Tag className="w-2.5 h-2.5" />
                                            {currentAccount.custom_label}
                                        </span>
                                    )}
                                </div>
                            </div>

                            {/* Divider only if there was content above it */}
                            {currentAccount.custom_label && <div className="w-full h-px bg-gray-100 dark:bg-white/5" />}

                            {/* Models List */}
                            <AnimatePresence mode='popLayout'>
                                <div className="space-y-4 !mt-0">
                                    {renderModelRow(creditModel, 'Kiro Credits', 'cyan')}

                                    {!creditModel && (
                                        <div className="text-center py-4 text-xs text-gray-400">
                                            No quota data available
                                        </div>
                                    )}
                                </div>
                            </AnimatePresence>
                        </div>
                    )}
                </div>

                {/* Footer Status / Latest Log */}
                <div className="flex-none h-8 bg-gray-50 dark:bg-black/20 flex items-center justify-between px-3 text-[10px] text-gray-500 dark:text-gray-400 border-t border-gray-100 dark:border-white/5 overflow-hidden">
                    {latestLog ? (
                        <motion.div
                            key={latestLog.id}
                            initial={{ opacity: 0, y: 5 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="flex items-center w-full gap-2"
                        >
                            <span className="font-bold truncate max-w-[100px]" title={latestLog.model}>
                                {latestLog.mapped_model || 'Unknown'}
                            </span>

                            <div className="flex-1 flex items-center justify-end gap-2">
                                <div className="flex items-center gap-1.5 text-[9px]" title="Input/Output Tokens">
                                    <Activity size={10} className="text-blue-500" />
                                    <span className="flex items-center gap-0.5 text-gray-500 dark:text-gray-400">
                                        I:<span className="font-mono text-gray-900 dark:text-gray-200">{formatCompactNumber(latestLog.input_tokens || 0)}</span>
                                    </span>
                                    <span className="text-gray-300 dark:text-gray-600">/</span>
                                    <span className="flex items-center gap-0.5 text-gray-500 dark:text-gray-400">
                                        O:<span className="font-mono text-gray-900 dark:text-gray-200">{formatCompactNumber(latestLog.output_tokens || 0)}</span>
                                    </span>
                                </div>

                                <div className="w-px h-2.5 bg-gray-300 dark:bg-white/10" />

                                <div className="flex items-center gap-0.5" title="Duration">
                                    <Clock size={10} className="text-gray-400" />
                                    <span className="font-mono">{(latestLog.duration / 1000).toFixed(2)}s</span>
                                </div>
                            </div>
                        </motion.div>
                    ) : (
                        <>
                            <div className="flex items-center gap-1.5">
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                                <span>Connected</span>
                            </div>
                            <span className="font-mono opacity-50">v{appVersion}</span>
                        </>
                    )}
                </div>
            </motion.div>
        </div>
    );
}
