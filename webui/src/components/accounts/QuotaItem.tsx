
import { cn } from '../../utils/cn';
import { getQuotaColor } from '../../utils/format';

interface QuotaItemProps {
    label: string;
    percentage: number;
    className?: string;
    Icon?: React.ComponentType<{ size?: number; className?: string }>;
    usageLimit?: number;
    currentUsage?: number;
}

export function QuotaItem({ label, percentage, className, Icon, usageLimit, currentUsage }: QuotaItemProps) {

    const getBgColorClass = (p: number) => {
        const color = getQuotaColor(p);
        switch (color) {
            case 'success': return 'bg-emerald-500';
            case 'warning': return 'bg-amber-500';
            case 'error': return 'bg-rose-500';
            default: return 'bg-gray-500';
        }
    };

    const getTextColorClass = (p: number) => {
        const color = getQuotaColor(p);
        switch (color) {
            case 'success': return 'text-emerald-600 dark:text-emerald-400';
            case 'warning': return 'text-amber-600 dark:text-amber-400';
            case 'error': return 'text-rose-600 dark:text-rose-400';
            default: return 'text-gray-500';
        }
    };

    return (
        <div className={cn(
            "relative h-[22px] flex items-center px-1.5 rounded-md overflow-hidden border border-gray-100/50 dark:border-white/5 bg-gray-50/30 dark:bg-white/5 group/quota",
            className
        )}>
            {/* Background Progress Bar */}
            <div
                className={cn(
                    "absolute inset-y-0 left-0 transition-all duration-700 ease-out opacity-15 dark:opacity-20",
                    getBgColorClass(percentage)
                )}
                style={{ width: `${percentage}%` }}
            />

            {/* Content */}
            <div className="relative z-10 w-full flex items-center text-[10px] font-mono leading-none gap-1.5">
                {/* Model Name */}
                <span className="flex-1 min-w-0 text-gray-500 dark:text-gray-400 font-bold truncate text-left flex items-center gap-1" title={label}>
                    {Icon && <Icon size={12} className="shrink-0" />}
                    {label}
                </span>

                {/* Percentage + Absolute */}
                <span className={cn("text-right font-bold transition-colors flex items-center justify-end gap-0.5 shrink-0", getTextColorClass(percentage))}>
                    {usageLimit != null && currentUsage != null
                        ? `${Math.round(usageLimit - currentUsage)}/${Math.round(usageLimit)}`
                        : `${percentage}%`
                    }
                </span>
            </div>
        </div>
    );
}
