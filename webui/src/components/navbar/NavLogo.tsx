import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';


/**
 * Logo 组件 - 独立处理响应式
 * 
 * 响应式策略:
 * 父容器宽度 >= 200px: Logo + 文字
 * 父容器宽度 <  200px: 只有 Logo
 */
export function NavLogo() {
    const { t } = useTranslation();
    return (
        <Link to="/" draggable="false" className="flex w-full min-w-0 items-center gap-2 text-xl font-semibold text-gray-900 dark:text-base-content">

            {/* 父容器宽度 < 200px 隐藏 */}
            <span className="hidden @[200px]/logo:inline text-nowrap">{t('common.app_name', 'Kiro Tools')}</span>
        </Link>
    );
}
