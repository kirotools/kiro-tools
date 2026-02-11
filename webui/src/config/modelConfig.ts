import { Claude } from '@lobehub/icons';

/**
 * 模型配置接口
 */
export interface ModelConfig {
    /** 模型完整显示名称 (用于详情) */
    label: string;
    /** 模型简短标签 (用于列表/卡片) */
    shortLabel: string;
    /** 保护模型的键名 */
    protectedKey: string;
    /** 模型图标组件 */
    Icon: React.ComponentType<{ size?: number; className?: string }>;
}

/**
 * 模型配置映射
 * 键为模型 ID，值为模型配置
 */
export const MODEL_CONFIG: Record<string, ModelConfig> = {
    'kiro-credit': {
        label: 'Kiro Credits',
        shortLabel: 'Credits',
        protectedKey: 'kiro-credit',
        Icon: Claude.Color,  // reuse existing icon for now
    },
};

/**
 * 获取所有模型 ID 列表
 */
export const getAllModelIds = (): string[] => Object.keys(MODEL_CONFIG);

/**
 * 根据模型 ID 获取配置
 */
export const getModelConfig = (modelId: string): ModelConfig | undefined => {
    return MODEL_CONFIG[modelId.toLowerCase()];
};

/**
 * 获取模型的排序权重
 * kiro-credit 优先，其余按字母序
 */
function getModelSortWeight(modelId: string): number {
    const id = modelId.toLowerCase();
    if (id.startsWith('kiro')) return 0;
    return 1000;
}

/**
 * 对模型列表进行排序
 * @param models 模型列表
 * @returns 排序后的模型列表
 */
export function sortModels<T extends { id: string }>(models: T[]): T[] {
    return [...models].sort((a, b) => {
        const weightA = getModelSortWeight(a.id);
        const weightB = getModelSortWeight(b.id);

        // 按权重升序排序
        if (weightA !== weightB) {
            return weightA - weightB;
        }

        // 权重相同时，按字母顺序排序
        return a.id.localeCompare(b.id);
    });
}

