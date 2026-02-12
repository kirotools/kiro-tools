import { Claude } from '@lobehub/icons';

export interface ModelConfig {
    label: string;
    shortLabel: string;
    Icon: React.ComponentType<{ size?: number; className?: string }>;
}

export const MODEL_CONFIG: Record<string, ModelConfig> = {
    'kiro-credit': {
        label: 'Kiro Credits',
        shortLabel: 'Credits',
        Icon: Claude.Color,
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

