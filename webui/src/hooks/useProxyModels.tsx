import { useState, useEffect, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { request as invoke } from '../utils/request';
import {
    Cpu,
    BrainCircuit,
    Sparkles
} from 'lucide-react';

interface ModelFromApi {
    id: string;
    name: string;
    group: string;
    thinking: boolean;
}

interface ProxyModel {
    id: string;
    name: string;
    desc: string;
    group: string;
    icon: ReactNode;
}

function getModelIcon(model: ModelFromApi): ReactNode {
    if (model.thinking) return <BrainCircuit size={16} />;
    if (model.id.includes('opus')) return <Cpu size={16} />;
    return <Sparkles size={16} />;
}

function getModelDesc(model: ModelFromApi, t: (key: string) => string): string {
    if (model.thinking) return t('proxy.model.thinking');
    if (model.id.includes('opus')) return t('proxy.model.opus');
    if (model.id.includes('haiku')) return t('proxy.model.haiku');
    return t('proxy.model.default');
}

export const useProxyModels = () => {
    const { t } = useTranslation();
    const [models, setModels] = useState<ProxyModel[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let cancelled = false;

        const fetchModels = async () => {
            try {
                const resp = await invoke<{ models: ModelFromApi[] }>('list_proxy_models');
                if (cancelled) return;
                const modelList = resp?.models;
                if (!Array.isArray(modelList)) {
                    console.warn('list_proxy_models returned unexpected format:', resp);
                    return;
                }
                setModels(
                    modelList.map((m) => ({
                        id: m.id,
                        name: m.name,
                        desc: getModelDesc(m, t),
                        group: m.group,
                        icon: getModelIcon(m),
                    }))
                );
            } catch (err) {
                console.error('Failed to fetch proxy models:', err);
            } finally {
                if (!cancelled) setLoading(false);
            }
        };

        fetchModels();
        return () => { cancelled = true; };
    }, [t]);

    return { models, loading };
};
