import {
  AlertTriangle,
  Bot,
  Download,
  LayoutGrid,
  List,
  RefreshCw,
  Search,
  ToggleLeft,
  ToggleRight,
  Trash2,
  Upload,
  Users,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import AccountDetailsDialog from "../components/accounts/AccountDetailsDialog";
import AccountGrid from "../components/accounts/AccountGrid";
import AccountTable from "../components/accounts/AccountTable";
import AddAccountDialog from "../components/accounts/AddAccountDialog";
import ModalDialog from "../components/common/ModalDialog";
import Pagination from "../components/common/Pagination";
import { showToast } from "../components/common/ToastContainer";
import { exportAccounts, importAccounts, type AddAccountParams, type ImportAccountItem } from "../services/accountService";
import { useAccountStore } from "../stores/useAccountStore";
import { useConfigStore } from "../stores/useConfigStore";
import { Account } from "../types/account";
import { cn } from "../utils/cn";

type FilterType = "all" | "power" | "pro_plus" | "pro" | "free";
type ViewMode = "list" | "grid";

function Dashboard() {
  const { t } = useTranslation();
  const {
    accounts,
    currentAccount,
    fetchAccounts,
    fetchCurrentAccount,
    addAccount,
    deleteAccount,
    deleteAccounts,
    switchAccount,
    loading,
    refreshQuota,
    toggleProxyStatus,
    reorderAccounts,
    updateAccountLabel,
  } = useAccountStore();
  const { config, showAllQuotas, toggleShowAllQuotas } = useConfigStore();

  const [searchQuery, setSearchQuery] = useState("");
  const [filter, setFilter] = useState<FilterType>("all");
  const [isSearchExpanded, setIsSearchExpanded] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [viewMode, setViewMode] = useState<ViewMode>(() => {
    const saved = localStorage.getItem("accounts_view_mode");
    return saved === "list" || saved === "grid" ? saved : "list";
  });

  // Save view mode preference
  useEffect(() => {
    localStorage.setItem("accounts_view_mode", viewMode);
  }, [viewMode]);

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [detailsAccount, setDetailsAccount] = useState<Account | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [isBatchDelete, setIsBatchDelete] = useState(false);
  const [toggleProxyConfirm, setToggleProxyConfirm] = useState<{
    accountId: string;
    enable: boolean;
  } | null>(null);
  const [refreshingIds, setRefreshingIds] = useState<Set<string>>(new Set());

  const handleUpdateLabel = async (accountId: string, label: string) => {
    try {
      await updateAccountLabel(accountId, label);
      showToast(t("accounts.label_updated", "Label updated"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    }
  };

  const fileInputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerSize, setContainerSize] = useState({ width: 0, height: 0 });

  useEffect(() => {
    if (!containerRef.current) return;
    const resizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        setContainerSize({
          width: entry.contentRect.width,
          height: entry.contentRect.height,
        });
      }
    });
    resizeObserver.observe(containerRef.current);
    return () => resizeObserver.disconnect();
  }, []);

  // Pagination State
  const [currentPage, setCurrentPage] = useState(1);
  const [localPageSize, setLocalPageSize] = useState<number | null>(() => {
    const saved = localStorage.getItem("accounts_page_size");
    return saved ? parseInt(saved) : null;
  }); // 本地分页大小状态

  // Save page size preference
  useEffect(() => {
    if (localPageSize !== null) {
      localStorage.setItem("accounts_page_size", localPageSize.toString());
    }
  }, [localPageSize]);

  // 动态计算分页条数
  const ITEMS_PER_PAGE = useMemo(() => {
    // 优先使用本地设置的分页大小
    if (localPageSize && localPageSize > 0) {
      return localPageSize;
    }

    // 其次使用用户配置的固定值
    if (config?.accounts_page_size && config.accounts_page_size > 0) {
      return config.accounts_page_size;
    }

    // 回退到原有的动态计算逻辑
    if (!containerSize.height) return viewMode === "grid" ? 6 : 8;

    if (viewMode === "list") {
      const headerHeight = 36; // 缩深后的表头高度
      const rowHeight = 72; // 包含多行模型信息后的实际行高
      // 计算能容纳多少行, 默认最低 10 行
      const autoFitCount = Math.floor(
        (containerSize.height - headerHeight) / rowHeight
      );
      return Math.max(10, autoFitCount);
    } else {
      const cardHeight = 180; // AccountCard 实际高度 (含间距)
      const gap = 16; // gap-4

      // 匹配 Tailwind 断点逻辑
      let cols = 1;
      if (containerSize.width >= 1200) cols = 4; // xl (约为 1280 左右)
      else if (containerSize.width >= 900) cols = 3; // lg (约为 1024 左右)
      else if (containerSize.width >= 600) cols = 2; // md (约为 768 左右)

      const rows = Math.max(
        1,
        Math.floor((containerSize.height + gap) / (cardHeight + gap))
      );
      return cols * rows;
    }
  }, [localPageSize, config?.accounts_page_size, containerSize, viewMode]);

  useEffect(() => {
    fetchAccounts();
    fetchCurrentAccount();
  }, []);

  // Sync stats calculation from old Dashboard
  const stats = useMemo(() => {
    const creditQuotas = accounts
      .map(
        (a) =>
          a.quota?.models.find((m) => m.name.toLowerCase() === "kiro-credit")
            ?.percentage || 0
      )
      .filter((q) => q > 0);

    const lowQuotaCount = accounts.filter((a) => {
      if (a.quota?.is_forbidden) return false;
      const credit =
        a.quota?.models.find((m) => m.name.toLowerCase() === "kiro-credit")
          ?.percentage || 0;
      return credit < 20;
    }).length;

    return {
      total: accounts.length,
      avgCredit:
        creditQuotas.length > 0
          ? Math.round(
              creditQuotas.reduce((a, b) => a + b, 0) / creditQuotas.length
            )
          : 0,
      lowQuota: lowQuotaCount,
    };
  }, [accounts]);

  // Reset pagination when view mode changes
  useEffect(() => {
    setCurrentPage(1);
  }, [viewMode]);

  // 搜索过滤逻辑
  const searchedAccounts = useMemo(() => {
    if (!searchQuery) return accounts;
    const lowQuery = searchQuery.toLowerCase();
    return accounts.filter((a) => a.email.toLowerCase().includes(lowQuery));
  }, [accounts, searchQuery]);

  // 计算各筛选状态下的数量
  const filterCounts = useMemo(() => {
    return {
      all: searchedAccounts.length,
      power: searchedAccounts.filter((a) =>
        a.quota?.subscription_tier?.toLowerCase().includes("power")
      ).length,
      pro_plus: searchedAccounts.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return (
          !tier.includes("power") &&
          (tier.includes("pro+") ||
            tier.includes("pro_plus") ||
            tier.includes("proplus"))
        );
      }).length,
      pro: searchedAccounts.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return (
          tier.includes("pro") &&
          !tier.includes("power") &&
          !tier.includes("pro+") &&
          !tier.includes("pro_plus") &&
          !tier.includes("proplus")
        );
      }).length,
      free: searchedAccounts.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return (!tier.includes("pro") && !tier.includes("power")) || !tier;
      }).length,
    };
  }, [searchedAccounts]);

  // 过滤和搜索最终结果
  const filteredAccounts = useMemo(() => {
    let result = searchedAccounts;

    if (filter === "power") {
      result = result.filter((a) =>
        a.quota?.subscription_tier?.toLowerCase().includes("power")
      );
    } else if (filter === "pro_plus") {
      result = result.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return (
          !tier.includes("power") &&
          (tier.includes("pro+") ||
            tier.includes("pro_plus") ||
            tier.includes("proplus"))
        );
      });
    } else if (filter === "pro") {
      result = result.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return (
          tier.includes("pro") &&
          !tier.includes("power") &&
          !tier.includes("pro+") &&
          !tier.includes("pro_plus") &&
          !tier.includes("proplus")
        );
      });
    } else if (filter === "free") {
      result = result.filter((a) => {
        const tier = a.quota?.subscription_tier?.toLowerCase() || "";
        return !tier.includes("pro") && !tier.includes("power");
      });
    }

    return result;
  }, [searchedAccounts, filter]);

  // Pagination Logic
  const paginatedAccounts = useMemo(() => {
    const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
    return filteredAccounts.slice(startIndex, startIndex + ITEMS_PER_PAGE);
  }, [filteredAccounts, currentPage, ITEMS_PER_PAGE]);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  // 清空选择当过滤改变 并重置分页
  useEffect(() => {
    setSelectedIds(new Set());
    setCurrentPage(1);
  }, [filter, searchQuery]);

  const handleToggleSelect = (id: string) => {
    const newSet = new Set(selectedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedIds(newSet);
  };

  const handleToggleAll = () => {
    const currentIds = paginatedAccounts.map((a) => a.id);
    const allSelected = currentIds.every((id) => selectedIds.has(id));

    const newSet = new Set(selectedIds);
    if (allSelected) {
      currentIds.forEach((id) => newSet.delete(id));
    } else {
      currentIds.forEach((id) => newSet.add(id));
    }
    setSelectedIds(newSet);
  };

  const handleAddAccount = async (params: AddAccountParams) => {
    await addAccount(params);
    await fetchAccounts();
  };

  const [switchingAccountId, setSwitchingAccountId] = useState<string | null>(
    null
  );

  const handleSwitch = async (accountId: string) => {
    if (loading || switchingAccountId) return;

    setSwitchingAccountId(accountId);
    try {
      await switchAccount(accountId);
      showToast(t("common.success"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    } finally {
      setTimeout(() => {
        setSwitchingAccountId(null);
      }, 500);
    }
  };

  const handleRefresh = async (accountId: string) => {
    setRefreshingIds((prev) => {
      const next = new Set(prev);
      next.add(accountId);
      return next;
    });
    try {
      // 刷新多次??? 原逻辑如此
      await refreshQuota(accountId);
      await refreshQuota(accountId);
      await refreshQuota(accountId);
      showToast(t("common.success"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    } finally {
      setRefreshingIds((prev) => {
        const next = new Set(prev);
        next.delete(accountId);
        return next;
      });
      fetchCurrentAccount(); // Refresh current account status too
    }
  };

  const handleBatchDelete = () => {
    if (selectedIds.size === 0) return;
    setIsBatchDelete(true);
  };

  const executeBatchDelete = async () => {
    setIsBatchDelete(false);
    try {
      const ids = Array.from(selectedIds);
      await deleteAccounts(ids);
      setSelectedIds(new Set());
      showToast(t("common.success"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    }
  };

  const handleDelete = (accountId: string) => {
    setDeleteConfirmId(accountId);
  };

  const executeDelete = async () => {
    if (!deleteConfirmId) return;

    try {
      await deleteAccount(deleteConfirmId);
      showToast(t("common.success"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    } finally {
      setDeleteConfirmId(null);
    }
  };

  const handleToggleProxy = (accountId: string, currentlyDisabled: boolean) => {
    setToggleProxyConfirm({ accountId, enable: currentlyDisabled });
  };

  const executeToggleProxy = async () => {
    if (!toggleProxyConfirm) return;

    try {
      await toggleProxyStatus(
        toggleProxyConfirm.accountId,
        toggleProxyConfirm.enable,
        toggleProxyConfirm.enable
          ? undefined
          : t("accounts.proxy_disabled_reason_manual")
      );
      showToast(t("common.success"), "success");
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    } finally {
      setToggleProxyConfirm(null);
    }
  };

  const handleBatchToggleProxy = async (enable: boolean) => {
    if (selectedIds.size === 0) return;

    try {
      const promises = Array.from(selectedIds).map((id) =>
        toggleProxyStatus(
          id,
          enable,
          enable ? undefined : t("accounts.proxy_disabled_reason_batch")
        )
      );
      await Promise.all(promises);
      showToast(
        enable
          ? t("accounts.toast.proxy_enabled", { count: selectedIds.size })
          : t("accounts.toast.proxy_disabled", { count: selectedIds.size }),
        "success"
      );
      setSelectedIds(new Set());
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    }
  };

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isRefreshConfirmOpen, setIsRefreshConfirmOpen] = useState(false);

  const handleRefreshClick = () => {
    setIsRefreshConfirmOpen(true);
  };

  const executeRefresh = async () => {
    setIsRefreshConfirmOpen(false);
    setIsRefreshing(true);
    try {
      const isBatch = selectedIds.size > 0;
      let successCount = 0;
      let failedCount = 0;
      const details: string[] = [];

      if (isBatch) {
        // 批量刷新选中
        const ids = Array.from(selectedIds);
        setRefreshingIds(new Set(ids));

        const results = await Promise.allSettled(
          ids.map((id) => refreshQuota(id))
        );

        results.forEach((result, index) => {
          const id = ids[index];
          const email = accounts.find((a) => a.id === id)?.email || id;
          if (result.status === "fulfilled") {
            successCount++;
          } else {
            failedCount++;
            details.push(`${email}: ${result.reason}`);
          }
        });
      } else {
        // 刷新所有
        setRefreshingIds(new Set(accounts.map((a) => a.id)));
        const stats = await useAccountStore.getState().refreshAllQuotas();
        if (stats) {
          successCount = stats.success;
          failedCount = stats.failed;
          details.push(...stats.details);
        }
      }

      if (failedCount === 0) {
        showToast(
          t("accounts.refresh_selected", { count: successCount }),
          "success"
        );
      } else {
        showToast(
          `${t("common.success")}: ${successCount}, ${t(
            "common.error"
          )}: ${failedCount}`,
          "warning"
        );
        if (details.length > 0) {
          console.warn("Refresh failures:", details);
        }
      }
    } catch (error) {
      showToast(`${t("common.error")}: ${error}`, "error");
    } finally {
      setIsRefreshing(false);
      setRefreshingIds(new Set());
      fetchCurrentAccount();
    }
  };

  const exportAccountsToJson = async (accountsToExport: Account[]) => {
    try {
      if (accountsToExport.length === 0) {
        showToast(t("dashboard.toast.export_no_accounts"), "warning");
        return;
      }

      const accountIds = accountsToExport.map((acc) => acc.id);
      const response = await exportAccounts(accountIds);

      if (!response.accounts || response.accounts.length === 0) {
        showToast(t("dashboard.toast.export_no_accounts"), "warning");
        return;
      }

      const exportData = response;
      const content = JSON.stringify(exportData, null, 2);
      const fileName = `kiro_accounts_${
        new Date().toISOString().split("T")[0]
      }.json`;

      const blob = new Blob([content], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast(
        t("dashboard.toast.export_success", { path: fileName }),
        "success"
      );
    } catch (error: any) {
      showToast(`${t("common.error")}: ${error}`, "error");
    }
  };

  const handleExport = () => {
    const idsToExport =
      selectedIds.size > 0
        ? Array.from(selectedIds)
        : accounts.map((a) => a.id);

    const accountsToExport = accounts.filter((a) => idsToExport.includes(a.id));
    exportAccountsToJson(accountsToExport);
  };

  const handleExportOne = (accountId: string) => {
    const account = accounts.find((a) => a.id === accountId);
    if (account) {
      exportAccountsToJson([account]);
    }
  };

  const processImportData = async (content: string) => {
    type ImportEntry = {
      email?: string;
      refresh_token?: string;
      refreshToken?: string;
      auth_source?: string;
      authSource?: string;
      auth_type?: string;
      authType?: string;
      creds_data?: any;
      credsData?: any;
    };

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      showToast(t("accounts.import_invalid_format"), "error");
      return;
    }

    // Convert parsed data into ImportAccountItem[] for the bulk import endpoint
    const toImportItem = (entry: ImportEntry): ImportAccountItem | null => {
      const token = entry.refresh_token ?? entry.refreshToken;
      const credsData = entry.creds_data ?? entry.credsData;
      const authSource = entry.auth_source ?? entry.authSource;
      const authType = entry.auth_type ?? entry.authType;

      // Rich format: has creds_data (file-based account)
      if (credsData) {
        return {
          email: entry.email,
          refresh_token: typeof token === "string" ? token.trim() : undefined,
          auth_source: authSource,
          auth_type: authType,
          creds_data: credsData,
        };
      }

      // Simple format: has refresh_token
      if (typeof token === "string" && token.trim().length > 20) {
        return {
          email: entry.email,
          refresh_token: token.trim(),
          auth_source: authSource ?? "token",
        };
      }

      return null;
    };

    const fromArrayItem = (item: unknown): ImportAccountItem | null => {
      // Tuple style: [email, refresh_token]
      if (Array.isArray(item) && item.length >= 2 && typeof item[1] === "string") {
        const token = item[1].trim();
        if (token.length > 20) {
          return { email: typeof item[0] === "string" ? item[0] : undefined, refresh_token: token, auth_source: "token" };
        }
        return null;
      }
      // Object with fields
      if (item && typeof item === "object") {
        return toImportItem(item as ImportEntry);
      }
      return null;
    };

    let importItems: ImportAccountItem[] = [];

    // Format C: wrapped object { accounts: [...] }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const wrapper = parsed as { accounts?: unknown };
      if (Array.isArray(wrapper.accounts)) {
        importItems = wrapper.accounts
          .map(fromArrayItem)
          .filter((item): item is ImportAccountItem => item !== null);
      } else {
        // Format B: single object { email, refresh_token }
        const single = toImportItem(parsed as ImportEntry);
        if (single) importItems = [single];
      }
    }

    // Format A/D: top-level array
    if (Array.isArray(parsed)) {
      importItems = parsed
        .map(fromArrayItem)
        .filter((item): item is ImportAccountItem => item !== null);
    }

    // Deduplicate by refresh_token (if present)
    const seen = new Set<string>();
    importItems = importItems.filter((item) => {
      const key = item.refresh_token || JSON.stringify(item.creds_data) || Math.random().toString();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (importItems.length === 0) {
      showToast(t("accounts.import_invalid_format"), "error");
      return;
    }

    // Check if any items have rich data (creds_data) — use bulk import endpoint
    const hasRichData = importItems.some((item) => item.creds_data);

    if (hasRichData) {
      // Use the new bulk import endpoint
      try {
        const result = await importAccounts(importItems);
        if (result.failed === 0) {
          showToast(t("accounts.import_success", { count: result.success }), "success");
        } else if (result.success > 0) {
          showToast(t("accounts.import_partial", { success: result.success, fail: result.failed }), "warning");
        } else {
          const firstError = result.details.find((d) => d.error)?.error || "Unknown error";
          showToast(t("accounts.import_fail", { error: firstError }), "error");
        }
      } catch (error) {
        showToast(`${t("common.error")}: ${error}`, "error");
      }
    } else {
      // Legacy: add accounts one by one via refreshToken
      let successCount = 0;
      let failCount = 0;

      for (const item of importItems) {
        try {
          await addAccount({ refreshToken: item.refresh_token });
          successCount++;
        } catch (error) {
          console.error("Import account failed:", error);
          failCount++;
        }
        await new Promise((r) => setTimeout(r, 100));
      }

      if (failCount === 0) {
        showToast(t("accounts.import_success", { count: successCount }), "success");
      } else if (successCount > 0) {
        showToast(t("accounts.import_partial", { success: successCount, fail: failCount }), "warning");
      } else {
        showToast(t("accounts.import_fail", { error: "All accounts failed to import" }), "error");
      }
    }

    fetchAccounts();
  };

  const handleImportJson = async () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const content = await file.text();
      await processImportData(content);
    } catch (error) {
      console.error("Import failed:", error);
      showToast(t("accounts.import_fail", { error: String(error) }), "error");
    } finally {
      event.target.value = "";
    }
  };

  const handleViewDetails = (accountId: string) => {
    const account = accounts.find((a) => a.id === accountId);
    if (account) {
      setDetailsAccount(account);
    }
  };

  return (
    <div className="h-full flex flex-col p-5 gap-4 max-w-7xl mx-auto w-full">
      {/* 隐藏的文件输入 */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,application/json"
        style={{ display: "none" }}
        onChange={handleFileChange}
      />

      {/* 问候语 */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-base-content">
          {currentAccount
            ? t("dashboard.hello").replace(
                "用户",
                currentAccount.name || currentAccount.email.split("@")[0]
              )
            : t("dashboard.hello")}
        </h1>
      </div>

      {/* 统计卡片 (保留自原 Dashboard) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-white dark:bg-base-100 rounded-xl p-4 shadow-sm border border-gray-100 dark:border-base-200">
          <div className="flex items-center justify-between mb-2">
            <div className="p-1.5 bg-blue-50 dark:bg-blue-900/20 rounded-md">
              <Users className="w-4 h-4 text-blue-500 dark:text-blue-400" />
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900 dark:text-base-content mb-0.5">
            {stats.total}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {t("dashboard.total_accounts")}
          </div>
        </div>

        <div className="bg-white dark:bg-base-100 rounded-xl p-4 shadow-sm border border-gray-100 dark:border-base-200">
          <div className="flex items-center justify-between mb-2">
            <div className="p-1.5 bg-cyan-50 dark:bg-cyan-900/20 rounded-md">
              <Bot className="w-4 h-4 text-cyan-500 dark:text-cyan-400" />
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900 dark:text-base-content mb-0.5">
            {stats.avgCredit}%
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {t("dashboard.avg_claude")}
          </div>
          {stats.avgCredit > 0 && (
            <div
              className={`text-[10px] mt-1 ${
                stats.avgCredit >= 50
                  ? "text-green-600 dark:text-green-400"
                  : "text-orange-600 dark:text-orange-400"
              }`}
            >
              {stats.avgCredit >= 50
                ? t("dashboard.quota_sufficient")
                : t("dashboard.quota_low")}
            </div>
          )}
        </div>

        <div className="bg-white dark:bg-base-100 rounded-xl p-4 shadow-sm border border-gray-100 dark:border-base-200">
          <div className="flex items-center justify-between mb-2">
            <div className="p-1.5 bg-orange-50 dark:bg-orange-900/20 rounded-md">
              <AlertTriangle className="w-4 h-4 text-orange-500 dark:text-orange-400" />
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900 dark:text-base-content mb-0.5">
            {stats.lowQuota}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            {t("dashboard.low_quota_accounts")}
          </div>
          <div className="text-[10px] text-gray-400 dark:text-gray-500 mt-1">
            {t("dashboard.quota_desc")}
          </div>
        </div>
      </div>

      {/* 顶部工具栏:搜索、过滤和操作按钮 (整合自 Accounts) */}
      <div className="flex-none flex items-center gap-2">
        {/* 搜索框 */}
        <div className="hidden lg:block flex-none w-40 relative transition-all focus-within:w-48">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder={t("accounts.search_placeholder")}
            className="w-full pl-9 pr-4 py-2 bg-white dark:bg-base-100 text-sm text-gray-900 dark:text-base-content border border-gray-200 dark:border-base-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-gray-400 dark:placeholder:text-gray-500"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        {/* 搜索按钮 - 小屏显示 */}
        <div className="lg:hidden relative">
          {!isSearchExpanded ? (
            <button
              onClick={() => {
                setIsSearchExpanded(true);
                setTimeout(() => searchInputRef.current?.focus(), 100);
              }}
              className="p-2 bg-gray-100 dark:bg-base-200 hover:bg-gray-200 dark:hover:bg-base-100 rounded-lg transition-colors"
              title={t("accounts.search_placeholder")}
            >
              <Search className="w-4 h-4 text-gray-600 dark:text-gray-300" />
            </button>
          ) : (
            <div className="absolute left-0 top-0 z-10 w-64 flex items-center gap-1">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder={t("accounts.search_placeholder")}
                  className="w-full pl-9 pr-4 py-2 bg-white dark:bg-base-100 text-sm text-gray-900 dark:text-base-content border border-gray-200 dark:border-base-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder:text-gray-400 dark:placeholder:text-gray-500 shadow-lg"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onBlur={() => setIsSearchExpanded(false)}
                />
              </div>
            </div>
          )}
        </div>

        {/* 视图切换按钮组 */}
        <div className="flex gap-1 bg-gray-100 dark:bg-base-200 p-1 rounded-lg shrink-0">
          <button
            className={cn(
              "p-1.5 rounded-md transition-all",
              viewMode === "list"
                ? "bg-white dark:bg-base-100 text-blue-600 dark:text-blue-400 shadow-sm"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-base-content"
            )}
            onClick={() => setViewMode("list")}
            title={t("accounts.views.list")}
          >
            <List className="w-4 h-4" />
          </button>
          <button
            className={cn(
              "p-1.5 rounded-md transition-all",
              viewMode === "grid"
                ? "bg-white dark:bg-base-100 text-blue-600 dark:text-blue-400 shadow-sm"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-base-content"
            )}
            onClick={() => setViewMode("grid")}
            title={t("accounts.views.grid")}
          >
            <LayoutGrid className="w-4 h-4" />
          </button>
        </div>

        {/* 过滤按钮组 */}
        <div className="flex gap-0.5 bg-gray-100/80 dark:bg-base-200 p-1 rounded-xl border border-gray-200/50 dark:border-white/5 shrink-0 overflow-x-auto">
            {/* 简化的过滤按钮，这里直接复用 */}
           {['all', 'power', 'pro_plus', 'pro', 'free'].map((ft) => (
             <button
               key={ft}
               className={cn(
                 "px-2 md:px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-all flex items-center gap-1 md:gap-1.5 whitespace-nowrap shrink-0",
                 filter === ft
                   ? "bg-white dark:bg-base-100 text-blue-600 dark:text-blue-400 shadow-sm ring-1 ring-black/5"
                   : "text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-base-content hover:bg-white/40"
               )}
               onClick={() => setFilter(ft as FilterType)}
               title={t(`accounts.${ft}`)}
             >
               <span className="hidden md:inline">{ft === 'pro_plus' ? 'PRO+' : t(`accounts.${ft}`)}</span>
               <span className={cn(
                 "px-1.5 py-0.5 rounded-md text-[10px] font-bold transition-colors",
                 filter === ft
                   ? "bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400"
                   : "bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400"
               )}>
                 {/* @ts-ignore */}
                 {filterCounts[ft as keyof typeof filterCounts]}
               </span>
             </button>
           ))}
        </div>

        <div className="flex-1 min-w-[8px]"></div>

        {/* 操作按钮组 */}
        <div className="flex items-center gap-1.5 shrink-0">
          <AddAccountDialog onAdd={handleAddAccount} showText={false} />

          {selectedIds.size > 0 && (
            <>
              <button
                className="px-2.5 py-2 bg-red-500 text-white text-xs font-medium rounded-lg hover:bg-red-600 transition-colors flex items-center gap-1.5 shadow-sm"
                onClick={handleBatchDelete}
                title={t("accounts.delete_selected", {
                  count: selectedIds.size,
                })}
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span className="hidden xl:inline">
                  {t("accounts.delete_selected", { count: selectedIds.size })}
                </span>
              </button>
              {/* Proxy toggles omitted for brevity if needed, but keeping them for full parity */}
               <button
                className="px-2.5 py-2 bg-orange-500 text-white text-xs font-medium rounded-lg hover:bg-orange-600 transition-colors flex items-center gap-1.5 shadow-sm"
                onClick={() => handleBatchToggleProxy(false)}
                title={t("accounts.disable_proxy_selected", { count: selectedIds.size })}
              >
                <ToggleLeft className="w-3.5 h-3.5" />
              </button>
               <button
                className="px-2.5 py-2 bg-green-500 text-white text-xs font-medium rounded-lg hover:bg-green-600 transition-colors flex items-center gap-1.5 shadow-sm"
                onClick={() => handleBatchToggleProxy(true)}
                title={t("accounts.enable_proxy_selected", { count: selectedIds.size })}
              >
                <ToggleRight className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          <button
            className={`px-2.5 py-2 bg-blue-500 text-white text-xs font-medium rounded-lg hover:bg-blue-600 transition-colors flex items-center gap-1.5 shadow-sm ${
              isRefreshing ? "opacity-70 cursor-not-allowed" : ""
            }`}
            onClick={handleRefreshClick}
            disabled={isRefreshing}
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`}
            />
             <span className="hidden xl:inline">
              {isRefreshing
                ? t("common.loading")
                : selectedIds.size > 0
                  ? t("accounts.refresh_selected", { count: selectedIds.size })
                  : t("accounts.refresh_all")}
            </span>
          </button>

           <label className="flex items-center gap-2 cursor-pointer select-none px-2 py-2 border border-transparent hover:bg-gray-100 dark:hover:bg-base-200 rounded-lg transition-colors" title={t('accounts.show_all_quotas')}>
            <input
              type="checkbox"
              className="toggle toggle-xs toggle-primary"
              checked={showAllQuotas}
              onChange={toggleShowAllQuotas}
            />
            {/* Show label text on large screens */}
             <span className="text-xs font-medium text-gray-600 dark:text-gray-300 hidden xl:inline">
              {t('accounts.show_all_quotas')}
            </span>
          </label>

          <button
            className="px-2.5 py-2 border border-gray-200 dark:border-base-300 text-gray-700 dark:text-gray-300 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-base-200 transition-colors flex items-center gap-1.5"
            onClick={handleImportJson}
            title={t("accounts.import_json")}
          >
            <Upload className="w-3.5 h-3.5" />
          </button>

          <button
            className="px-2.5 py-2 border border-gray-200 dark:border-base-300 text-gray-700 dark:text-gray-300 text-xs font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-base-200 transition-colors flex items-center gap-1.5"
            onClick={handleExport}
            title={t("common.export")}
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 账号列表内容区域 */}
      <div className="flex-1 min-h-0 relative" ref={containerRef}>
        {viewMode === "list" ? (
          <div className="h-full bg-white dark:bg-base-100 rounded-2xl shadow-sm border border-gray-100 dark:border-base-200 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto">
              <AccountTable
                accounts={paginatedAccounts}
                selectedIds={selectedIds}
                refreshingIds={refreshingIds}
                onToggleSelect={handleToggleSelect}
                onToggleAll={handleToggleAll}
                currentAccountId={currentAccount?.id || null}
                switchingAccountId={switchingAccountId}
                onSwitch={handleSwitch}
                onRefresh={handleRefresh}
                onViewDetails={handleViewDetails}
                onExport={handleExportOne}
                onDelete={handleDelete}
                onToggleProxy={(id) =>
                  handleToggleProxy(
                    id,
                    !!accounts.find((a) => a.id === id)?.proxy_disabled
                  )
                }
                onReorder={reorderAccounts}
                onUpdateLabel={handleUpdateLabel}
              />
            </div>
          </div>
        ) : (
          <div className="h-full overflow-y-auto">
            <AccountGrid
              accounts={paginatedAccounts}
              selectedIds={selectedIds}
              refreshingIds={refreshingIds}
              onToggleSelect={handleToggleSelect}
              currentAccountId={currentAccount?.id || null}
              switchingAccountId={switchingAccountId}
              onSwitch={handleSwitch}
              onRefresh={handleRefresh}
              onViewDetails={handleViewDetails}
              onExport={handleExportOne}
              onDelete={handleDelete}
              onToggleProxy={(id) =>
                handleToggleProxy(
                  id,
                  !!accounts.find((a) => a.id === id)?.proxy_disabled
                )
              }
              onUpdateLabel={handleUpdateLabel}
            />
          </div>
        )}
      </div>

      {/* 极简分页 */}
      {filteredAccounts.length > 0 && (
        <div className="flex-none">
          <Pagination
            currentPage={currentPage}
            totalPages={Math.ceil(filteredAccounts.length / ITEMS_PER_PAGE)}
            onPageChange={handlePageChange}
            totalItems={filteredAccounts.length}
            itemsPerPage={ITEMS_PER_PAGE}
            onPageSizeChange={(newSize) => {
              setLocalPageSize(newSize);
              setCurrentPage(1);
            }}
            pageSizeOptions={[10, 20, 50, 100]}
          />
        </div>
      )}

      {/* Dialogs */}
      <AccountDetailsDialog
        account={detailsAccount}
        onClose={() => setDetailsAccount(null)}
      />

      <ModalDialog
        isOpen={!!deleteConfirmId || isBatchDelete}
        title={
          isBatchDelete
            ? t("accounts.dialog.batch_delete_title")
            : t("accounts.dialog.delete_title")
        }
        message={
          isBatchDelete
            ? t("accounts.dialog.batch_delete_msg", { count: selectedIds.size })
            : t("accounts.dialog.delete_msg")
        }
        type="confirm"
        confirmText={t("common.delete")}
        isDestructive={true}
        onConfirm={isBatchDelete ? executeBatchDelete : executeDelete}
        onCancel={() => {
          setDeleteConfirmId(null);
          setIsBatchDelete(false);
        }}
      />

      <ModalDialog
        isOpen={isRefreshConfirmOpen}
        title={
          selectedIds.size > 0
            ? t("accounts.dialog.batch_refresh_title")
            : t("accounts.dialog.refresh_title")
        }
        message={
          selectedIds.size > 0
            ? t("accounts.dialog.batch_refresh_msg", {
                count: selectedIds.size,
              })
            : t("accounts.dialog.refresh_msg")
        }
        type="confirm"
        confirmText={t("common.refresh")}
        isDestructive={false}
        onConfirm={executeRefresh}
        onCancel={() => setIsRefreshConfirmOpen(false)}
      />

      {toggleProxyConfirm && (
        <ModalDialog
          isOpen={!!toggleProxyConfirm}
          onCancel={() => setToggleProxyConfirm(null)}
          onConfirm={executeToggleProxy}
          title={
            toggleProxyConfirm.enable
              ? t("accounts.dialog.enable_proxy_title")
              : t("accounts.dialog.disable_proxy_title")
          }
          message={
            toggleProxyConfirm.enable
              ? t("accounts.dialog.enable_proxy_msg")
              : t("accounts.dialog.disable_proxy_msg")
          }
        />
      )}
    </div>
  );
}

export default Dashboard;
