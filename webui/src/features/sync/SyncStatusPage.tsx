import { useQuery } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { AlertTriangle, RefreshCw, UploadCloud } from "lucide-react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { DataTable } from "../../components/ui/DataTable";
import { useI18n } from "../../i18n";
import { formatBytes } from "../../lib/bytes";
import { formatApiErrorMessage } from "../../lib/error-message";
import { formatDateTime } from "../../lib/time";
import { getSyncStatus } from "./api";
import type { RefreshStats, UploadAttempt } from "./types";

function formatMillis(ms: number): string {
  if (!ms) {
    return "-";
  }
  if (ms < 1000) {
    return `${ms} ms`;
  }
  return `${(ms / 1000).toFixed(2)} s`;
}

function formatSeconds(seconds: number): string {
  if (!seconds) {
    return "-";
  }
  if (seconds % 3600 === 0) {
    return `${seconds / 3600}h`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }
  return `${seconds}s`;
}

export function SyncStatusPage() {
  const { t } = useI18n();
  const statusQuery = useQuery({
    queryKey: ["sync-status"],
    queryFn: getSyncStatus,
    refetchInterval: 5_000,
  });

  const upload = statusQuery.data?.upload;
  const refreshes = statusQuery.data?.refreshes ?? [];
  const lastAttempt = upload?.history?.[0];

  const historyColumns: ColumnDef<UploadAttempt>[] = [
    {
      accessorKey: "finished_at",
      header: t("完成时间"),
      cell: ({ row }) => formatDateTime(row.original.finished_at),
    },
    {
      accessorKey: "records",
      header: t("记录数"),
      cell: ({ row }) => row.original.records,
    },
    {
      accessorKey: "eligible",
      header: t("候选节点"),
      cell: ({ row }) => row.original.eligible,
    },
    {
      accessorKey: "stale",
      header: t("过期跳过"),
      cell: ({ row }) => row.original.stale,
    },
    {
      accessorKey: "unsupported",
      header: t("不支持"),
      cell: ({ row }) => row.original.unsupported,
    },
    {
      accessorKey: "duration_ms",
      header: t("耗时"),
      cell: ({ row }) => formatMillis(row.original.duration_ms),
    },
    {
      id: "result",
      header: t("结果"),
      cell: ({ row }) =>
        row.original.error ? (
          <Badge variant="danger" title={row.original.error}>
            {t("失败")}
          </Badge>
        ) : (
          <Badge variant="success" title={row.original.response}>
            {t("成功")}
          </Badge>
        ),
    },
  ];

  const refreshColumns: ColumnDef<RefreshStats>[] = [
    {
      id: "subscription",
      header: t("订阅"),
      cell: ({ row }) => (
        <span className="lease-node-cell" title={row.original.subscription_id}>
          <strong>{row.original.subscription_name || row.original.subscription_id}</strong>
          <small>{row.original.subscription_id}</small>
        </span>
      ),
    },
    {
      id: "state",
      header: t("状态"),
      cell: ({ row }) =>
        row.original.in_flight ? <Badge variant="info">{t("拉取中")}</Badge> : <Badge variant="neutral">{t("空闲")}</Badge>,
    },
    {
      accessorKey: "started_at",
      header: t("开始时间"),
      cell: ({ row }) => formatDateTime(row.original.started_at || ""),
    },
    {
      accessorKey: "finished_at",
      header: t("完成时间"),
      cell: ({ row }) => formatDateTime(row.original.finished_at || ""),
    },
    {
      id: "fetch",
      header: t("拉取"),
      cell: ({ row }) => formatMillis(row.original.fetch_ms),
    },
    {
      id: "parse",
      header: t("解析"),
      cell: ({ row }) => formatMillis(row.original.parse_ms),
    },
    {
      id: "apply",
      header: t("应用"),
      cell: ({ row }) => formatMillis(row.original.apply_ms),
    },
    {
      accessorKey: "bytes",
      header: t("数据量"),
      cell: ({ row }) => formatBytes(row.original.bytes),
    },
    {
      accessorKey: "parsed",
      header: t("解析节点"),
      cell: ({ row }) => row.original.parsed,
    },
    {
      id: "diff",
      header: t("新增 / 保留 / 移除"),
      cell: ({ row }) => `${row.original.added} / ${row.original.kept} / ${row.original.removed}`,
    },
    {
      accessorKey: "error",
      header: t("错误"),
      cell: ({ row }) =>
        row.original.error ? (
          <span style={{ color: "var(--delete-btn-color, #c27070)" }} title={row.original.error}>
            {row.original.error}
          </span>
        ) : (
          "-"
        ),
    },
  ];

  return (
    <section className="sync-page">
      <header className="module-header">
        <div>
          <h2>{t("同步状态")}</h2>
          <p className="module-description">{t("查看订阅完整池的拉取耗时，以及本地验证节点的回传状态。")}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void statusQuery.refetch()} disabled={statusQuery.isFetching}>
          <RefreshCw size={16} className={statusQuery.isFetching ? "spin" : undefined} />
          {t("刷新")}
        </Button>
      </header>

      {statusQuery.isError ? (
        <div className="callout callout-error">
          <AlertTriangle size={14} />
          <span>{formatApiErrorMessage(statusQuery.error, t)}</span>
        </div>
      ) : null}

      <Card className="platform-cards-container" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div className="list-card-header">
          <div>
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <UploadCloud size={16} />
              {t("节点回传")}
            </h3>
            <p>{t("拉取开始时，将本地检测可用的节点上传到接收端。")}</p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Badge variant={upload?.enabled ? "success" : "muted"}>{upload?.enabled ? t("已启用") : t("未启用")}</Badge>
            <Badge variant={upload?.running ? "info" : "neutral"}>{upload?.running ? t("上传中") : t("空闲")}</Badge>
          </div>
        </div>

        <div className="geoip-status-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
          <div className="geoip-kv">
            <span>{t("接收端")}</span>
            <p style={{ wordBreak: "break-all" }}>{upload?.endpoint || "-"}</p>
          </div>
          <div className="geoip-kv">
            <span>{t("新鲜度窗口")}</span>
            <p>{formatSeconds(upload?.window_seconds ?? 0)}</p>
          </div>
          <div className="geoip-kv">
            <span>{t("请求超时")}</span>
            <p>{formatSeconds(upload?.timeout_seconds ?? 0)}</p>
          </div>
          <div className="geoip-kv">
            <span>{t("最近成功")}</span>
            <p>{formatDateTime(upload?.last_success_at || "")}</p>
          </div>
        </div>

        {upload?.last_error ? (
          <div className="callout callout-error">
            <AlertTriangle size={14} />
            <span>{upload.last_error}</span>
          </div>
        ) : null}

        {lastAttempt ? (
          <div className="geoip-status-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
            <div className="geoip-kv">
              <span>{t("最近一次 · 记录数")}</span>
              <p>{lastAttempt.records}</p>
            </div>
            <div className="geoip-kv">
              <span>{t("候选节点")}</span>
              <p>{lastAttempt.eligible}</p>
            </div>
            <div className="geoip-kv">
              <span>{t("过期跳过")}</span>
              <p>{lastAttempt.stale}</p>
            </div>
            <div className="geoip-kv">
              <span>{t("不支持")}</span>
              <p>{lastAttempt.unsupported}</p>
            </div>
            <div className="geoip-kv">
              <span>{t("耗时")}</span>
              <p>{formatMillis(lastAttempt.duration_ms)}</p>
            </div>
          </div>
        ) : null}

        <div>
          <h4>{t("上传历史")}</h4>
          {upload && upload.history.length > 0 ? (
            <DataTable data={upload.history} columns={historyColumns} />
          ) : (
            <div className="empty-box">
              <UploadCloud size={16} />
              <p>{t("暂无上传记录")}</p>
            </div>
          )}
        </div>
      </Card>

      <Card className="platform-cards-container" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <div className="list-card-header">
          <div>
            <h3>{t("订阅拉取")}</h3>
            <p>{t("订阅完整池最近一次拉取的耗时与结果。")}</p>
          </div>
        </div>
        {refreshes.length > 0 ? (
          <DataTable data={refreshes} columns={refreshColumns} />
        ) : (
          <div className="empty-box">
            <RefreshCw size={16} />
            <p>{t("暂无拉取记录")}</p>
          </div>
        )}
      </Card>
    </section>
  );
}
