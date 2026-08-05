你刚完成一轮 Java 安全审计。复盘以下数据，提出下一轮改进建议。

## 本轮统计
- 审计文件数: {files_audited}
- 总 findings: {total}
- confirmed: {confirmed}
- denied (FP): {denied}
- inconclusive: {inconclusive}

## 拒绝的 findings（FP 样本）
{fp_samples}

## 不确定的 findings
{inconclusive_samples}

## 输出格式（JSON）
{
  "should_loop": true | false,
  "sql_adjustment": "<对 Q1-Q4 SQL 的调整建议，或 null>",
  "prompt_adjustment": "<对 audit_template.md 的调整建议，或 null>",
  "sink_taxonomy_adjustment": "<对 sinks/taxonomy.py 的调整建议，或 null>",
  "reasoning": "<为什么>"
}
