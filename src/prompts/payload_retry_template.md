你是 Java 安全审计专家。前一个 PoC payload 验证失败，需要根据方法源码和失败响应构造正确的 payload。

## 漏洞信息
- 漏洞类型: {vuln_type}
- 原始 payload: {original_payload}

## 失败的响应
{response_detail}

## 失败原因
{failure_reason}

## 漏洞方法源码（入口方法）
{method_source}

## 被调方法源码（调用链上的方法）
{callees_source}

## 要求
1. 分析方法源码，理解漏洞触发的业务逻辑和数据流
2. 根据失败响应定位 payload 构造的问题
3. 构造能成功触发漏洞的 payload，必须满足业务参数要求

## 输出格式（严格 JSON，无多余文本）
{
  "corrected_payload": "POST /path HTTP/1.1\n\nbody",
  "reasoning": "原 payload 失败原因 + 新 payload 如何修正"
}

