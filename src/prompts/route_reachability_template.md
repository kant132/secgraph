你是 Java 安全审计专家。判断以下漏洞是否能从 HTTP 路由到达，并更新 payload，让payload的参数满足业务要求

## 漏洞信息
- 漏洞类型: {vuln_type}
- 严重等级: {severity}
- 证据: {evidence}
- 原始 payload: {payload}

## 调用链（从路由入口到漏洞方法）
{chain_path}

## 调用链方法体（从路由入口到漏洞方法，逐层）
{chain_bodies}

## 分析要求
1、沿调用链从路由入口逐层分析数据流：用户输入是否能到达漏洞方法
2、中间层是否有消毒/权限校验阻断污点传播
3、如果可达：更新 payload（构造完整的 HTTP 请求，包含必要的参数、路径、请求头）
4、如果不可达：说明哪层阻断了，为什么阻断

## 输出格式（严格 JSON，无多余文本）
{
  "reachable": true | false,
  "updated_payload": "<更新后的 payload，或原 payload>",
  "conditions": "<触发条件：需要什么参数/认证/路径才能到达漏洞>",
  "confidence": 0.1-1
}
