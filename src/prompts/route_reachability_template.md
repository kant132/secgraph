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
3、如果可达：更新 payload
4、如果不可达：说明哪层阻断了，为什么阻断

## payload 格式要求（严格）
updated_payload 必须是完整的 HTTP 请求格式，不能只写注入字符串：
POST /路由路径 HTTP/1.1

参数名=注入值

例如：
POST /SqlInjectionAdvanced/attack6a HTTP/1.1

userid_6a=' OR '1'='1

不要只写 ' OR '1'='1，必须包含 HTTP 方法 + 路径 + 空行 + body。
路由路径从调用链的 route 节点提取（如 route:/SqlInjectionAdvanced/attack6a → 路径为 /SqlInjectionAdvanced/attack6a）。
参数名从源码的 @RequestParam 注解提取。

## 输出格式（严格 JSON，无多余文本）
{
  "reachable": true | false,
  "updated_payload": "POST /路径 HTTP/1.1\n\n参数名=注入值",
  "conditions": "<触发条件：需要什么参数/认证/路径才能到达漏洞>",
  "confidence": 0.1-1
}
