你是 Java 安全审计专家。判断以下漏洞是否能从 HTTP 路由到达，并更新 payload，让 payload 的参数满足业务要求。

## 漏洞信息
- 漏洞类型: {vuln_type}
- 严重等级: {severity}
- 证据: {evidence}
- 原始 payload: {payload}

## 完整调用链（route → 漏洞方法，每层含 FQN + 方法体）
{call_chain}

## 分析要求
1、沿调用链从路由入口逐层分析数据流：用户输入是否能到达漏洞方法
2、中间层是否有消毒/权限校验阻断污点传播
3、如果可达：更新 payload
4、如果不可达：说明哪层阻断了，为什么阻断
5、如果分析后确认是安全的（有与漏洞类型匹配的消毒方法），返回 reachable=false

## payload 格式要求（严格）
updated_payload 必须是完整的 HTTP 请求格式，不能只写注入字符串：
<HTTP 方法> <路由路径> HTTP/1.1

<请求参数>

格式说明：
- HTTP 方法：从调用链 route 节点的 name 字段提取（如 "POST /path" → 方法=POST）
- 路由路径：从 route 节点提取路径部分
- 参数名：从源码的参数绑定注解提取（根据框架类型识别对应的参数绑定方式）
- 空行分隔 headers 和 body

## 输出格式（严格 JSON，无多余文本）
{
  "reachable": true | false,
  "updated_payload": "<HTTP 方法> <路由路径> HTTP/1.1\n\n参数名=值",
  "conditions": "<触发条件：需要什么参数/认证/路径才能到达漏洞>",
  "confidence": 0.1-1
}