你刚完成静态安全审计，现在需要动态验证以下漏洞。根据漏洞信息生成 PoC。

## 漏洞信息
- 文件: {file_path}
- node_id: {node_id}
- 漏洞类型: {vuln_type}
- 严重等级: {severity}
- 证据: {evidence}
- 静态 payload: {payload}

## 目标环境
- 应用地址: {target_url}
- 认证信息: {auth_info}

## 审计要求
1. 根据 vuln_type 选择验证方式（HTTP 请求 / Arthas OGNL / DB 查询）
2. 构造能证明漏洞存在的 PoC
3. 给出预期返回特征（用于判断 confirmed / denied）

## 输出格式（JSON）
{
  "poc_command": "<curl 命令 或 Arthas OGNL 表达式 或 SQL 查询>",
  "expected_result": "<预期返回的特征，如响应包含某字符串 / 状态码 / 数据变化>",
  "verification_method": "http_response | arthas_output | db_query"
}
