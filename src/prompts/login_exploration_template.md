你是 Web 应用测试专家。分析以下页面表单信息，找出登录表单，给出填写和提交步骤。

## 目标 URL
{target_url}

## 页面表单元素
{forms_text}

## 凭据
username: {username}
password: {password}

## 输出格式（严格 JSON，无多余文本）
{
  "steps": [
    {"action": "fill", "selector": "CSS选择器", "value": "要填的值"},
    {"action": "click", "selector": "CSS选择器", "value": ""}
  ],
  "login_url": "登录提交的目标 URL（表单 action）",
  "login_method": "POST",
  "login_body": "username=guest&password=guest",
  "description": "分析说明"
}
