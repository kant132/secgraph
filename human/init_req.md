查询
-- 筛选出初始化为public的方法
SELECT * FROM nodes WHERE visibility = 'public' and kind = 'method' and  signature NOT GLOB  '.*\(\)';

--
SELECT n1.file_path,n1.start_line, n1.end_line,n2.file_path,n2.start_line,n2.end_line 
FROM nodes n1
  INNER JOIN edges e1 on e1.source = n1.id 
  INNER JOIN nodes n2 on e1.target = n2.id 
WHERE n1.visibility = 'public' 
and n1.kind = 'method' 
and NOT n1.signature REGEXP '.*\(\)' 
and n1.language = 'java' 
and n1.file_path like '%com/huawei/%'
ORDER BY n1.id ;


-- qualified_name,file_path, start_line,end_line 
SELECT * FROM nodes WHERE kind = 'field' and file_path = '上一步查出来的id' ORDER BY qualified_name DESC;


SELECT * FROM nodes WHERE id  in (
SELECT target FROM edges WHERE source in (SELECT id FROM nodes WHERE visibility = 'public' and kind = 'method' and NOT signature REGEXP '.*\(\)') and kind = 'calls');

test:
D:\jar\webgoat




先忽略反思模块，


为啥不使用这种方式解析llm返回呢，from pydantic import BaseModel, Field
from typing import Dict, Optional
from langchain_openai import ChatOpenAI

# 1. 定义你的“模具”（Schema）
class VulnDetail(BaseModel):
    vuln_type: str = Field(description="漏洞类型")
    severity: str = Field(description="严重等级")
    evidence: str = Field(description="漏洞证据")
    payload: str = Field(default="", description="攻击载荷")
    confidence: float = Field(description="置信度")

# 2. 绑定模型并开启结构化输出
llm = ChatOpenAI(model="gpt-4o")
structured_llm = llm.with_structured_output(Dict[str, VulnDetail])

# 3. 直接获取对象（JSON 已经躲在对象属性里了）
# 如果模型输出不合法，LangChain 会自动拦截并要求模型重试
result = structured_llm.invoke("你的审计提示词...") 


需要输入项目的地址，和项目的groupid，而不是写死，


使用SQLAlchemy 操作sql

使用opencode的glm 5.1配置进行代码审计，需要放到env文件里，不git提交


提示词，全部都要写道prompts下面，
注释都要是中文，
AND file_path = :file_path 改成nodeid 查询，

_REFLECT_TEMPLATE = """\
你刚完成一轮 Java 安全审计。复盘以下数据，提出下一轮改进建议。

