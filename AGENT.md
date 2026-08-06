1、本项目是基于langraph架构开发的反编译代码审计+漏洞自验证+自我反思优化项目
2、构建pipeline，按文件的维度loop 代码审计，结果需要记录到数据库，已验证的是漏洞的问题需要独立记录到md文档
3、区分开发态和运行态，开发态需详细打印日志，仅测试10个左右的文件（审计文件数limit,10，默认无限制）
4、只能使用中文注释
5、codegraph 边类型：
   - route → method 是 kind='references'（不是 calls）
   - method → method 是 kind='calls'
   - Q5 反向追溯 route 入口时必须跟 IN ('calls', 'references')
   - Q6 正向从 route 遍历时必须跟 IN ('calls', 'references')
   - 只跟 calls 会导致 route 可达集只含 route 自身，过滤后返回 0 个方法
   - Q1 不按 visibility='public' 过滤 — protected/private 方法也可能是漏洞点（Spring AOP/反射/内部调用）
   - 过滤策略：Q1 全量方法 → Q6 route 可达集取交集 → 只审 route 能到达的方法
6、LangGraph 节点返回值必须包含所有下游需要读的 state 字段（如 work_list）
   - state.update() 只更新局部副本，LangGraph 只合并 return 的 dict
   - return 缺字段 → 全局 state 读不到 → 路由函数判断错误
7、LLM 结构化输出兼容性：
   - 用 method='json_mode'（比默认 function_calling 更广泛兼容）
   - prompt 前加强约束：不用 markdown 代码块包裹
   - fallback: raw LLM + 剥 markdown + 手动 json 解析
8、Windows 编码：
   - main.py 顶部设 PYTHONUTF8=1 + PYTHONIOENCODING=utf-8
   - 日志用 FileHandler(encoding='utf-8')，不用 PowerShell 重定向（会乱码）
   - print 加 try/except UnicodeEncodeError