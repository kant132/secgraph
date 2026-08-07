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
9、模板必须和代码分离：
   - 所有 prompt 模板、报告模板、文档模板放在 src/prompts/ 目录下（.md 文件）
   - 代码里不内联 f-string 多行模板（禁止 body = f"""..."""）
   - 用 src/prompts/__init__.py 的 render(name, **vars) 加载+填充模板
   - 模板内用 {placeholder} 占位符，不用 f-string（避免 JSON {} 冲突）
   - 默认值在 Python 端算好再传入模板，不在模板里写 or 逻辑
10、提示词必须是原则性、流程性、规则性说明：
   - 禁止为某个具体漏洞类型写专属说明（不写"SQLi：响应中有数据库数据"、"XSS：响应中有 script 标签"等）
   - 禁止为某个具体框架写专属说明（不写"@RequestParam 注解提取"、"Spring AOP"等）
   - 禁止为某个具体目标写专属说明（不写 WebGoat 的 lessonCompleted、/SqlInjectionAdvanced 路径等）
   - 必须用通用原则描述：按 CIA（机密性/完整性/可用性）语义判断，按污点传播流程分析
   - 必须用通用流程描述：先分析→再构造→再测试→失败则改进，循环直到成功或确认不可利用
   - 必须用通用规则描述：消毒措施与漏洞类型匹配才算安全、报错不算成功、session 失效不算失败
    - 输出格式的字段枚举（如 vuln_type 的 SQLi|SSRF|deser|...）不算违规——那是 schema 定义不是漏洞专属说明
11、测试分层规则（pytest markers）：
    - unit: 纯函数测试，无 LLM 无 DB，<2s。改任何代码后必跑。
      文件: test_config, test_pipeline, test_payload, test_login, test_codegraph_tools, test_trace_route
    - integration: mock LLM + 真实 codegraph DB。改 codegraph/record/audit/discovery/llm 后必跑。
      文件: test_refactor_regressions (record/llm cache/discovery memory/prompts)
    - e2e: 真实 LLM 请求（1 个漏洞 SQLi），完整跑 audit→trace→verify→record。大改动才跑。
      文件: test_e2e (1 个 SQLi nodeid，~3 个 LLM 调用)
    - 默认 pytest 只跑 unit + integration（不消耗 token，<3s）
    - pytest -m e2e 只跑 e2e（真实 LLM，~60s）
    - pytest -m "unit or integration or e2e" 全跑（大改动验证）
    - 禁止在 unit/integration 测试里发真实 LLM 请求（必须 mock）
    - e2e 只选 1 个明确有漏洞的 nodeid（SQLi 最可靠），不跑多个漏洞
    - 删除冗余 stage 测试（原 stage2/stage3 已删，逻辑合并到 e2e + integration）