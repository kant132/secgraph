"""鑷姩鐢熸垚鐨勬祴璇曟暟鎹?鈥?鏉ヨ嚜鐪熷疄 webgoat codegraph.db"""
from src.state import MethodNode, FieldNode, FileAuditTask

# ============================================================
# SQLI_INJECTABLE 鈥?org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery
# ============================================================
SQLI_INJECTABLE_METHOD = MethodNode(
    id="method:997b7879a35fb0d978b1dec266c18e63",
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery",
    name="injectableQuery",
    signature="AttackResult (String accountName)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    start_line=36, end_line=53,
)

SQLI_INJECTABLE_FIELDS = [
    FieldNode(id="field:2cee44d56b59c48abf0430c36a8271aa", qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::dataSource", name="dataSource", start_line=23, end_line=23),
]

SQLI_INJECTABLE_BODY = "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery\n    public AttackResult injectableQuery(String accountName) {\n        String query = \"\";\n        try {\n            Connection connection = this.dataSource.getConnection();\n            try {\n                boolean usedUnion = unionQueryChecker(accountName);\n                query = \"SELECT * FROM user_data WHERE last_name = '\" + accountName + \"'\";\n                AttackResult attackResultExecuteSqlInjection = executeSqlInjection(connection, query, usedUnion);\n                if (connection != null) {\n                    connection.close();\n                }\n                return attackResultExecuteSqlInjection;\n            } finally {\n            }\n        } catch (Exception e) {\n            return AttackResultBuilder.failed(this).output(getClass().getName() + \" : \" + e.getMessage() + \"<br> Your query was: \" + query).build();\n        }\n    }\n"

SQLI_INJECTABLE_CALLEES = {
    "method:0403e6ad87737fc4bb0ed3579601f302": "// org.owasp.webgoat.container::LessonDataSource::getConnection\n    @Override // javax.sql.DataSource\n    public Connection getConnection() throws SQLException {\n        Connection targetConnection = this.originalDataSource.getConnection();\n        return (Connection) Proxy.newProxyInstance(ConnectionProxy.class.getClassLoader(), new Class[]{ConnectionProxy.class}, new LessonConnectionInvocationHandler(targetConnection));\n    }\n",
    "method:0d370dac488240fd0914521becc21a8d": "// org.apache.commons.lang3::ClassUtils::getClass\n    public static Class<?> getClass(ClassLoader classLoader, String className) throws ClassNotFoundException {\n        return getClass(classLoader, className, true);\n    }\n",
    "method:125da04dd8a1dc26c5d7326cf6578cf8": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::failed\n    public static AttackResultBuilder failed(AssignmentEndpoint assignment) {\n        return new AttackResultBuilder().assignmentCompleted(false).attemptWasMade().feedback(\"assignment.not.solved\").assignment(assignment);\n    }\n",
    "method:20df665d446bd71e644585b43acf7832": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::executeSqlInjection\n    private AttackResult executeSqlInjection(Connection connection, String query, boolean usedUnion) {\n        try {\n            Statement statement = connection.createStatement(1004, 1007);\n            try {\n                ResultSet results = statement.executeQuery(query);\n                if (results == null || !results.first()) {\n                    AttackResult attackResultBuild = AttackResultBuilder.failed(this).feedback(\"sql-injection.advanced.6a.no.results\").output(\"<br> Your query was: \" + query).build();\n                    if (statement != null) {\n                        statement.close();\n                    }\n                    return attackResultBuild;\n                }\n                ResultSetMetaData resultsMetaData = results.getMetaData();\n                StringBuilder output = new StringBuilder();\n                String appendingWhenSucceded = appendSuccededMessage(usedUnion);\n                output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));\n                results.last();\n                AttackResult attackResultVerifySqlInjection = verifySqlInjection(output, appendingWhenSucceded, query);\n                if (statement != null) {\n                    statement.close();\n                }\n                return attackResultVerifySqlInjection;\n            } finally {\n            }\n        } catch (SQLException sqle) {\n            return AttackResultBuilder.failed(this).output(sqle.getMessage() + \"<br> Your query was: \" + query).build();\n        }\n    }\n",
    "method:235bc6497e5a1057756da78d5abcec76": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::output\n    public AttackResultBuilder output(String output) {\n        this.output = output;\n        return this;\n    }\n",
    "method:6132b9dafbe4e0a343bbcf84c0e33021": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::unionQueryChecker\n    private boolean unionQueryChecker(String accountName) {\n        return accountName.matches(\"(?i)(^[^-/*;)]*)(\\\\s*)UNION(.*$)\");\n    }\n",
    "method:9282d1324cc61da65d6fcbda7d4cc557": "// org.flywaydb.core.internal.database.base::Connection::close\n    @Override // java.io.Closeable, java.lang.AutoCloseable\n    public final void close() {\n        restoreOriginalState();\n        restoreOriginalSchema();\n        restoreOriginalAutoCommit();\n        JdbcUtils.closeConnection(this.jdbcConnection);\n    }\n",
    "method:d354dab03332d87dea027fde6364a945": "// org.jruby.exceptions::RaiseException::getMessage\n    @Override // java.lang.Throwable\n    public String getMessage() {\n        if (this.providedMessage == null) {\n            this.providedMessage = '(' + this.exception.getMetaClass().getBaseName() + \") \" + this.exception.message(this.exception.getRuntime().getCurrentContext()).asJavaString();\n        }\n        return this.providedMessage;\n    }\n",
}

SQLI_INJECTABLE_REACHABLE = True

SQLI_INJECTABLE_CHAIN = {
  "id": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:30:POST:/SqlInjectionAdvanced/attack6a",
  "qualified_name": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a",
  "kind": "route",
  "file_path": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
  "start_line": 30,
  "end_line": 30,
  "depth": 2,
  "chain_path": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a -> org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::completed -> org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery",
  "chain_ids": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:30:POST:/SqlInjectionAdvanced/attack6a,method:0d187d9ac1aa8a2efc9d66e1b0077f5d,method:997b7879a35fb0d978b1dec266c18e63"
}

SQLI_INJECTABLE_CHAIN_BODIES = {
    "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:30:POST:/SqlInjectionAdvanced/attack6a": "// sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a\n    @PostMapping({\"/SqlInjectionAdvanced/attack6a\"})\n",
    "method:0d187d9ac1aa8a2efc9d66e1b0077f5d": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::completed\n    @PostMapping({\"/SqlInjectionAdvanced/attack6a\"})\n    @ResponseBody\n    public AttackResult completed(@RequestParam(\"userid_6a\") String userId) {\n        return injectableQuery(userId);\n    }\n",
    "method:997b7879a35fb0d978b1dec266c18e63": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery\n    public AttackResult injectableQuery(String accountName) {\n        String query = \"\";\n        try {\n            Connection connection = this.dataSource.getConnection();\n            try {\n                boolean usedUnion = unionQueryChecker(accountName);\n                query = \"SELECT * FROM user_data WHERE last_name = '\" + accountName + \"'\";\n                AttackResult attackResultExecuteSqlInjection = executeSqlInjection(connection, query, usedUnion);\n                if (connection != null) {\n                    connection.close();\n                }\n                return attackResultExecuteSqlInjection;\n            } finally {\n            }\n        } catch (Exception e) {\n            return AttackResultBuilder.failed(this).output(getClass().getName() + \" : \" + e.getMessage() + \"<br> Your query was: \" + query).build();\n        }\n    }\n",
}

SQLI_INJECTABLE_TASK = FileAuditTask(
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    node_id="method:997b7879a35fb0d978b1dec266c18e63",
    fields=SQLI_INJECTABLE_FIELDS,
    method_bodies={"method:997b7879a35fb0d978b1dec266c18e63": SQLI_INJECTABLE_BODY},
    calls=SQLI_INJECTABLE_CALLEES,
)

# ============================================================
# SQLI_REGISTER 鈥?org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser
# ============================================================
SQLI_REGISTER_METHOD = MethodNode(
    id="method:647d162fdf923cdfbc8d4343d418e51e",
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser",
    name="registerNewUser",
    signature="AttackResult (@RequestParam(\"username_reg\") String username, @RequestParam(\"email_reg\") String email, @RequestParam(\"password_reg\") String password)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java",
    start_line=35, end_line=66,
)

SQLI_REGISTER_FIELDS = [
    FieldNode(id="field:ca63db5ac382db3d8399da381347c23c", qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::dataSource", name="dataSource", start_line=29, end_line=29),
]

SQLI_REGISTER_BODY = "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser\n    @PutMapping({\"/SqlInjectionAdvanced/register\"})\n    @ResponseBody\n    public AttackResult registerNewUser(@RequestParam(\"username_reg\") String username, @RequestParam(\"email_reg\") String email, @RequestParam(\"password_reg\") String password) {\n        AttackResult attackResult = checkArguments(username, email, password);\n        if (attackResult == null) {\n            try {\n                Connection connection = this.dataSource.getConnection();\n                try {\n                    String checkUserQuery = \"select userid from sql_challenge_users where userid = '\" + username + \"'\";\n                    Statement statement = connection.createStatement();\n                    ResultSet resultSet = statement.executeQuery(checkUserQuery);\n                    if (resultSet.next()) {\n                        attackResult = AttackResultBuilder.failed(this).feedback(\"user.exists\").feedbackArgs(username).build();\n                    } else {\n                        PreparedStatement preparedStatement = connection.prepareStatement(\"INSERT INTO sql_challenge_users VALUES (?, ?, ?)\");\n                        preparedStatement.setString(1, username);\n                        preparedStatement.setString(2, email);\n                        preparedStatement.setString(3, password);\n                        preparedStatement.execute();\n                        attackResult = AttackResultBuilder.informationMessage(this).feedback(\"user.created\").feedbackArgs(username).build();\n                    }\n                    if (connection != null) {\n                        connection.close();\n                    }\n                } finally {\n                }\n            } catch (SQLException e) {\n                attackResult = AttackResultBuilder.failed(this).output(\"Something went wrong\").build();\n            }\n        }\n        return attackResult;\n    }\n"

SQLI_REGISTER_CALLEES = {
    "method:0403e6ad87737fc4bb0ed3579601f302": "// org.owasp.webgoat.container::LessonDataSource::getConnection\n    @Override // javax.sql.DataSource\n    public Connection getConnection() throws SQLException {\n        Connection targetConnection = this.originalDataSource.getConnection();\n        return (Connection) Proxy.newProxyInstance(ConnectionProxy.class.getClassLoader(), new Class[]{ConnectionProxy.class}, new LessonConnectionInvocationHandler(targetConnection));\n    }\n",
    "method:125da04dd8a1dc26c5d7326cf6578cf8": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::failed\n    public static AttackResultBuilder failed(AssignmentEndpoint assignment) {\n        return new AttackResultBuilder().assignmentCompleted(false).attemptWasMade().feedback(\"assignment.not.solved\").assignment(assignment);\n    }\n",
    "method:235bc6497e5a1057756da78d5abcec76": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::output\n    public AttackResultBuilder output(String output) {\n        this.output = output;\n        return this;\n    }\n",
    "method:367644a48636c66e78884397f338eddc": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::feedback\n    public AttackResultBuilder feedback(String resourceBundleKey) {\n        this.feedbackResourceBundleKey = resourceBundleKey;\n        return this;\n    }\n",
    "method:6e853139310d17d73338e0a82936ac56": "// com.zaxxer.hikari.pool::HikariProxyConnection::prepareStatement\n    @Override // com.zaxxer.hikari.pool.ProxyConnection, java.sql.Connection\n    public PreparedStatement prepareStatement(String str) throws SQLException {\n        try {\n            return super.prepareStatement(str);\n        } catch (SQLException e) {\n            throw checkException(e);\n        }\n    }\n",
    "method:6fa9453dda86a3c0f83e963674bc78d2": "// com.zaxxer.hikari.pool::HikariProxyCallableStatement::executeQuery\n    @Override // com.zaxxer.hikari.pool.ProxyStatement, java.sql.Statement\n    public ResultSet executeQuery(String str) throws SQLException {\n        try {\n            return super.executeQuery(str);\n        } catch (SQLException e) {\n            throw checkException(e);\n        }\n    }\n",
    "method:757f90f43ad29e75a8975eafc523850b": "// com.zaxxer.hikari.pool::HikariProxyConnection::createStatement\n    @Override // com.zaxxer.hikari.pool.ProxyConnection, java.sql.Connection\n    public Statement createStatement() throws SQLException {\n        try {\n            return super.createStatement();\n        } catch (SQLException e) {\n            throw checkException(e);\n        }\n    }\n",
    "method:7f8d3de3c76015660415dddc3cd2b73a": "// com.zaxxer.hikari.pool::HikariProxyPreparedStatement::setString\n    @Override // java.sql.PreparedStatement\n    public void setString(int i, String str) throws SQLException {\n        try {\n            ((PreparedStatement) this.delegate).setString(i, str);\n        } catch (SQLException e) {\n            throw checkException(e);\n        }\n    }\n",
    "method:9282d1324cc61da65d6fcbda7d4cc557": "// org.flywaydb.core.internal.database.base::Connection::close\n    @Override // java.io.Closeable, java.lang.AutoCloseable\n    public final void close() {\n        restoreOriginalState();\n        restoreOriginalSchema();\n        restoreOriginalAutoCommit();\n        JdbcUtils.closeConnection(this.jdbcConnection);\n    }\n",
    "method:c8d2ee03639304c5505f42f0abb2e40b": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::checkArguments\n    private AttackResult checkArguments(String username, String email, String password) {\n        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(email) || StringUtils.isEmpty(password)) {\n            return AttackResultBuilder.failed(this).feedback(\"input.invalid\").build();\n        }\n        if (username.length() > 250 || email.length() > 30 || password.length() > 30) {\n            return AttackResultBuilder.failed(this).feedback(\"input.invalid\").build();\n        }\n        return null;\n    }\n",
    "method:ee28a2b0bd584ac5a082ff39816cdaf0": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::informationMessage\n    public static AttackResultBuilder informationMessage(AssignmentEndpoint assignment) {\n        return new AttackResultBuilder().assignmentCompleted(false).assignment(assignment);\n    }\n",
}

SQLI_REGISTER_REACHABLE = True

SQLI_REGISTER_CHAIN = {
  "id": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:35:PUT:/SqlInjectionAdvanced/register",
  "qualified_name": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java::route:/SqlInjectionAdvanced/register",
  "kind": "route",
  "file_path": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java",
  "start_line": 35,
  "end_line": 35,
  "depth": 1,
  "chain_path": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java::route:/SqlInjectionAdvanced/register -> org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser",
  "chain_ids": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:35:PUT:/SqlInjectionAdvanced/register,method:647d162fdf923cdfbc8d4343d418e51e"
}

SQLI_REGISTER_CHAIN_BODIES = {
    "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:35:PUT:/SqlInjectionAdvanced/register": "// sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java::route:/SqlInjectionAdvanced/register\n    @PutMapping({\"/SqlInjectionAdvanced/register\"})\n",
    "method:647d162fdf923cdfbc8d4343d418e51e": "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser\n    @PutMapping({\"/SqlInjectionAdvanced/register\"})\n    @ResponseBody\n    public AttackResult registerNewUser(@RequestParam(\"username_reg\") String username, @RequestParam(\"email_reg\") String email, @RequestParam(\"password_reg\") String password) {\n        AttackResult attackResult = checkArguments(username, email, password);\n        if (attackResult == null) {\n            try {\n                Connection connection = this.dataSource.getConnection();\n                try {\n                    String checkUserQuery = \"select userid from sql_challenge_users where userid = '\" + username + \"'\";\n                    Statement statement = connection.createStatement();\n                    ResultSet resultSet = statement.executeQuery(checkUserQuery);\n                    if (resultSet.next()) {\n                        attackResult = AttackResultBuilder.failed(this).feedback(\"user.exists\").feedbackArgs(username).build();\n                    } else {\n                        PreparedStatement preparedStatement = connection.prepareStatement(\"INSERT INTO sql_challenge_users VALUES (?, ?, ?)\");\n                        preparedStatement.setString(1, username);\n                        preparedStatement.setString(2, email);\n                        preparedStatement.setString(3, password);\n                        preparedStatement.execute();\n                        attackResult = AttackResultBuilder.informationMessage(this).feedback(\"user.created\").feedbackArgs(username).build();\n                    }\n                    if (connection != null) {\n                        connection.close();\n                    }\n                } finally {\n                }\n            } catch (SQLException e) {\n                attackResult = AttackResultBuilder.failed(this).output(\"Something went wrong\").build();\n            }\n        }\n        return attackResult;\n    }\n",
}

SQLI_REGISTER_TASK = FileAuditTask(
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java",
    node_id="method:647d162fdf923cdfbc8d4343d418e51e",
    fields=SQLI_REGISTER_FIELDS,
    method_bodies={"method:647d162fdf923cdfbc8d4343d418e51e": SQLI_REGISTER_BODY},
    calls=SQLI_REGISTER_CALLEES,
)

# ============================================================
# XSS_COMPLETED 鈥?org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed
# ============================================================
XSS_COMPLETED_METHOD = MethodNode(
    id="method:7ee6991165334a5b9998084beba380b5",
    qualified_name="org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed",
    name="completed",
    signature="AttackResult (@RequestParam(value = \"checkboxAttack1\", required = false) String checkboxValue)",
    file_path="sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java",
    start_line=14, end_line=21,
)

XSS_COMPLETED_FIELDS = [
]

XSS_COMPLETED_BODY = "// org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed\n    @PostMapping({\"/CrossSiteScripting/attack1\"})\n    @ResponseBody\n    public AttackResult completed(@RequestParam(value = \"checkboxAttack1\", required = false) String checkboxValue) {\n        if (checkboxValue != null) {\n            return AttackResultBuilder.success(this).build();\n        }\n        return AttackResultBuilder.failed(this).feedback(\"xss.lesson1.failure\").build();\n    }\n"

XSS_COMPLETED_CALLEES = {
    "method:125da04dd8a1dc26c5d7326cf6578cf8": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::failed\n    public static AttackResultBuilder failed(AssignmentEndpoint assignment) {\n        return new AttackResultBuilder().assignmentCompleted(false).attemptWasMade().feedback(\"assignment.not.solved\").assignment(assignment);\n    }\n",
    "method:367644a48636c66e78884397f338eddc": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::feedback\n    public AttackResultBuilder feedback(String resourceBundleKey) {\n        this.feedbackResourceBundleKey = resourceBundleKey;\n        return this;\n    }\n",
    "method:37338ce0a09bfabbf89f419366d3a39c": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::build\n    public AttackResult build() {\n        return new AttackResult(this.assignmentCompleted, this.feedbackResourceBundleKey, this.feedbackArgs, this.output, this.outputArgs, this.assignment.getClass().getSimpleName(), this.attemptWasMade);\n    }\n",
    "method:ec292eecb294ede7e368f38aa0e4a981": "// org.owasp.webgoat.container.assignments::AttackResultBuilder::success\n    public static AttackResultBuilder success(AssignmentEndpoint assignment) {\n        return new AttackResultBuilder().assignmentCompleted(true).attemptWasMade().feedback(\"assignment.solved\").assignment(assignment);\n    }\n",
}

XSS_COMPLETED_REACHABLE = True

XSS_COMPLETED_CHAIN = {
  "id": "route:sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java:14:POST:/CrossSiteScripting/attack1",
  "qualified_name": "sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java::route:/CrossSiteScripting/attack1",
  "kind": "route",
  "file_path": "sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java",
  "start_line": 14,
  "end_line": 14,
  "depth": 1,
  "chain_path": "sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java::route:/CrossSiteScripting/attack1 -> org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed",
  "chain_ids": "route:sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java:14:POST:/CrossSiteScripting/attack1,method:7ee6991165334a5b9998084beba380b5"
}

XSS_COMPLETED_CHAIN_BODIES = {
    "route:sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java:14:POST:/CrossSiteScripting/attack1": "// sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java::route:/CrossSiteScripting/attack1\n    @PostMapping({\"/CrossSiteScripting/attack1\"})\n",
    "method:7ee6991165334a5b9998084beba380b5": "// org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed\n    @PostMapping({\"/CrossSiteScripting/attack1\"})\n    @ResponseBody\n    public AttackResult completed(@RequestParam(value = \"checkboxAttack1\", required = false) String checkboxValue) {\n        if (checkboxValue != null) {\n            return AttackResultBuilder.success(this).build();\n        }\n        return AttackResultBuilder.failed(this).feedback(\"xss.lesson1.failure\").build();\n    }\n",
}

XSS_COMPLETED_TASK = FileAuditTask(
    file_path="sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java",
    node_id="method:7ee6991165334a5b9998084beba380b5",
    fields=XSS_COMPLETED_FIELDS,
    method_bodies={"method:7ee6991165334a5b9998084beba380b5": XSS_COMPLETED_BODY},
    calls=XSS_COMPLETED_CALLEES,
)

# ============================================================
# UNREACHABLE 鈥?org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::SqlInjectionLesson6a
# ============================================================
UNREACHABLE_METHOD = MethodNode(
    id="method:1a6f33df415e87274a6d8b8b3c777423",
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::SqlInjectionLesson6a",
    name="SqlInjectionLesson6a",
    signature="(LessonDataSource dataSource)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    start_line=26, end_line=28,
)

UNREACHABLE_FIELDS = [
    FieldNode(id="field:2cee44d56b59c48abf0430c36a8271aa", qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::dataSource", name="dataSource", start_line=23, end_line=23),
]

UNREACHABLE_BODY = "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::SqlInjectionLesson6a\n    public SqlInjectionLesson6a(LessonDataSource dataSource) {\n        this.dataSource = dataSource;\n    }\n"

UNREACHABLE_CALLEES = {
}

UNREACHABLE_REACHABLE = False

UNREACHABLE_CHAIN = []  # 涓嶅彲杈?

UNREACHABLE_CHAIN_BODIES = {
}

UNREACHABLE_TASK = FileAuditTask(
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    node_id="method:1a6f33df415e87274a6d8b8b3c777423",
    fields=UNREACHABLE_FIELDS,
    method_bodies={"method:1a6f33df415e87274a6d8b8b3c777423": UNREACHABLE_BODY},
    calls=UNREACHABLE_CALLEES,
)

