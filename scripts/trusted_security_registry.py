#!/usr/bin/env python3
"""
Trusted Security Operations Registry

All security-relevant operations (sinks, sources, sanitizers, crypto, auth,
file I/O, network, deserialization) systematically collected from:

  - CodeQL (github/codeql) query metadata
  - Semgrep (semgrep/semgrep-rules) rule definitions
  - Bandit (PyCQA/bandit) check documentation
  - MITRE CWE definitions

Each operation is documented with:
  - The API pattern to detect in source code
  - The trusted source rule ID(s)
  - The CWE mapping
  - A human-readable description

Keywords for description analysis are derived from CWE names and
rule descriptions, NOT manually invented.

This module is imported by build_ground_truth.py and analyze_transparency_v2.py.
"""

import json
import re
from pathlib import Path

# =========================================================================
# Security Properties
# =========================================================================

SECURITY_PROPERTIES = [
    "COMMAND_EXEC",
    "FILE_SYSTEM",
    "NETWORK",
    "DATABASE",
    "INFO_EXPOSURE",
    "CRYPTO",
    "DESERIALIZATION",
    "AUTH",
]

PROPERTY_RISK = {
    "COMMAND_EXEC": "Critical",
    "FILE_SYSTEM": "High",
    "NETWORK": "High",
    "DATABASE": "High",
    "INFO_EXPOSURE": "Medium",
    "CRYPTO": "Medium",
    "DESERIALIZATION": "High",
    "AUTH": "High",
}


# =========================================================================
# Security-Relevant Operations Registry
#
# Structure: { property: { "python": [...], "typescript": [...], "javascript": [...] } }
# Each entry: { "apis": [...], "pattern": regex, "sources": [...], "cwes": [...] }
#
# "sources" lists the trusted tool + rule ID.
# "cwes" lists the MITRE CWE identifiers.
# =========================================================================

SECURITY_OPERATIONS = {
    "COMMAND_EXEC": {
        "cwes": ["CWE-078", "CWE-094", "CWE-095"],
        "cwe_names": {
            "CWE-078": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
            "CWE-094": "Improper Control of Generation of Code (Code Injection)",
            "CWE-095": "Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)",
        },
        "python": [
            {
                "apis": ["subprocess.run", "subprocess.call", "subprocess.Popen",
                         "subprocess.check_output", "subprocess.check_call",
                         "subprocess.getoutput", "subprocess.getstatusoutput"],
                "pattern": r"subprocess\.\w+\s*\(",
                "import_pattern": r"(?:import\s+subprocess|from\s+subprocess\s+import)",
                "sources": [
                    "CodeQL py/command-line-injection",
                    "Bandit B603 (subprocess_without_shell_equals_true)",
                    "Bandit B604 (any_other_function_with_shell_equals_true)",
                    "Bandit B607 (start_process_with_partial_path)",
                    "Semgrep python.lang.security.audit.subprocess-shell-true",
                ],
            },
            {
                "apis": ["os.system"],
                "pattern": r"os\.system\s*\(",
                "import_pattern": r"(?:import\s+os|from\s+os\s+import\s+system)",
                "sources": [
                    "CodeQL py/command-line-injection",
                    "Bandit B605 (start_process_with_a_shell)",
                ],
            },
            {
                "apis": ["os.popen", "os.popen2", "os.popen3", "os.popen4"],
                "pattern": r"os\.popen\d?\s*\(",
                "import_pattern": r"(?:import\s+os|from\s+os\s+import)",
                "sources": [
                    "Bandit B605 (start_process_with_a_shell)",
                ],
            },
            {
                "apis": ["os.execl", "os.execle", "os.execlp", "os.execlpe",
                         "os.execv", "os.execve", "os.execvp", "os.execvpe",
                         "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
                         "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe"],
                "pattern": r"os\.(?:exec|spawn)\w+\s*\(",
                "import_pattern": r"(?:import\s+os|from\s+os\s+import)",
                "sources": [
                    "Bandit B606 (start_process_with_no_shell)",
                ],
            },
            {
                "apis": ["eval"],
                "pattern": r"(?<!\w)eval\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL py/code-injection",
                    "Bandit B307 (eval)",
                ],
            },
            {
                "apis": ["exec"],
                "pattern": r"(?<!\w)exec\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL py/code-injection",
                    "Bandit B102 (exec_used)",
                ],
            },
            {
                "apis": ["compile"],
                "pattern": r"(?<!\w)compile\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL py/code-injection",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["child_process.exec", "child_process.execSync",
                         "child_process.spawn", "child_process.spawnSync",
                         "child_process.execFile", "child_process.execFileSync",
                         "child_process.fork"],
                "pattern": r"(?:child_process\.\w+|exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]child_process['\"]|from\s+['\"]child_process['\"]|import\s+.*child_process)",
                "sources": [
                    "CodeQL js/command-line-injection",
                    "Semgrep javascript.lang.security.audit.child-process",
                ],
            },
            {
                "apis": ["eval"],
                "pattern": r"(?<!\w)eval\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/code-injection",
                    "Semgrep javascript.lang.security.audit.eval-detected",
                ],
            },
            {
                "apis": ["Function"],
                "pattern": r"(?:new\s+Function|Function\s*\()",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/code-injection",
                ],
            },
            {
                "apis": ["vm.runInContext", "vm.runInNewContext",
                         "vm.runInThisContext", "vm.createContext"],
                "pattern": r"vm\.(?:runIn\w+|createContext)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]vm['\"]|from\s+['\"]vm['\"])",
                "sources": [
                    "CodeQL js/code-injection",
                ],
            },
        ],
        "javascript": None,  # Same as typescript
    },

    "FILE_SYSTEM": {
        "cwes": ["CWE-022", "CWE-073", "CWE-377", "CWE-732"],
        "cwe_names": {
            "CWE-022": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
            "CWE-073": "External Control of File Name or Path",
            "CWE-377": "Insecure Temporary File",
            "CWE-732": "Incorrect Permission Assignment for Critical Resource",
        },
        "python": [
            {
                "apis": ["open", "io.open"],
                "pattern": r"(?<!\w)(?:open|io\.open)\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL py/path-injection",
                    "Semgrep python.lang.security.audit.open-with-user-input",
                ],
            },
            {
                "apis": ["pathlib.Path.read_text", "pathlib.Path.write_text",
                         "pathlib.Path.read_bytes", "pathlib.Path.write_bytes",
                         "pathlib.Path.mkdir", "pathlib.Path.rmdir",
                         "pathlib.Path.unlink", "pathlib.Path.rename",
                         "pathlib.Path.open", "pathlib.Path.touch",
                         "pathlib.Path.glob", "pathlib.Path.iterdir"],
                "pattern": r"(?:Path|pathlib)\s*\(|\.(?:read_text|write_text|read_bytes|write_bytes|mkdir|rmdir|unlink|rename|open|touch|glob|iterdir)\s*\(",
                "import_pattern": r"(?:import\s+pathlib|from\s+pathlib\s+import)",
                "sources": [
                    "CodeQL py/path-injection",
                ],
            },
            {
                "apis": ["os.remove", "os.unlink", "os.rmdir", "os.mkdir",
                         "os.makedirs", "os.rename", "os.listdir", "os.walk",
                         "os.scandir", "os.path.exists", "os.path.join",
                         "os.chmod", "os.chown", "os.stat"],
                "pattern": r"os\.(?:remove|unlink|rmdir|mkdir|makedirs|rename|listdir|walk|scandir|chmod|chown|stat|path\.(?:exists|join|isfile|isdir|abspath|realpath))\s*\(",
                "import_pattern": r"(?:import\s+os|from\s+os\s+import|from\s+os\.path\s+import)",
                "sources": [
                    "CodeQL py/path-injection",
                    "Bandit B103 (set_bad_file_permissions)",
                ],
            },
            {
                "apis": ["shutil.copy", "shutil.copy2", "shutil.copytree",
                         "shutil.move", "shutil.rmtree", "shutil.disk_usage"],
                "pattern": r"shutil\.(?:copy2?|copytree|move|rmtree|disk_usage)\s*\(",
                "import_pattern": r"(?:import\s+shutil|from\s+shutil\s+import)",
                "sources": [
                    "CodeQL py/path-injection",
                ],
            },
            {
                "apis": ["tempfile.mktemp", "tempfile.mkdtemp",
                         "tempfile.NamedTemporaryFile", "tempfile.TemporaryDirectory"],
                "pattern": r"tempfile\.(?:mktemp|mkdtemp|NamedTemporaryFile|TemporaryDirectory)\s*\(",
                "import_pattern": r"(?:import\s+tempfile|from\s+tempfile\s+import)",
                "sources": [
                    "Bandit B306 (mktemp_q)",
                    "Bandit B108 (hardcoded_tmp_directory)",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["fs.readFile", "fs.readFileSync", "fs.writeFile",
                         "fs.writeFileSync", "fs.appendFile", "fs.appendFileSync",
                         "fs.unlink", "fs.unlinkSync", "fs.rename", "fs.renameSync",
                         "fs.mkdir", "fs.mkdirSync", "fs.rmdir", "fs.rmdirSync",
                         "fs.readdir", "fs.readdirSync", "fs.stat", "fs.statSync",
                         "fs.access", "fs.accessSync", "fs.copyFile", "fs.copyFileSync",
                         "fs.rm", "fs.rmSync", "fs.chmod", "fs.chmodSync",
                         "fs.createReadStream", "fs.createWriteStream"],
                "pattern": r"fs(?:Promises?)?\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rename|renameSync|mkdir|mkdirSync|rmdir|rmdirSync|readdir|readdirSync|stat|statSync|access|accessSync|copyFile|copyFileSync|rm|rmSync|chmod|chmodSync|createReadStream|createWriteStream|promises\.(?:readFile|writeFile|unlink|rename|mkdir|rmdir|readdir|stat|access|copyFile|rm))\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:fs|fs/promises|node:fs|node:fs/promises)['\"]|from\s+['\"](?:fs|fs/promises|node:fs|node:fs/promises)['\"]|import\s+.*['\"](?:fs|node:fs)['\"])",
                "sources": [
                    "CodeQL js/path-injection",
                    "Semgrep javascript.lang.security.audit.path-traversal",
                ],
            },
        ],
        "javascript": None,  # Same as typescript
    },

    "NETWORK": {
        "cwes": ["CWE-918", "CWE-295", "CWE-319", "CWE-601"],
        "cwe_names": {
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-295": "Improper Certificate Validation",
            "CWE-319": "Cleartext Transmission of Sensitive Information",
            "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
        },
        "python": [
            {
                "apis": ["requests.get", "requests.post", "requests.put",
                         "requests.delete", "requests.patch", "requests.head",
                         "requests.request", "requests.Session"],
                "pattern": r"requests\.(?:get|post|put|delete|patch|head|request|Session)\s*\(",
                "import_pattern": r"(?:import\s+requests|from\s+requests\s+import)",
                "sources": [
                    "CodeQL py/request-forgery",
                    "Bandit B309 (httpsconnection)",
                    "Semgrep python.lang.security.audit.dynamic-urllib-use-detected",
                ],
            },
            {
                "apis": ["urllib.request.urlopen", "urllib.request.urlretrieve",
                         "urllib.request.Request"],
                "pattern": r"urllib\.request\.(?:urlopen|urlretrieve|Request)\s*\(",
                "import_pattern": r"(?:import\s+urllib|from\s+urllib\.request\s+import|from\s+urllib\s+import)",
                "sources": [
                    "CodeQL py/request-forgery",
                    "Bandit B310 (urllib_urlopen)",
                    "Semgrep python.lang.security.audit.dynamic-urllib-use-detected",
                ],
            },
            {
                "apis": ["http.client.HTTPConnection", "http.client.HTTPSConnection"],
                "pattern": r"(?:http\.client\.)?HTTPS?Connection\s*\(",
                "import_pattern": r"(?:import\s+http\.client|from\s+http\.client\s+import)",
                "sources": [
                    "Bandit B309 (httpsconnection)",
                ],
            },
            {
                "apis": ["httpx.get", "httpx.post", "httpx.put", "httpx.delete",
                         "httpx.Client", "httpx.AsyncClient"],
                "pattern": r"httpx\.(?:get|post|put|delete|Client|AsyncClient)\s*\(",
                "import_pattern": r"(?:import\s+httpx|from\s+httpx\s+import)",
                "sources": [
                    "CodeQL py/request-forgery",
                ],
            },
            {
                "apis": ["aiohttp.ClientSession", "aiohttp.request"],
                "pattern": r"aiohttp\.(?:ClientSession|request)\s*\(",
                "import_pattern": r"(?:import\s+aiohttp|from\s+aiohttp\s+import)",
                "sources": [
                    "CodeQL py/request-forgery",
                ],
            },
            {
                "apis": ["socket.socket", "socket.create_connection"],
                "pattern": r"socket\.(?:socket|create_connection)\s*\(",
                "import_pattern": r"(?:import\s+socket|from\s+socket\s+import)",
                "sources": [
                    "Bandit B104 (hardcoded_bind_all_interfaces)",
                    "CodeQL py/bind-socket-all-network-interfaces",
                ],
            },
            {
                "apis": ["ftplib.FTP", "ftplib.FTP_TLS"],
                "pattern": r"(?:ftplib\.)?FTP(?:_TLS)?\s*\(",
                "import_pattern": r"(?:import\s+ftplib|from\s+ftplib\s+import)",
                "sources": [
                    "Bandit B321 (ftp)",
                    "Bandit B402 (import_ftplib)",
                ],
            },
            {
                "apis": ["xmlrpc.client.ServerProxy"],
                "pattern": r"(?:xmlrpc\.client\.)?ServerProxy\s*\(",
                "import_pattern": r"(?:import\s+xmlrpc|from\s+xmlrpc\.client\s+import)",
                "sources": [
                    "Bandit B411 (import_xmlrpc)",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["fetch"],
                "pattern": r"(?<!\w)fetch\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]node-fetch['\"]|from\s+['\"]node-fetch['\"]|import\s+.*['\"]node-fetch['\"])",
                "sources": [
                    "CodeQL js/request-forgery",
                ],
            },
            {
                "apis": ["axios.get", "axios.post", "axios.put", "axios.delete",
                         "axios.patch", "axios.request", "axios.create"],
                "pattern": r"axios\.(?:get|post|put|delete|patch|request|create)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]axios['\"]|from\s+['\"]axios['\"]|import\s+.*['\"]axios['\"])",
                "sources": [
                    "CodeQL js/request-forgery",
                ],
            },
            {
                "apis": ["http.request", "http.get", "https.request", "https.get",
                         "http.createServer", "https.createServer"],
                "pattern": r"https?\.(?:request|get|createServer)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:https?|node:https?)['\"]|from\s+['\"](?:https?|node:https?)['\"])",
                "sources": [
                    "CodeQL js/request-forgery",
                ],
            },
            {
                "apis": ["XMLHttpRequest"],
                "pattern": r"(?:new\s+)?XMLHttpRequest\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/request-forgery",
                ],
            },
            {
                "apis": ["net.createConnection", "net.connect", "net.Socket"],
                "pattern": r"net\.(?:createConnection|connect|Socket)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:net|node:net)['\"]|from\s+['\"](?:net|node:net)['\"])",
                "sources": [
                    "CodeQL js/request-forgery",
                ],
            },
        ],
        "javascript": None,
    },

    "DATABASE": {
        "cwes": ["CWE-089", "CWE-943"],
        "cwe_names": {
            "CWE-089": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
            "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
        },
        "python": [
            {
                "apis": ["sqlite3.connect", "cursor.execute", "cursor.executemany",
                         "cursor.executescript"],
                "pattern": r"(?:sqlite3\.connect|\.execute(?:many|script)?)\s*\(",
                "import_pattern": r"(?:import\s+sqlite3|from\s+sqlite3\s+import)",
                "sources": [
                    "CodeQL py/sql-injection",
                    "Bandit B608 (hardcoded_sql_expressions)",
                ],
            },
            {
                "apis": ["psycopg2.connect", "psycopg.connect"],
                "pattern": r"psycopg2?\.connect\s*\(",
                "import_pattern": r"(?:import\s+psycopg2?|from\s+psycopg2?\s+import)",
                "sources": [
                    "CodeQL py/sql-injection",
                    "Bandit B608 (hardcoded_sql_expressions)",
                ],
            },
            {
                "apis": ["pymysql.connect", "MySQLdb.connect", "mysql.connector.connect"],
                "pattern": r"(?:pymysql|MySQLdb|mysql\.connector)\.connect\s*\(",
                "import_pattern": r"(?:import\s+(?:pymysql|MySQLdb|mysql\.connector)|from\s+(?:pymysql|MySQLdb|mysql\.connector)\s+import)",
                "sources": [
                    "CodeQL py/sql-injection",
                ],
            },
            {
                "apis": ["sqlalchemy.create_engine", "sqlalchemy.text",
                         "session.execute", "engine.execute"],
                "pattern": r"(?:create_engine|sqlalchemy\.text|\.execute)\s*\(",
                "import_pattern": r"(?:import\s+sqlalchemy|from\s+sqlalchemy\s+import)",
                "sources": [
                    "CodeQL py/sql-injection",
                    "Semgrep python.sqlalchemy.security.sqlalchemy-execute-raw-query",
                ],
            },
            {
                "apis": ["pymongo.MongoClient", "collection.find", "collection.insert_one",
                         "collection.update_one", "collection.delete_one",
                         "collection.aggregate"],
                "pattern": r"(?:MongoClient|\.(?:find|find_one|insert_one|insert_many|update_one|update_many|delete_one|delete_many|aggregate|count_documents))\s*\(",
                "import_pattern": r"(?:import\s+pymongo|from\s+pymongo\s+import)",
                "sources": [
                    "CodeQL py/nosql-injection",
                    "Semgrep python.pymongo.security.nosql-injection",
                ],
            },
            {
                "apis": ["redis.Redis", "redis.StrictRedis", "redis.from_url"],
                "pattern": r"(?:redis\.(?:Redis|StrictRedis|from_url)|Redis\(|StrictRedis\()\s*\(?\s*",
                "import_pattern": r"(?:import\s+redis|from\s+redis\s+import)",
                "sources": [
                    "Semgrep python.redis.security.injection",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["pg.Client", "pg.Pool", "client.query", "pool.query"],
                "pattern": r"(?:(?:new\s+)?(?:Client|Pool)\s*\(|\.query\s*\()",
                "import_pattern": r"(?:require\s*\(\s*['\"]pg['\"]|from\s+['\"]pg['\"]|import\s+.*['\"]pg['\"])",
                "sources": [
                    "CodeQL js/sql-injection",
                ],
            },
            {
                "apis": ["mysql.createConnection", "mysql.createPool",
                         "connection.query", "connection.execute"],
                "pattern": r"(?:createConnection|createPool|\.query|\.execute)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]mysql2?['\"]|from\s+['\"]mysql2?['\"]|import\s+.*['\"]mysql2?['\"])",
                "sources": [
                    "CodeQL js/sql-injection",
                ],
            },
            {
                "apis": ["mongoose.connect", "mongoose.model",
                         "Model.find", "Model.findOne", "Model.create",
                         "Model.updateOne", "Model.deleteOne"],
                "pattern": r"(?:mongoose\.(?:connect|model)|\.(?:find|findOne|findById|create|updateOne|updateMany|deleteOne|deleteMany|aggregate))\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]mongoose['\"]|from\s+['\"]mongoose['\"]|import\s+.*['\"]mongoose['\"])",
                "sources": [
                    "CodeQL js/nosql-injection",
                    "Semgrep javascript.mongoose.security.nosql-injection",
                ],
            },
            {
                "apis": ["sequelize.query", "knex.raw", "prisma"],
                "pattern": r"(?:\.query\s*\(|knex\.raw\s*\(|prisma\.\w+\.(?:findMany|findUnique|findFirst|create|update|delete|upsert))\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:sequelize|knex|@prisma/client)['\"]|from\s+['\"](?:sequelize|knex|@prisma/client)['\"])",
                "sources": [
                    "CodeQL js/sql-injection",
                    "Semgrep javascript.sequelize.security.audit",
                ],
            },
            {
                "apis": ["redis.createClient", "ioredis"],
                "pattern": r"(?:createClient|Redis)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:redis|ioredis)['\"]|from\s+['\"](?:redis|ioredis)['\"])",
                "sources": [
                    "Semgrep javascript.redis.security.injection",
                ],
            },
        ],
        "javascript": None,
    },

    "INFO_EXPOSURE": {
        "cwes": ["CWE-200", "CWE-209", "CWE-215", "CWE-312", "CWE-532", "CWE-798"],
        "cwe_names": {
            "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
            "CWE-209": "Generation of Error Message Containing Sensitive Information",
            "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
            "CWE-312": "Cleartext Storage of Sensitive Information",
            "CWE-532": "Insertion of Sensitive Information into Log File",
            "CWE-798": "Use of Hard-coded Credentials",
        },
        "python": [
            {
                "apis": ["os.environ", "os.getenv", "os.environ.get"],
                "pattern": r"os\.(?:environ|getenv)\s*[\.\[\(]",
                "import_pattern": r"(?:import\s+os|from\s+os\s+import)",
                "sources": [
                    "CodeQL py/clear-text-logging-sensitive-data",
                    "Semgrep python.lang.security.audit.dangerous-os-exec-detected",
                ],
            },
            {
                "apis": ["dotenv.load_dotenv", "dotenv_values"],
                "pattern": r"(?:load_dotenv|dotenv_values)\s*\(",
                "import_pattern": r"(?:import\s+dotenv|from\s+dotenv\s+import)",
                "sources": [
                    "Semgrep python.lang.security.audit.env-access",
                ],
            },
            {
                "apis": ["logging.debug", "logging.info", "logging.warning",
                         "logging.error", "logging.critical", "logging.exception",
                         "logger.debug", "logger.info", "logger.warning",
                         "logger.error"],
                "pattern": r"(?:logging|logger)\.(?:debug|info|warning|error|critical|exception)\s*\(",
                "import_pattern": r"(?:import\s+logging|from\s+logging\s+import)",
                "sources": [
                    "CodeQL py/clear-text-logging-sensitive-data",
                    "Bandit B110 (try_except_pass)",
                ],
            },
            {
                # Hardcoded credentials
                "apis": ["hardcoded_password", "hardcoded_secret"],
                "pattern": r"""(?:password|passwd|secret|api_key|apikey|token|auth_token|access_key|secret_key)\s*=\s*['"][^'"]{4,}['"]""",
                "import_pattern": None,
                "sources": [
                    "Bandit B105 (hardcoded_password_string)",
                    "Bandit B106 (hardcoded_password_funcarg)",
                    "Bandit B107 (hardcoded_password_default)",
                    "CodeQL py/hardcoded-credentials",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["process.env"],
                "pattern": r"process\.env\s*[\.\[]",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/clear-text-logging",
                    "Semgrep javascript.lang.security.audit.environment-access",
                ],
            },
            {
                "apis": ["dotenv.config"],
                "pattern": r"(?:dotenv\.config|config\(\{)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]dotenv['\"]|from\s+['\"]dotenv['\"]|import\s+.*['\"]dotenv['\"])",
                "sources": [
                    "Semgrep javascript.lang.security.audit.environment-access",
                ],
            },
            {
                "apis": ["console.log", "console.error", "console.warn",
                         "console.debug", "console.info"],
                "pattern": r"console\.(?:log|error|warn|debug|info)\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/clear-text-logging",
                ],
            },
            {
                "apis": ["hardcoded_credentials"],
                "pattern": r"""(?:password|secret|api[_-]?key|token|auth[_-]?token|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"][^'"]{4,}['"]""",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/hardcoded-credentials",
                    "Semgrep javascript.lang.security.audit.hardcoded-credentials",
                ],
            },
        ],
        "javascript": None,
    },

    "CRYPTO": {
        "cwes": ["CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338"],
        "cwe_names": {
            "CWE-326": "Inadequate Encryption Strength",
            "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-328": "Use of Weak Hash",
            "CWE-330": "Use of Insufficiently Random Values",
            "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
        },
        "python": [
            {
                "apis": ["hashlib.md5", "hashlib.sha1", "hashlib.sha256",
                         "hashlib.sha512", "hashlib.sha384", "hashlib.sha224",
                         "hashlib.new", "hashlib.pbkdf2_hmac"],
                "pattern": r"hashlib\.(?:md5|sha1|sha256|sha512|sha384|sha224|new|pbkdf2_hmac)\s*\(",
                "import_pattern": r"(?:import\s+hashlib|from\s+hashlib\s+import)",
                "sources": [
                    "CodeQL py/weak-cryptographic-algorithm",
                    "Bandit B303 (md5)",
                    "Bandit B324 (hashlib)",
                ],
            },
            {
                "apis": ["hmac.new", "hmac.compare_digest"],
                "pattern": r"hmac\.(?:new|compare_digest)\s*\(",
                "import_pattern": r"(?:import\s+hmac|from\s+hmac\s+import)",
                "sources": [
                    "CodeQL py/weak-cryptographic-algorithm",
                ],
            },
            {
                "apis": ["Crypto.Cipher.AES", "Crypto.Cipher.DES",
                         "Crypto.PublicKey.RSA", "Crypto.Hash",
                         "Crypto.Signature", "Crypto.Random"],
                "pattern": r"(?:Crypto|Cryptodome)\.(?:Cipher|PublicKey|Hash|Signature|Random)",
                "import_pattern": r"(?:from\s+(?:Crypto|Cryptodome)\s+import|import\s+(?:Crypto|Cryptodome))",
                "sources": [
                    "Bandit B413 (import_pycrypto)",
                    "CodeQL py/weak-cryptographic-algorithm",
                ],
            },
            {
                "apis": ["cryptography.fernet.Fernet", "cryptography.hazmat"],
                "pattern": r"(?:Fernet|cryptography\.hazmat|cryptography\.fernet)",
                "import_pattern": r"(?:from\s+cryptography\s+import|import\s+cryptography|from\s+cryptography\.fernet\s+import|from\s+cryptography\.hazmat\s+import)",
                "sources": [
                    "CodeQL py/weak-cryptographic-algorithm",
                ],
            },
            {
                "apis": ["ssl.wrap_socket", "ssl.create_default_context",
                         "ssl.SSLContext"],
                "pattern": r"ssl\.(?:wrap_socket|create_default_context|SSLContext)\s*\(",
                "import_pattern": r"(?:import\s+ssl|from\s+ssl\s+import)",
                "sources": [
                    "Bandit B502 (ssl_with_bad_version)",
                    "Bandit B504 (ssl_with_no_version)",
                    "CodeQL py/insecure-protocol",
                ],
            },
            {
                "apis": ["bcrypt.hashpw", "bcrypt.checkpw", "bcrypt.gensalt"],
                "pattern": r"bcrypt\.(?:hashpw|checkpw|gensalt)\s*\(",
                "import_pattern": r"(?:import\s+bcrypt|from\s+bcrypt\s+import)",
                "sources": [
                    "Semgrep python.cryptography.bcrypt",
                ],
            },
            {
                "apis": ["secrets.token_hex", "secrets.token_bytes",
                         "secrets.token_urlsafe", "secrets.choice"],
                "pattern": r"secrets\.(?:token_hex|token_bytes|token_urlsafe|choice)\s*\(",
                "import_pattern": r"(?:import\s+secrets|from\s+secrets\s+import)",
                "sources": [
                    "Semgrep python.cryptography.secure-random",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["crypto.createHash", "crypto.createHmac",
                         "crypto.createCipher", "crypto.createCipheriv",
                         "crypto.createDecipher", "crypto.createDecipheriv",
                         "crypto.createSign", "crypto.createVerify",
                         "crypto.generateKeyPair", "crypto.randomBytes",
                         "crypto.scrypt", "crypto.pbkdf2"],
                "pattern": r"crypto\.(?:createHash|createHmac|createCipher|createCipheriv|createDecipher|createDecipheriv|createSign|createVerify|generateKeyPair|randomBytes|scrypt|pbkdf2)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:crypto|node:crypto)['\"]|from\s+['\"](?:crypto|node:crypto)['\"]|import\s+.*['\"](?:crypto|node:crypto)['\"])",
                "sources": [
                    "CodeQL js/weak-cryptographic-algorithm",
                    "Semgrep javascript.crypto.security.audit",
                ],
            },
            {
                "apis": ["bcrypt.hash", "bcrypt.compare", "bcrypt.genSalt"],
                "pattern": r"bcrypt\.(?:hash|compare|genSalt|hashSync|compareSync)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:bcrypt|bcryptjs)['\"]|from\s+['\"](?:bcrypt|bcryptjs)['\"])",
                "sources": [
                    "Semgrep javascript.cryptography.bcrypt",
                ],
            },
            {
                "apis": ["Math.random"],
                "pattern": r"Math\.random\s*\(",
                "import_pattern": None,
                "sources": [
                    "CodeQL js/insecure-randomness",
                    "Semgrep javascript.lang.security.audit.math-random",
                ],
            },
        ],
        "javascript": None,
    },

    "DESERIALIZATION": {
        "cwes": ["CWE-502", "CWE-611", "CWE-776"],
        "cwe_names": {
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
            "CWE-776": "Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)",
        },
        "python": [
            {
                "apis": ["pickle.load", "pickle.loads", "pickle.Unpickler"],
                "pattern": r"pickle\.(?:load|loads|Unpickler)\s*\(",
                "import_pattern": r"(?:import\s+pickle|from\s+pickle\s+import)",
                "sources": [
                    "CodeQL py/unsafe-deserialization",
                    "Bandit B301 (pickle)",
                    "Bandit B302 (marshal)",
                    "Semgrep python.lang.security.deserialization.avoid-pickle",
                ],
            },
            {
                "apis": ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
                "pattern": r"yaml\.(?:load|unsafe_load|full_load)\s*\(",
                "import_pattern": r"(?:import\s+yaml|from\s+yaml\s+import)",
                "sources": [
                    "CodeQL py/unsafe-deserialization",
                    "Bandit B506 (yaml_load)",
                    "Semgrep python.lang.security.deserialization.avoid-pyyaml-load",
                ],
            },
            {
                "apis": ["marshal.load", "marshal.loads"],
                "pattern": r"marshal\.(?:load|loads)\s*\(",
                "import_pattern": r"(?:import\s+marshal|from\s+marshal\s+import)",
                "sources": [
                    "Bandit B302 (marshal)",
                ],
            },
            {
                "apis": ["shelve.open"],
                "pattern": r"shelve\.open\s*\(",
                "import_pattern": r"(?:import\s+shelve|from\s+shelve\s+import)",
                "sources": [
                    "Bandit B302 (shelve)",
                ],
            },
            {
                "apis": ["xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
                         "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
                         "xml.sax.parse", "xml.sax.parseString"],
                "pattern": r"(?:ElementTree|minidom|xml\.sax)\.(?:parse|parseString|fromstring|iterparse)\s*\(",
                "import_pattern": r"(?:import\s+xml|from\s+xml\s+import|from\s+xml\.etree\s+import|from\s+xml\.dom\s+import|from\s+xml\.sax\s+import)",
                "sources": [
                    "Bandit B313 (xml_bad_cElementTree)",
                    "Bandit B314 (xml_bad_ElementTree)",
                    "Bandit B315 (xml_bad_expatreader)",
                    "Bandit B316 (xml_bad_expatbuilder)",
                    "Bandit B317 (xml_bad_sax)",
                    "Bandit B318 (xml_bad_minidom)",
                    "Bandit B319 (xml_bad_pulldom)",
                    "Bandit B320 (xml_bad_etree)",
                    "CodeQL py/xml-bomb",
                    "CodeQL py/xxe",
                ],
            },
            {
                "apis": ["jsonpickle.decode", "jsonpickle.loads"],
                "pattern": r"jsonpickle\.(?:decode|loads)\s*\(",
                "import_pattern": r"(?:import\s+jsonpickle|from\s+jsonpickle\s+import)",
                "sources": [
                    "Semgrep python.lang.security.deserialization.avoid-jsonpickle",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["yaml.load", "yaml.loadAll"],
                "pattern": r"(?:yaml|YAML)\.(?:load|loadAll|safeLoad)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:js-yaml|yaml)['\"]|from\s+['\"](?:js-yaml|yaml)['\"])",
                "sources": [
                    "CodeQL js/unsafe-deserialization",
                    "Semgrep javascript.lang.security.audit.unsafe-yaml-load",
                ],
            },
            {
                "apis": ["xml2js.parseString", "xml2js.Parser"],
                "pattern": r"(?:xml2js\.parseString|Parser)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]xml2js['\"]|from\s+['\"]xml2js['\"])",
                "sources": [
                    "CodeQL js/xxe",
                ],
            },
            {
                "apis": ["serialize", "node-serialize"],
                "pattern": r"(?:serialize|unserialize)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:node-serialize|serialize-javascript)['\"]|from\s+['\"](?:node-serialize|serialize-javascript)['\"])",
                "sources": [
                    "CodeQL js/unsafe-deserialization",
                    "Semgrep javascript.lang.security.audit.node-serialize",
                ],
            },
        ],
        "javascript": None,
    },

    "AUTH": {
        "cwes": ["CWE-287", "CWE-306", "CWE-384", "CWE-614", "CWE-916"],
        "cwe_names": {
            "CWE-287": "Improper Authentication",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-384": "Session Fixation",
            "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
        },
        "python": [
            {
                "apis": ["jwt.encode", "jwt.decode"],
                "pattern": r"jwt\.(?:encode|decode)\s*\(",
                "import_pattern": r"(?:import\s+jwt|from\s+jwt\s+import|import\s+jose|from\s+jose\s+import)",
                "sources": [
                    "CodeQL py/jwt-missing-algorithm",
                    "Semgrep python.jwt.security.audit",
                ],
            },
            {
                "apis": ["flask_login.login_user", "flask_login.logout_user",
                         "flask_login.current_user", "flask_login.login_required"],
                "pattern": r"(?:flask_login\.|login_user|logout_user|current_user|login_required|LoginManager)\s*[\(\.]",
                "import_pattern": r"(?:import\s+flask_login|from\s+flask_login\s+import)",
                "sources": [
                    "Semgrep python.flask.security.audit.session",
                ],
            },
            {
                "apis": ["django.contrib.auth.authenticate",
                         "django.contrib.auth.login",
                         "django.contrib.auth.logout"],
                "pattern": r"(?:authenticate|login|logout|login_required|permission_required)\s*\(",
                "import_pattern": r"from\s+django\.contrib\.auth\s+import",
                "sources": [
                    "Semgrep python.django.security.audit.authentication",
                ],
            },
            {
                "apis": ["passlib.hash", "passlib.context.CryptContext"],
                "pattern": r"(?:passlib\.hash|CryptContext)\s*[\.\(]",
                "import_pattern": r"(?:import\s+passlib|from\s+passlib\s+import|from\s+passlib\.hash\s+import|from\s+passlib\.context\s+import)",
                "sources": [
                    "Semgrep python.cryptography.password-hashing",
                ],
            },
            {
                "apis": ["oauth2client", "authlib", "oauthlib"],
                "pattern": r"(?:OAuth\w*|oauth|AuthorizationCode|ClientCredentials)\s*\(",
                "import_pattern": r"(?:import\s+(?:oauth2client|authlib|oauthlib)|from\s+(?:oauth2client|authlib|oauthlib)\s+import)",
                "sources": [
                    "Semgrep python.oauth.security.audit",
                ],
            },
        ],
        "typescript": [
            {
                "apis": ["jsonwebtoken.sign", "jsonwebtoken.verify",
                         "jsonwebtoken.decode", "jwt.sign", "jwt.verify"],
                "pattern": r"(?:jwt|jsonwebtoken)\.(?:sign|verify|decode)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]jsonwebtoken['\"]|from\s+['\"]jsonwebtoken['\"]|import\s+.*['\"]jsonwebtoken['\"])",
                "sources": [
                    "CodeQL js/jwt-missing-algorithm",
                    "Semgrep javascript.jsonwebtoken.security.audit",
                ],
            },
            {
                "apis": ["passport.authenticate", "passport.use",
                         "passport.initialize", "passport.session"],
                "pattern": r"passport\.(?:authenticate|use|initialize|session|serializeUser|deserializeUser)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"]passport['\"]|from\s+['\"]passport['\"]|import\s+.*['\"]passport['\"])",
                "sources": [
                    "Semgrep javascript.passport.security.audit",
                ],
            },
            {
                "apis": ["express-session", "cookie-session"],
                "pattern": r"(?:session|cookieSession)\s*\(",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:express-session|cookie-session)['\"]|from\s+['\"](?:express-session|cookie-session)['\"])",
                "sources": [
                    "CodeQL js/insecure-cookie",
                    "Semgrep javascript.express.security.audit.session",
                ],
            },
            {
                "apis": ["oauth", "openid-client"],
                "pattern": r"(?:OAuth2Client|OpenIdClient|Issuer|generators)\s*[\.\(]",
                "import_pattern": r"(?:require\s*\(\s*['\"](?:simple-oauth2|openid-client|oauth)['\"]|from\s+['\"](?:simple-oauth2|openid-client|oauth)['\"])",
                "sources": [
                    "Semgrep javascript.oauth.security.audit",
                ],
            },
        ],
        "javascript": None,
    },
}

# For properties with javascript=None, use the typescript patterns
for prop in SECURITY_OPERATIONS:
    if SECURITY_OPERATIONS[prop].get("javascript") is None:
        SECURITY_OPERATIONS[prop]["javascript"] = SECURITY_OPERATIONS[prop].get("typescript", [])


# =========================================================================
# Derived Keywords for Description Analysis
#
# METHODOLOGY: Keywords are extracted PROGRAMMATICALLY by
# fetch_and_build_sources.py from the verbatim text of:
#   1. CWE descriptions from MITRE (https://cwe.mitre.org/data/xml/)
#   2. CodeQL query metadata (github/codeql repository)
#   3. Semgrep rule descriptions (semgrep/semgrep-rules repository)
#   4. Bandit check descriptions (PyCQA/bandit repository)
#
# The script tokenizes source descriptions, removes stop words, scores
# terms by TF-IDF (term frequency - inverse property frequency), and
# keeps the most distinctive terms per property. Every keyword has a
# source citation recording which source document contains it verbatim.
#
# To regenerate:
#   python3 scripts/fetch_and_build_sources.py
#
# Output: data/derived_keywords.json, data/reference_texts.json
# =========================================================================

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_derived_keywords():
    """Load programmatically generated keywords from JSON."""
    path = _DATA_DIR / "derived_keywords.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    else:
        print(f"WARNING: {path} not found.")
        print("  Run: python3 scripts/fetch_and_build_sources.py")
        return {}


def _load_reference_texts():
    """Load programmatically generated reference texts from JSON."""
    path = _DATA_DIR / "reference_texts.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    else:
        print(f"WARNING: {path} not found.")
        print("  Run: python3 scripts/fetch_and_build_sources.py")
        return {}


DERIVED_KEYWORDS = _load_derived_keywords()

# =========================================================================
# Reference texts for similarity-based techniques (TF-IDF, embeddings)
#
# Built by concatenating verbatim CWE descriptions, CodeQL query
# descriptions, Semgrep rule messages, and Bandit check docstrings
# for each security property. Generated by fetch_and_build_sources.py.
# =========================================================================

PROPERTY_REFERENCE_TEXTS = _load_reference_texts()


def get_keyword_set(property_name):
    """Get the set of keywords for a property (just the keyword strings)."""
    entry = DERIVED_KEYWORDS.get(property_name, {})
    return set(entry.get("keywords", {}).keys())


def get_all_keyword_sources():
    """Get a full report of all keywords and their sources."""
    report = {}
    for prop in SECURITY_PROPERTIES:
        entry = DERIVED_KEYWORDS.get(prop, {})
        report[prop] = entry.get("keywords", {})
    return report


def get_operations_for_language(property_name, language):
    """Get the operation patterns for a specific property and language."""
    prop_data = SECURITY_OPERATIONS.get(property_name, {})
    return prop_data.get(language, [])


def get_all_cwes():
    """Get all CWEs covered by this registry."""
    cwes = {}
    for prop, data in SECURITY_OPERATIONS.items():
        for cwe_id, cwe_name in data.get("cwe_names", {}).items():
            cwes[cwe_id] = {"name": cwe_name, "property": prop}
    return cwes


def generate_registry_report():
    """Generate a human-readable report of the registry contents."""
    lines = []
    lines.append("=" * 80)
    lines.append("TRUSTED SECURITY OPERATIONS REGISTRY")
    lines.append("=" * 80)

    total_ops = 0
    total_kw = 0

    for prop in SECURITY_PROPERTIES:
        prop_data = SECURITY_OPERATIONS.get(prop, {})
        kw_data = DERIVED_KEYWORDS.get(prop, {})

        lines.append(f"\n{'─' * 80}")
        lines.append(f"Property: {prop} (Risk: {PROPERTY_RISK[prop]})")
        lines.append(f"{'─' * 80}")

        # CWEs
        for cwe_id, cwe_name in prop_data.get("cwe_names", {}).items():
            lines.append(f"  CWE: {cwe_id} - {cwe_name}")

        # Operations by language
        for lang in ["python", "typescript", "javascript"]:
            ops = prop_data.get(lang, [])
            if not ops:
                continue
            lines.append(f"\n  {lang.upper()} Operations:")
            for op in ops:
                total_ops += len(op["apis"])
                apis_str = ", ".join(op["apis"][:5])
                if len(op["apis"]) > 5:
                    apis_str += f" (+{len(op['apis'])-5} more)"
                lines.append(f"    APIs: {apis_str}")
                for src in op["sources"]:
                    lines.append(f"      Source: {src}")

        # Keywords
        kws = kw_data.get("keywords", {})
        total_kw += len(kws)
        lines.append(f"\n  Derived Keywords ({len(kws)}):")
        for kw, source in sorted(kws.items()):
            lines.append(f"    \"{kw}\" <- {source}")

    lines.append(f"\n{'=' * 80}")
    lines.append(f"TOTALS: {total_ops} API patterns, {total_kw} keywords")
    lines.append(f"Properties: {len(SECURITY_PROPERTIES)}")
    lines.append(f"CWEs covered: {len(get_all_cwes())}")
    lines.append(f"Trusted sources: CodeQL, Semgrep, Bandit, MITRE CWE")
    lines.append(f"{'=' * 80}")

    return "\n".join(lines)


if __name__ == "__main__":
    print(generate_registry_report())
