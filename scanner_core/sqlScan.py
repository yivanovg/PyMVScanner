"""Class for scanning an website sql vulnerabilities"""
"""City Unviersity Project"""
from datetime import datetime
import re
from urllib.parse import urljoin, urlparse
from requests import get, Session, head, post, request, exceptions
from warnings import filterwarnings as fwarning
from scanner_core import logger, crawlerURLs, DVWALogin
import logging
from scanner_cli import cliParser

#Load custom formatted logger class
myLogger = logger.getLogger()
myLogger.setLevel(logging.DEBUG)

#ignore warnings
fwarning(action='ignore')

#SQL error messages source https://github.com/sqlmapproject/sqlmap/blob/master/data/xml/errors.xml
DBMS_ERROR_PATTERNS = {
        "MySQL": [
            re.compile(r"SQL syntax.*?MySQL"),
            re.compile(r"Warning.*?\Wmysqli?_"),
            re.compile(r"MySQLSyntaxErrorException"),
            re.compile(r"valid MySQL result"),
            re.compile(r"check the manual that (corresponds to|fits) your MySQL server version"),
            re.compile(r"Unknown column '[^ ]+' in 'field list'"),
            re.compile(r"MySqlClient\."),
            re.compile(r"com\.mysql\.jdbc"),
            re.compile(r"Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
            re.compile(r"Pdo[./_\\]Mysql"),
            re.compile(r"MySqlException"),
            re.compile(r"you have an error in your SQL syntax;"),
            re.compile(r"SQLSTATE\[\d+\]: Syntax error or access violation")
        ],
        "MariaDB": [
            re.compile(r"check the manual that (corresponds to|fits) your MariaDB server version"),

        ],
        "Drizzle": [
            re.compile(r"check the manual that (corresponds to|fits) your Drizzle server version")
        ],
        "MemSQL": [
            re.compile(r"MemSQL does not support this type of query"),
            re.compile(r"is not supported by MemSQL"),
            re.compile(r"unsupported nested scalar subselect")
        ],
        "PostgreSQL": [
            re.compile(r"PostgreSQL.*?ERROR"),
            re.compile(r"Warning.*?\Wpg_"),
            re.compile(r"valid PostgreSQL result"),
            re.compile(r"Npgsql\."),
            re.compile(r"PG::SyntaxError:"),
            re.compile(r"org\.postgresql\.util\.PSQLException"),
            re.compile(r"ERROR:\s\ssyntax error at or near"),
            re.compile(r"ERROR: parser: parse error at or near"),
            re.compile(r"PostgreSQL query failed"),
            re.compile(r"org\.postgresql\.jdbc"),
            re.compile(r"Pdo[./_\\]Pgsql"),
            re.compile(r"PSQLException"),
        ],
        "Microsoft SQL Server": [
            re.compile(r"Driver.*? SQL[\-\_\ ]*Server"),
            re.compile(r"OLE DB.*? SQL Server"),
            re.compile(r"\bSQL Server[^&lt;&quot;]+Driver"),
            re.compile(r"Warning.*?\W(mssql|sqlsrv)_"),
            re.compile(r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"),
            re.compile(r"System\.Data\.SqlClient\.SqlException"),
            re.compile(r"(?s)Exception.*?\bRoadhouse\.Cms\."),
            re.compile(r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}"),
            re.compile(r"\[SQL Server\]"),
            re.compile(r"ODBC SQL Server Driver"),
            re.compile(r"ODBC Driver \d+ for SQL Server"),
            re.compile(r"SQLServer JDBC Driver"),
            re.compile(r"com\.jnetdirect\.jsql"),
            re.compile(r"macromedia\.jdbc\.sqlserver"),
            re.compile(r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"),
            re.compile(r"com\.microsoft\.sqlserver\.jdbc"),
            re.compile(r"Pdo[./_\\](Mssql|SqlSrv)"),
            re.compile(r"SQL(Srv|Server)Exception"),
             re.compile(r"unclosed quotation mark after the character string"),
        ],
        "Microsoft Access": [
            re.compile(r"Microsoft Access (\d+ )?Driver"),
            re.compile(r"JET Database Engine"),
            re.compile(r"Access Database Engine"),
            re.compile(r"ODBC Microsoft Access"),
            re.compile(r"Syntax error \(missing operator\) in query expression"),
        ],
        "Oracle": [
            re.compile(r"\bORA-\d{5}"),
            re.compile(r"Oracle error"),
            re.compile(r"Oracle.*?Driver"),
            re.compile(r"Warning.*?\W(oci|ora)_"),
            re.compile(r"quoted string not properly terminated"),
            re.compile(r"SQL command not properly ended"),
            re.compile(r"macromedia\.jdbc\.oracle"),
            re.compile(r"oracle\.jdbc"),
            re.compile(r"Zend_Db_(Adapter|Statement)_Oracle_Exception"),
            re.compile(r"Pdo[./_\\](Oracle|OCI)"),
            re.compile(r"OracleException"),
        ],
        "IBM DB2": [
            re.compile(r"CLI Driver.*?DB2"),
            re.compile(r"DB2 SQL error"),
            re.compile(r"\bdb2_\w+\("),
            re.compile(r"SQLCODE[=:\d, -]+SQLSTATE"),
            re.compile(r"com\.ibm\.db2\.jcc"),
            re.compile(r"Zend_Db_(Adapter|Statement)_Db2_Exception"),
            re.compile(r"Pdo[./_\\]Ibm"),
            re.compile(r"DB2Exception"),
            re.compile(r"ibm_db_dbi\.ProgrammingError"),
        ],
        "Informix": [
            re.compile(r"Warning.*?\Wifx_"),
            re.compile(r"Exception.*?Informix"),
            re.compile(r"Informix ODBC Driver"),
            re.compile(r"ODBC Informix driver"),
            re.compile(r"com\.informix\.jdbc"),
            re.compile(r"weblogic\.jdbc\.informix"),
            re.compile(r"Pdo[./_\\]Informix"),
            re.compile(r"IfxException"),
        ],
        "Firebird": [
            re.compile(r"Dynamic SQL Error"),
            re.compile(r"Warning.*?\Wibase_"),
            re.compile(r"org\.firebirdsql\.jdbc"),
            re.compile(r"Pdo[./_\\]Firebird"),

        ],
        "SQLite": [
            re.compile(r"SQLite/JDBCDriver"),
            re.compile(r"SQLite\.Exception"),
            re.compile(r"(Microsoft|System)\.Data\.SQLite\.SQLiteException"),
            re.compile(r"Warning.*?\W(sqlite_|SQLite3::)"),
            re.compile(r"\[SQLITE_ERROR\]"),
            re.compile(r"SQLite error \d+:"),
            re.compile(r"sqlite3.OperationalError:"),
            re.compile(r"SQLite3::SQLException"),
            re.compile(r"org\.sqlite\.JDBC"),
            re.compile(r"Pdo[./_\\]Sqlite"),
            re.compile(r"SQLiteException"),
        ],
        "SAP MaxDB": [
            re.compile(r"SQL error.*?POS([0-9]+)"),
            re.compile(r"Warning.*?\Wmaxdb_"),
            re.compile(r"DriverSapDB"),
            re.compile(r"-3014.*?Invalid end of SQL statement"),
            re.compile(r"com\.sap\.dbtech\.jdbc"),
            re.compile(r"\[-3008\].*?: Invalid keyword or missing delimiter"),
        ],
        "Sybase": [
            re.compile(r"Warning.*?\Wsybase_"),
            re.compile(r"Sybase message"),
            re.compile(r"Sybase.*?Server message"),
            re.compile(r"SybSQLException"),
            re.compile(r"Sybase\.Data\.AseClient"),
            re.compile(r"com\.sybase\.jdbc"),
        ],
        "Ingres": [
            re.compile(r"Warning.*?\Wingres_"),
            re.compile(r"Ingres SQLSTATE"),
            re.compile(r"Ingres\W.*?Driver"),
            re.compile(r"com\.ingres\.gcf\.jdbc"),
        ],
        "FrontBase": [
            re.compile(r"Exception (condition )?\d+\. Transaction rollback"),
            re.compile(r"com\.frontbase\.jdbc"),
            re.compile(r"Syntax error 1. Missing"),
            re.compile(r"(Semantic|Syntax) error [1-4]\d{2}\."),
        ],
        "HSQLDB": [
            re.compile(r"Unexpected end of command in statement \["),
            re.compile(r"Unexpected token.*?in statement \["),
            re.compile(r"org\.hsqldb\.jdbc"),
        ],
        "H2": [
            re.compile(r"org\.h2\.jdbc"),
            re.compile(r"\[42000-192\]"),
        ],
        "MonetDB": [
            re.compile(r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)"),
            re.compile(r"\[MonetDB\]\[ODBC Driver"),
            re.compile(r"nl\.cwi\.monetdb\.jdbc"),
        ],
        "Apache Derby": [
            re.compile(r"Syntax error: Encountered"),
            re.compile(r"org\.apache\.derby"),
            re.compile(r"ERROR 42X01"),
        ],
        "Vertica": [
            re.compile(r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):"),
            re.compile(r"/vertica/Parser/scan"),
            re.compile(r"com\.vertica\.jdbc"),
            re.compile(r"org\.jkiss\.dbeaver\.ext\.vertica"),
            re.compile(r"com\.vertica\.dsi\.dataengine"),
        ],
        "Mckoi": [
            re.compile(r"com\.mckoi\.JDBCDriver"),
            re.compile(r"com\.mckoi\.database\.jdbc"),
            re.compile(r"&lt;REGEX_LITERAL&gt;"),
        ],
        "Presto": [
            re.compile(r"com\.facebook\.presto\.jdbc"),
            re.compile(r"io\.prestosql\.jdbc"),
            re.compile(r"com\.simba\.presto\.jdbc"),
            re.compile(r"UNION query has different number of fields: \d+, \d+"),
        ],
        "Altibase": [
            re.compile(r"Altibase\.jdbc\.driver")
        ],
        "MimerSQL": [
            re.compile(r"com\.mimer\.jdbc"),
            re.compile(r"Syntax error,[^\n]+assumed to mean"),
        ],
        "CrateDB": [
            re.compile(r"io\.crate\.client\.jdbc"),
        ],
        "Cache": [
            re.compile(r"encountered after end of query"),
            re.compile(r"A comparison operator is required here"),
        ]
    }

text_errors = list()

#function for checking if a web response is vulnerable
def sql_vulnerable(data, payload):
    
    #var init
    found = False
    
    data = data.content.decode()
    
    #check the response text agains the error code from the list
    for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
        for regex in regex_list:
            
            if regex.search(data):
                
                found = True
                print(f"PVMCSCANNER: SQL Injection vulnerability detected: {('SQL Injection')} (DMBS: {dbms}) (Payload: {payload})\n")
                text_errors.append(f"PVMCSCANNER: SQL Injection vulnerability detected: {('SQL Injection')} (DMBS: {dbms}) (Payload: {payload})")
                return True
    
    #additional error checks for errors not in list 
    if "XPathException" in data:
        
            found = True     
            print("XPath Injection\n")
            text_errors.append("XPath Injection\n")
            return True
        
    if "Warning: SimpleXMLElement::xpath():" in data:
        
            found = True
            print("XPath Injection\n")
            text_errors.append("XPath Injection\n")
            return True
        
    if "supplied arument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
            
            found = True
            print("LDAP Injection")
            text_errors.append("LDAP Injection")
            return True
        
    if found == False:
        
        myLogger.info('Vulnerability Not Found!\n')
    
    
#scan a link for sql vulnerabilities
def scan_sql(url, fsave, onlyLink=False):
    
    url_check_parameters = ('\'', '\"', "%27")
    
    #check if there is error in the url by modifying the url parameters
    for custom in url_check_parameters:
        
        custom_url = f"{url}{custom}"
        
        print("PVMCSCANNER: Trying", custom_url)
        try:
            connURL = get(custom_url, verify=False)
            
        except exceptions.ConnectionError as e:
            ('Please check URL for syntax error!')
            exit(e)
            
        if sql_vulnerable(connURL, custom):
           
           continue
    if onlyLink == False:
        #find the forms
        forms = crawlerURLs.find_forms(url)     
        #print(forms['inputs'])
        
        for stringSQL in '\'"':
            payload = {}
            
            #create the payload for the input fields
            
            for input in forms['inputs']:
                if input["type"] == "hidden" or input["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            payload[input["name"]] = input["value"]
                            #print(payload)
                        except:
                            pass
                        
                elif input["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        payload[input["name"]] = f"{stringSQL}"
                        
            #join the url with the action (form request URL)
            url = urljoin(url, forms["action"])
            
            #setup the connection and payload data to be sent to the server
            conn = DVWALogin.loginDVWA()
            
            conn.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
            
            if forms["method"] == "post":
                    res = conn.post(url, data=payload)
                    
            elif forms["method"] == "get":
                    res = conn.get(url, params=payload)
            
            #for each response of each payload check if it is vulnerable and output the result
            if sql_vulnerable(res, payload):
                
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print(f"[+] Form: {forms}")
                    text_errors.append(f'Form: {forms}')
                    conn.close()
                    break     
                    
        conn.close()
    
    #save file if filesave is true
    if fsave == True:
        try:   
            with open('scanner_core\\data\\vulnerableSQL.txt', 'a') as file:
                
                    if 'vulnerability detected:' in str(text_errors):
                        
                        formatted = str(text_errors).replace(',', '\n')
                        file.writelines('\n' + str(formatted))
                        file.write('\n')
                        
                    else:
                        #file.write('\n'+str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
                        file.write('\n')
                        file.write(str(text_errors[0])+ ' ' + str(text_errors[1]))
                        file.write('\n')
                        file.write('No SQL Vulnerabilities')
                        file.write('\n')
                        
        except OSError:
                myLogger.info('Could not open/read file!!!')

#main function starting the scan           
def startSQL(url,fsave=False, onlyLink=False):
    
    dateTimeObj = datetime.now()
    text_errors.append(str(dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S)")))
    text_errors.append(f'PVMSCANNER SQL URL: {url}')
    
    #url validation
    if urlparse(url).scheme == '':
        print('Enter valid URL Scheme: HTTP:// OR HTTPS://')
        exit()
        
    scan_sql(url, fsave, onlyLink)
    
    
    