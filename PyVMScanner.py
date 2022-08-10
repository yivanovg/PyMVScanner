"""City Unviersity Project"""
from scanner_cli import cliCore, cliParser, cliConfig
from scanner_core import adminPanel, portScan, utilities, headers_check, dirBuster, crawlerURLs, sqlScan
from warnings import filterwarnings as fwarning

fwarning(action='ignore')


if __name__ == '__main__':
    
    print(f"{cliConfig.OKBLUE}{cliConfig.banner}{cliConfig.OKGREEN}")
    print('Python Web Application Vulnerability Scanner\n')
    #cliParser.cli()
    #pvmCore.checkAdmin()
    #pvmCore.checkRobots('http://hackthissite.org')
    #headers_check.check_ssl()
    #dirBuster.main(True, '127.0.0.1/DVWA-Master')
    #crawlerURLs.start_crawl('http://127.0.0.1', 1)
    #headers_check.check_headers('
    # http://127.0.0.1/DVWA-Master/index.php')
    portScan.portSettings('127.0.0.1', '80-500', True)
    #print(utilities.readWordlist('smallAdmin.txt')[1][0])
    #sqlScan.startSQL('http://testphp.vulnweb.com/artists.php')
    #sqlScan.startSQL('http://127.0.0.1/DVWA-Master/vulnerabilities/sqli')
    #headers_check.cookie_check('https://owasp.org/www-community/HttpOnly')
    #adminPanel.startAdminScan('127.0.0.1/DVWA-Master')
    
