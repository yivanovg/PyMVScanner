"""City Unviersity Project"""
from scanner_cli import cliCore, cliParser, cliConfig
from scanner_core import adminPanel, portScan, utilities, headers_check, dirBuster, crawlerURLs, sqlScan
from warnings import filterwarnings as fwarning

fwarning(action='ignore')


if __name__ == '__main__':
    
    print(f"{cliConfig.OKBLUE}{cliConfig.banner}{cliConfig.OKGREEN}")
    print('Python Web Application Vulnerability Scanner\n')
    cliParser.cli()
 
    
