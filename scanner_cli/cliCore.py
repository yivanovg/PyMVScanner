"""City Unviersity Project"""
#imports
from scanner_cli import cliConfig, cliParser
from scanner_core import logger

import re
import os

#class used for the cli menu which was decided not to be used because of design and use interaction problems
clear = lambda: os.system('cls')

def mainCli():
    print(cliConfig.banner)

    for option in cliConfig.options:
        print(option)

    #user choice of attack
    choice = input("\nPlease enter a number from the menu on top: ")
    while choice.isnumeric() == False:
        choice =input('\nPlease enter a number from the menu !: ')

    while int(choice) > 10 or int(choice) == 0:
          choice =input('\nPlease enter a number from the menu !: ') 
  
    #attack specific menus
    for option in cliConfig.options:

        option_number = re.search(r'\d+', option).group()

        if int(choice) == int(option_number):
            if int(option_number) == 1:
                clear()
                print(cliConfig.banner)
                print(cliConfig.lookup_address_option)
                cliParser.reverseURL()
                

            if int(option_number) == 2:
                clear()
                print(cliConfig.banner)
                print(cliConfig.lookup_ip_option)
                cliParser.reverseIP()
               
            if int(option_number) == 3:
                clear()
                print(cliConfig.banner)
                print(cliConfig.portscan_info[0])
                cliParser.reverseURL()

            if int(option_number) == 4:
                cliParser.cli()
                print('false')
               #exit()

            if int(option_number) == 5:
                exit()

            if int(option_number) == 6:
                exit()

            if int(option_number) == 7:
                exit()

            if int(option_number) == 8:
                exit()

            if int(option_number) == 9:
                exit()
                
            if int(option_number) == 10:
                exit()

#return to main page after attack
def returnToMenu(page):

    for option in cliConfig.scan_end:
        print(option)

    choice = input("\nPlease enter a number to proceed: ")

    if int(choice) == 1:
        mainCli()

    #For later add logic for going back to same page
    
   