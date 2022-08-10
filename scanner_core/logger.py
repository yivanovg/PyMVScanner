"""Class which sets a custom logger formatter to be used"""
"""City Unviersity Project"""
#imports
import logging
from datetime import datetime

#function for custom logger formatting
def getLogger():

    #check code for reuse
    
    loggerCustom = logging.getLogger('PYVMScanner')
    
    if not loggerCustom.handlers:

        loggerCustom.propagate = 0

        streamHandler = logging.StreamHandler()
        loggerCustom.addHandler(streamHandler)

        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s', '%Y-%m-%d %H:%M:%S')
        streamHandler.setFormatter(formatter)

    return loggerCustom

