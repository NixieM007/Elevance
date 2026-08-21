import pandas as pd
import numpy as np
import pandas.io.sql
import pyodbc
import xlrd
import openpyxl
import datetime
import sys
import string
import arrow

# BOTH ESRD AND MSP MUST BE RUN IN THE SAME SCRIPT. COPY AND PASTE BOTH MEDICARE NUMBERS IN BEFORE RUN
# CHANGE FILENAME MONTH NUMBER

strValidationDate = datetime.datetime.now().strftime("%d%b%Y").upper()

#from openpyxl import load_workbook
strfilename     = "F:\Vendors\Seidel\Files Jan 2023\JHHC WC RETRACT 6-2023.xlsx"
sourcefile      = openpyxl.load_workbook(filename=strfilename)
strfilemmyyyy   = strfilename[112:-5]
strfilemm       = strfilename[112:-9]
strfileyyyy     = strfilename[114:-5]
strfiledate     = strfileyyyy + strfilemm + '01'
strnowdated     = arrow.now().format('YYYYMMDD')

strVendorName   = "Seidel" 


print(strnowdated, strVendorName, )