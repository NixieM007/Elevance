

import warnings
import os
import re
import shutil
import threading
import time
import openpyxl  # Keep for verification report generation if needed
import psutil
import pythoncom
import pyxlsb
from tqdm import tqdm
from datetime import datetime, timedelta
from openpyxl import Workbook as OpenpyxlWorkbook  # Rename to avoid conflict
from openpyxl import load_workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
import logging
import sys
import pandas as pd
import pyodbc  # Explicitly imported though sqlalchemy uses it
from sqlalchemy import create_engine, text  # Import text for literal queries
import numpy as np
import requests
import pandas as pd
from io import BytesIO
import xlwings as xw
import win32com.client

def convert_xlsb_to_xlsx(xlsb_path, xlsx_path):
    # Suppress all non-critical messages globally
    logging.basicConfig(level=logging.CRITICAL)
    # Open the binary workbook using Excel
    app = xw.App(visible=False)
    try:
        wb = xw.Book(xlsb_path)
        wb.app.DisplayAlerts = False
        if os.path.exists(infilexlsx): os.remove(infilexlsx)
        wb.api.SaveAs(infilexlsx, FileFormat=51)  # 51 corresponds to the .xlsx format in Excel
        wb.save(infilexlsx)
        wb.close()
       # print(f"Converted '{xlsb_path}' to '{xlsx_path}'")
    finally:
        app.quit()

# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning, module='openpyxl')
# Set logging level to ERROR to suppress INFO and DEBUG messages
logging.basicConfig(level=logging.ERROR)


# Calculate the current week's Monday date
today = datetime.today()
days_since_monday = today.weekday()  # Monday is 0
monday = today - timedelta(days=days_since_monday)
mondaystr = monday.strftime("%Y%m%d")
mondaystrsubject = monday.strftime("%m/%d/%Y")

sr=0
#mondaystr = '20250714'
infilexlsb = f"""Z:\\{mondaystr}\\KY_Pharmacy\\205497203-Baptist Health Medical Group_{mondaystr}.xlsb"""
infilexlsx = f"""C:\\Users\\AL10013\\Documents\\PEP Automation 5.0\\Reports\\205497203-Baptist Health Medical Group_{mondaystr}.xlsx""" 
filexlsx = f"""C:\\Users\\AL10013\\Documents\\PEP Automation 5.0\\Reports\\205497203-Baptist Health Medical Group_Processed_{mondaystr}.xlsx"""    # Output file 
filexlsb = f"""C:\\Users\\AL10013\\Documents\\PEP Automation 5.0\\Reports\\205497203-Baptist Health Medical Group_Processed_{mondaystr}.xlsb"""    # Output file 

sn1 = 'Unpivoted Table'  
sn2 = 'SUPD'
sn3 = 'Full Report'
sn4 = 'Member List'

colnamesFR = ['LAST_NM','FRST_NM', 'GENDER','ADDRESS', 'CITY', 'STATE', 'ZIPCODE', 'PHONE', 'HC_ID']  
colnamesML = ['Member ID', 'Non-Adherent in 2024?']
rename_dict = {'Last Name':'Last Name', 'LAST_NM': 'Last Name', 'First Name':'First Name', 'GENDER': 'Gender', 
               'ADDRESS':'Street', 'CITY':'City', 'STATE':'State', 'ZIPCODE':'Zip Code', 'Member ID': 'HC_ID',
               'Member Phone #': 'PHONE', 'Date of Birth':'DOB', 'Provider TIN':'Provider TIN', 'TIN Name': 'Provider TIN Name'}

colsins = ['Last Name', 'First Name', 'Gender', 'Street', 'City', 'State', 'Zip Code', 'Phone', 'HC_ID']
colsSU  = ['Last Name', 'First Name', 'Date of Birth', 'Member ID', 'Member Phone #', 'Provider Name', 'TIN Name']
colsFinal = ['Measure', 'Last Name', 'First Name',  'DOB', 'HC_ID', 'SNPTYPE', 'LIS_IND', 
                 'Gender','Street', 'City', 'State', 'Zip Code', 'Phone', 
                 'Pharmacy Name', 'Pharmacy Phone', 'Attributed Provider Last Name', 'Attributed Provider First Name', 
                 'Portion of Days Covered', 'Estimated/Projected Fail Date', 'Allowed Days Remaining', 'Drug Name', 
                 'Prescriber', 'Prescriber NPI', 'Drug Last Days Supply', 'Drug Last Fill Date', 'Drug Next Fill Date', 
                 'Drug Refills Remaining', 'Day Supply Benefit', 'Provider TIN', 'Provider TIN Name', 
                 'Provider NPI']
colsFinal3 = ['Measure', 'Last Name', 'First Name',  'DOB', 'HC_ID', 'SNPTYPE', 'LIS_IND', 
                 'Gender','Street', 'City', 'State', 'Zip Code', 'Phone', 
                 'Pharmacy Name', 'Pharmacy Phone', 'Attributed Provider Last Name', 'Attributed Provider First Name', 
                 'Portion of Days Covered', 'Estimated/Projected Fail Date', 'Allowed Days Remaining', 'Drug Name', 
                 'Prescriber', 'Prescriber NPI', 'Drug Last Days Supply', 'Drug Last Fill Date', 'Drug Next Fill Date', 
                 'Drug Refills Remaining', 'Day Supply Benefit', 'Provider TIN', 'Provider TIN Name', 
                 'Provider NPI', 'First Fill', 'Non-Adherent in 2024?',  'Prior Year Fail', 'SUPD_Result']

colsSUFinal = ['Last Name', 'First Name', 'DOB', 'Gender', 'Street', 'City', 'State', 'Zip Code', 'HC_ID', 'PHONE', 'Provider TIN', 'Provider TIN Name', '_merge']
colsSUFinal2 = ['Last Name', 'First Name', 'DOB', 'Gender','Street', 'City', 'State', 'Zip Code', 'HC_ID', 'Phone', 'Provider TIN', 'Provider TIN Name']
colsadd = ['First Fill', 'Non-Adherent in 2024?', 'Prior Year Fail']

# Usage
convert_xlsb_to_xlsx(infilexlsb, infilexlsx)

dfU  = pd.read_excel(infilexlsx, sheet_name=sn1)
dfSU = pd.read_excel(infilexlsx, sheet_name=sn2)
dfFR = pd.read_excel(infilexlsx, sheet_name=sn3, usecols = colnamesFR, skiprows=sr)
dfML = pd.read_excel(infilexlsx, sheet_name=sn4, usecols = colnamesML)

#--------------------------------------------------------------------SUPD ALL COLUMNS--------------------------------------------------------------------------

dfSUFR = pd.merge(dfSU, dfFR, left_on='Member ID', right_on='HC_ID', how='inner', indicator=True)
dfSUFR = dfSUFR.rename(columns=rename_dict)
dfSUFR = dfSUFR.drop_duplicates(subset=['HC_ID'])

# Verify ensure there are no duplicate somewhere, check and remove if exists
dfSUFR = dfSUFR.loc[:, ~dfSUFR.columns.duplicated()]
dfSUFR = dfSUFR[colsSUFinal]
dfSUFR['SUPD_Result'] = 'Y'

#---------------------------------------------------------------------NON-ADHERENT FLAG----------------------------------------------------------------

dfML0  = pd.merge(dfU, dfML, left_on='HC_ID', right_on='Member ID', how='inner')
# Create a new 'Flag' column and set it to 'Y'
dfML0['Prior Year Fail'] = 'Y'

# Use conditional logic to determine the comparison results
dfML0 = dfML0.dropna(subset=['Non-Adherent in 2024?'])

# Sele'ct only the 'HC_ID', 'Non-Adherent in 2024?' and 'Flag' column
dfML = dfML0[['HC_ID', 'Non-Adherent in 2024?', 'Prior Year Fail']]
dfML = dfML.drop_duplicates(subset=['HC_ID'])

#--------------------------------------------------------------------FIRST FILL FLAG---------------------------------------------------------------------


dfUFF = pd.merge(dfU, dfFR, left_on='HC_ID', right_on='HC_ID', how='inner')
# Use conditional logic to determine the comparison results
dfUFF['First Fill'] = np.where(dfUFF['Portion of Days Covered'] == 'FIRSTFILL', 'Y', 'N')
# Select only the 'HC_ID', 'Non-Adherent in 2024?' and 'Flag' columns
dfUFF = dfUFF[['HC_ID', 'First Fill']]
dfUFF = dfUFF.drop_duplicates(subset=['HC_ID'])

#----------------------Unpivoted Table Join to Full Report for additional columns needed to include GENDER-------------------------------

df_UTFR = pd.merge(dfU, dfFR, left_on='HC_ID', right_on='HC_ID', how='left')
df_UTFR = df_UTFR.rename(columns=rename_dict)
# Verify ensure there are no duplicate somewhere, check and remove if exists
df_UTFR = df_UTFR.loc[:, ~df_UTFR.columns.duplicated()]
# Use conditional logic to determine the comparison results
df_UTFR = df_UTFR[colsFinal]
df_UTFR = df_UTFR.drop_duplicates(subset=['HC_ID'])

#----------------------Unpivoted Table Full Report join to Member list Non-Adherent Flag--------------------------------------------------


df_UTFR_ML = pd.merge(df_UTFR, dfML, left_on='HC_ID', right_on='HC_ID', how='left')
if 'Prior Year Fail' in df_UTFR_ML.columns: df_UTFR_ML['Prior Year Fail'] = df_UTFR_ML['Prior Year Fail'].fillna('N')
df_UTFR_ML   = df_UTFR_ML.drop_duplicates(subset=['HC_ID'])

#----------------------Unpivoted Table Full Report join to Member list Non-Adherent Flag-First Fill-------------------------------------------------


df_UTFR_ML_FF = pd.merge(df_UTFR_ML, dfUFF, left_on='HC_ID', right_on='HC_ID', how='left')
if 'First Fill' in df_UTFR_ML_FF.columns: df_UTFR_ML_FF['First Fill'] = df_UTFR_ML_FF['First Fill'].fillna('N')
df_UTFR_ML_FF   = df_UTFR_ML_FF.drop_duplicates(subset=['HC_ID'])

#----------------------Unpivoted Table Full Report join to Member list Non-Adherent Flag-First Fill SUPD-------------------------------------------------


dfSUFR = pd.merge(dfSU, dfFR, left_on='Member ID', right_on='HC_ID', how='inner')
dfSUFR = dfSUFR.rename(columns=rename_dict)
# Verify ensure there are no duplicate somewhere, check and remove if exists
dfSUFR = dfSUFR.loc[:, ~dfSUFR.columns.duplicated()]
dfSUFR = dfSUFR.drop_duplicates(subset=['HC_ID'])
dfSUUnpivoted = pd.merge(dfSUFR, dfU, left_on='HC_ID', right_on='HC_ID', how='left', indicator=True)
# Remove suffixes by renaming
dfSUUnpivoted.columns = dfSUUnpivoted.columns.str.replace('_x', '', regex=False).str.replace('_y', '', regex=False)
dfSUUnpivoted = dfSUUnpivoted.drop_duplicates(subset=['HC_ID']) 
dfSUUnpivoted['SUPD_Result'] = 'Y'
dfSUUnpivotedCols = dfSUUnpivoted.loc[:, ~dfSUUnpivoted.columns.duplicated()]

df_UTFR_ML_FF_SUPD = pd.merge(df_UTFR_ML_FF, dfSUUnpivotedCols, left_on='HC_ID', right_on='HC_ID', how='left')
if 'SUPD_Result' in df_UTFR_ML_FF_SUPD.columns: df_UTFR_ML_FF_SUPD['SUPD_Result'] = df_UTFR_ML_FF_SUPD['SUPD_Result'].fillna('N')
df_UTFR_ML_FF_SUPD   = df_UTFR_ML_FF_SUPD.drop_duplicates(subset=['HC_ID'])
df_UTFR_ML_FF_SUPD.columns = df_UTFR_ML_FF_SUPD.columns.str.replace('_x', '', regex=False).str.replace('_y', '', regex=False)
df_UTFR_ML_FF_SUPD2 = df_UTFR_ML_FF_SUPD.loc[:, ~df_UTFR_ML_FF_SUPD.columns.duplicated()]
if '_merge' in df_UTFR_ML_FF_SUPD2.columns: df_UTFR_ML_FF_SUPD2 = df_UTFR_ML_FF_SUPD2.drop(columns=['_merge'])
df_UTFR_ML_FF_SUPD2 = df_UTFR_ML_FF_SUPD2[colsFinal3]

#--------------------------------------------------------------------SUPD ONLY ROWS AND COLUMNS--------------------------------------------------------------------------

# Ensure you only keep rows where '_merge' is 'left_only'
df_SUPDOnly = dfSUUnpivotedCols[dfSUUnpivotedCols['_merge'] == 'left_only']
df_SUPDOnly = df_SUPDOnly.loc[:, ~df_SUPDOnly.columns.duplicated()]
# Check if the '_merge' column exists and drop it
if '_merge' in df_SUPDOnly.columns: df_SUPDOnly = df_SUPDOnly.drop(columns=['_merge'])
df_SUPDOnly = df_SUPDOnly[colsSUFinal2]
df_SUPDOnly['SUPD_Result'] = 'Y'

#-------------------------------------------------------------------------------------------------------------------------------------

df_UTFR_ML_FF_SUPD2 = df_UTFR_ML_FF_SUPD2.reset_index()
df_SUPDOnly = df_SUPDOnly.reset_index()
df_UnpivotedFinal = pd.concat([df_UTFR_ML_FF_SUPD2, df_SUPDOnly], ignore_index=True)
df_UnpivotedFinal = df_UnpivotedFinal.drop_duplicates()

df_UnpivotedFinal['DOB'] = pd.to_datetime(df_UnpivotedFinal['DOB']).dt.strftime('%m/%d/%Y')
df_UnpivotedFinal['Estimated/Projected Fail Date'] = pd.to_datetime(df_UnpivotedFinal['Estimated/Projected Fail Date'], errors='coerce').dt.strftime('%m/%d/%Y')
df_UnpivotedFinal['Drug Last Fill Date'] = pd.to_datetime(df_UnpivotedFinal['Drug Last Fill Date']).dt.strftime('%m/%d/%Y')
df_UnpivotedFinal['Drug Next Fill Date'] = pd.to_datetime(df_UnpivotedFinal['Drug Next Fill Date']).dt.strftime('%m/%d/%Y')

if 'index' in df_UnpivotedFinal.columns: df_UnpivotedFinal = df_UnpivotedFinal.drop(columns=['index'])

#print(df_UnpivotedFinal)
# Save to Excel if required
#df_UnpivotedFinal.to_excel(filexlsx, index=False, engine='openpyxl')

# Remove existing files if they exist
if os.path.exists(filexlsx):
    os.remove(filexlsx)
if os.path.exists(filexlsb):
    os.remove(filexlsb)

# Load the existing workbook
# wb = load_workbook(infile, keep_links=True)
sheet_name = 'Unpivoted Table Revised'

# Launch Excel application
app = xw.App(visible=False)
wb = app.books.open(infilexlsx)


# Manage Display Alerts and File Existence
wb.api.DisplayAlerts = False


if sheet_name in [sheet.name for sheet in wb.sheets]:
    sheet = wb.sheets[sheet_name]
else:
    sheet = wb.sheets.add(sheet_name, after=10)

# Write DataFrame to the sheet
sheet.range("A1").value = df_UnpivotedFinal

# Define the range to expand as a table
excel_range = sheet.range("A1").expand()

# Access Excel's ListObject to create and name the table
list_object = sheet.api.ListObjects.Add(1, excel_range.api, None, 1)

# Apply a table style
list_object.TableStyle = "TableStyleMedium9"


# Locate 'Column1' to delete it
headers_range = sheet.range("A1").expand('right')  # Assumes A1 is the starting cell
column1_range = headers_range.end('down') if 'Column1' in headers_range.value else None
headers_values = [cell.value for cell in headers_range if cell.value is not None]

# If Column1 is found, delete
if column1_range:
    column1_idx = headers_range.value.index('Column1') + 1  # +1 because Excel indexing is 1-based
    column1_range = sheet.range((1, column1_idx), (sheet.used_range.last_cell.row, column1_idx))
    column1_range.api.EntireColumn.Delete()

    
# Check if 'Index' column exists in the headers and delete it
if 'Index' in headers_values:
    index_column_idx = headers_values.index('Index') + 1  # Excel uses 1-based indexing
    sheet.Columns(index_column_idx).Delete()  # Delete the column based on the index

# Save the workbook
#wb.save()
wb.api.DisplayAlerts = False
wb.api.SaveAs(filexlsx, FileFormat=51)  # 51 corresponds to the .xlsx format in Excel
wb.api.SaveAs(filexlsb, FileFormat=50)  # 50 corresponds to the .xlsb format in Excel
wb.api.DisplayAlerts = True
wb.close()
app.quit()

print("Workbook successfully updated.")



def send_email_mapi(subject, body, to_email, attachment_path):
    # Create an instance of Outlook
    outlook = win32com.client.Dispatch("Outlook.Application")
    # Create a new Mail item
    mail = outlook.CreateItem(0)  # 0 corresponds to 'MailItem'

    # Set email parameters
    mail.Subject = subject
    mail.Body = body
    mail.To = to_email

    # Add the attachment
    if attachment_path:
        mail.Attachments.Add(attachment_path)

    # Send the email
    mail.Send()

# Usage
subject = f"""Week of {mondaystrsubject} Baptist Pharmacy Report"""
body    = f"""An updated report is attached."""
to_email = 'test.test@test.com;'
attachment_path = filexlsx

send_email_mapi(subject, body, to_email, attachment_path)



