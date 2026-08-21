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
import csv



dev_server = 'VMSQLDWBIDEV'
dev_db     = 'Sandbox_ConceptDevelopment'
dev_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + dev_server + ';DATABASE=' + dev_db + ';Trusted_Connection=yes')
dev_query   = """with records_to_keep as 
                (
                SELECT case when [COB Classification Indicator] in ('01','02') then 'Keep' 
                            when  [COB Record Validation Status] = 'Active'   and [COB Classification Indicator] in ('03','04') 
                                and [Other Business Model] <> '7'and [Other Coverage Type] not in ('47','98')then 'Keep'
                        else 'Remove record' end as linestatus, [COB Classification Indicator]  as COB_CI, [COB Record Validation Status] as COV_RVS, 
                            [Other Business Model] as COB_OBM, [Other Coverage Type] as COB_OCT, *

                FROM [Sandbox_ConceptDevelopment].[dbo].[NM_20230825_2900_2020_COBReport_235_P_I_1_T]
                )
                select * from records_to_keep
                where linestatus = 'Keep'"""
                
dev_cursor = dev_conn.cursor()
dev_cursor.execute(dev_query)
# print(f"{dev_cursor.rowcount}, rowcount")
dev_data    = dev_cursor.fetchall()

df  = pd.read_sql_query(dev_query,dev_conn)
dev_conn.close()
df.to_csv('F:\COB Unit\CAQH Incoming Files\CAQH Production Files\output.txt',sep='|', index = False)

    

