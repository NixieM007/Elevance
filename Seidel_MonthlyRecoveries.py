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
strfolder       = "//jhhc.com//jhhcfileshare//_Interdepartmental//COOOfficeCollab//Payment Integrity//JHHC Data Scientist//NMurrayVendors//Seidel//Files Jan 2023//"
strfilename     = "⁪JHMA PIP RETRACT 6-2023_Validated.xls"
strfiledate     = '20230627'
strnowdated     = arrow.now().format('YYYYMMDD')
strVendorName   = "Seidel" 
 
prod_server = "JHHCSQLDWBI"
prod_db     = 'JHHC_BIDW_PROD'
prod_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + prod_server + ';DATABASE=' + prod_db + ';Trusted_Connection=yes')

prod_cursor= prod_conn.cursor()

prod_query = """ SET NOCOUNT ON;
                IF OBJECT_ID(N'tempdb..#baseclms0') IS NOT NULL DROP TABLE #baseclms0; 


                select '0000000000000000' as ClaimNbr,'19000100' AS VendorFileDate, 0 as VendorAmt
                into #BASECLMS0
                   union all select '211810035800','20230627',244.77



                IF OBJECT_ID(N'tempdb..#BaseClms') IS NOT NULL DROP TABLE #BaseClms; 

                select a.ClaimNbr, a.VendorFileDate, 
                sum(a.VendorAmt) as VendorAmt
                into #BaseClms
                from #BaseClms0 a 
                where ClaimNbr <> '0000000000000000'
                group by a.ClaimNbr, a.VendorFileDate;


                IF OBJECT_ID(N'tempdb..#temp1') IS NOT NULL DROP TABLE #temp1; 

                select distinct a.ClaimNbr, clm.sk_Member, clm.bidwclaimnbr, clm.SourceOriginalClaimNbr, clm.SourceOriginalLineNbr, a.VendorFileDate, a.VendorAmt,  lob.lineofbusinessname,
                right(SourceOriginalClaimNbr,len(SourceOriginalClaimNbr)-8) as ClaimNbr_NoDOS,
                clm.PaidAmtActual as PaidAmt
                into #temp1
                from #BaseClms a
                left join JHHC_BIDW_prod.clm.factclaim (nolock) clm
                on right(clm.SourceOriginalClaimNbr,8)  = right(a.claimnbr,8) 
                left join JHHC_BIDW_prod.MEM.dimLineOfBusiness (nolock)  lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where lineofbusinessname in ('pp','ehp','hep');
  
                IF OBJECT_ID(N'tempdb..#temp2') IS NOT NULL DROP TABLE #temp2; 

                select a.ClaimNbr,	a.SK_Member,SK_ProviderBilling,SK_ProviderRendering,SK_AdmitDate,a.bidwclaimnbr, a.lineofbusinessname, a.VendorFileDate, a.VendorAmt,  
                min(case when sk_checkdate = -1 and sk_appostdate = -1 then SK_ClaimAddDate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end) as CheckDate_APPostDate
                into #temp2
                from #temp1 a
                left join JHHC_BIDW_prod.clm.factclaim (nolock) clm on a.bidwclaimnbr = clm.bidwclaimnbr
                left join JHHC_BIDW_prod.MEM.dimLineOfBusiness (nolock) lob on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where paidamtactual < 0 -- and a.ClaimNbr = '20201124H1258936'
                and case when sk_checkdate = -1 and sk_appostdate = -1 then SK_ClaimAddDate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate  end > VendorFileDate
                group by a.ClaimNbr,	a.SK_Member,SK_ProviderBilling,SK_ProviderRendering,SK_AdmitDate,a.bidwclaimnbr, a.lineofbusinessname, a.VendorFileDate,  a.VendorAmt;
                
                IF OBJECT_ID(N'tempdb..#temp3') IS NOT NULL DROP TABLE #temp3; 

                select a.ClaimNbr as VendorClaimNbr, clm.SourceOriginalClaimNbr as EDWClaimNbr,	a.bidwclaimnbr as EDW_BIDWClaimNbr,	a.lineofbusinessname, 
                sum(try_convert(decimal(10,2), clm.paidamtactual)) as PaidAmtActual, 
                a.VendorFileDate, try_convert(decimal(10,2), a.VendorAmt) as VendorAmt,  
                case when abs(sum(try_convert(decimal(10,2), clm.paidamtactual))) <  try_convert(decimal(10,2), a.VendorAmt) 
                then abs(sum(try_convert(decimal(10,2), paidamtactual))) else  try_convert(decimal(10,2), a.VendorAmt) end  as FinalAmt,
                max(case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate  end ) as RetractionDate
                into #temp3
                from #temp2 a
                left join JHHC_BIDW_prod.clm.factclaim clm (nolock) on a.bidwclaimnbr = clm.bidwclaimnbr
                and clm.SK_LineStatus	in ('2' ,'4','5','9')	
                and case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end >= CheckDate_APPostDate
                left join JHHC_BIDW_prod.MEM.dimLineOfBusiness (nolock) lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where paidamtactual <0
                group by a.ClaimNbr, clm.SourceOriginalClaimNbr, a.bidwclaimnbr, a.lineofbusinessname, a.VendorFileDate, try_convert(decimal(10,2), a.VendorAmt);


                select  a.VendorFileDate, a.lineofbusinessname, a.VendorClaimNbr, a.EDWClaimNbr, a.EDW_BIDWClaimNbr,  
                        a.PaidAmtActual as EDW_RetractionAmt,  a.VendorAmt,  a.FinalAmt, a.RetractionDate
                        from #temp3 a
                """ 

prod_datarow = prod_cursor.execute (prod_query)
prod_data    = prod_cursor.fetchall()
# print(prod_data)


dev_server = 'VMSQLDWBIDEV'
dev_db     = 'Sandbox_ConceptDevelopment'
dev_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + dev_server + ';DATABASE=' + dev_db + ';Trusted_Connection=yes')
dev_query1  = "select VendorFileDate, VendorName from [Sandbox_ConceptDevelopment].[dbo].[NM_PI_VendorRecoveries] where VendorFileDate = '" + strfiledate + "' and  VendorName = '""" + strVendorName + "'"
dev_cursor1 = dev_conn.cursor()
dev_cursor1.execute(dev_query1)
dev_data1 = dev_cursor1.fetchall()

if dev_cursor1.rowcount == 0:
   # print('No records found for this vendor run ' + strfilename + strVendorName)
    for row in prod_data:
        if strfilename not in dev_data1:
                VendorName         = strVendorName
                ValidationDate     = strnowdated  
                VendorFileDate     = row[0]
                lineofbusinessname = row[1]
                VendorClaimNbr     = row[2]
                EDWClaimNbr        = row[3]
                EDW_BIDWClaimNbr   = row[4]
                EDW_RetractionAmt  = row[5]
                VendorAmt          = row[6]
                FinalAmt           = row[7]
                RetractionDate     = row[8]
                VendorFileName     = strfilename 
                
                dev_values = (VendorName,ValidationDate,VendorFileDate,lineofbusinessname,VendorClaimNbr,EDWClaimNbr,EDW_BIDWClaimNbr,EDW_RetractionAmt,VendorAmt,FinalAmt,RetractionDate,VendorFileName)
                
                dev_query = """INSERT INTO dbo.NM_PI_VendorRecoveries 
                        (VendorName, ValidationDate, VendorFileDate,lineofbusinessname,VendorClaimNbr,EDWClaimNbr,EDW_BIDWClaimNbr,EDW_RetractionAmt,VendorAmt,FinalAmt,RetractionDate,VendorFileName)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"""
                
                
                dev_cursor1 = dev_conn.cursor()
                dev_cursor1.execute(dev_query, dev_values)
                print(f"{dev_cursor1.rowcount}, details inserted")
                dev_cursor1.commit()  
else:
        print('This run already done. Quit ' + strfilename + strVendorName) 
        
                

    
        
        
#         sourcesheet.cell(r,1).value  =  HICN_MCOContract
#         sourcesheet.cell(r,2).value  =  HICNumber
#         sourcesheet.cell(r,3).value  =  PaymentDate
#         sourcesheet.cell(r,4).value  =  PaymtAdjustmentMSAStartDate
#         sourcesheet.cell(r,5).value  =  PaymtAdjustmentMSAEndDate
#         sourcesheet.cell(r,6).value  =  AdjustmentReasonCode
#         sourcesheet.cell(r,7).value  =  RecordType
#         sourcesheet.cell(r,8).value  =  TotalPartCPayment
#         sourcesheet.cell(r,9).value  =  NumberofPaymtAdjustmtMonthsPartA
#         sourcesheet.cell(r,10).value =  NumberofPaymtAdjustmtMonthsPartB
#         sourcesheet.cell(r,11).value =  MCOContractNumber
        
#         r = r + 1
        
#         cursordev = conndev.cursor()
#         cursordev.execute(querydev, values)
#         cursordev.commit()
#         cursordev.close()
        
        
# #Save Workbook
# sourcefile.save(strfilename)

#dev_query = """INSERT INTO dbo.NM_PI_VendorRecoveries 
#            (VendorName,lineofbusinessname,ValidationDate,VendorFileDate,VendorClaimNbr,
#            EDWClaimNbr,EDW_BIDWClaimNbr,EDW_RetractionAmt,VendorAmt,FinalAmt)
#           SELECT * FROM (SELECT (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS TEMP
#            WHERE NOT EXISTS  
#            (SELECT VendorFileName from dbo.NM_PI_VendorRecoveries WHERE VendorFileName = '""" + strVendorName + """' and VendorFileName like '%""" + strfilename + """%'")"""

