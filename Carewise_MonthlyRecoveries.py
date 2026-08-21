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
#strfolder      = "//jhhc.com//jhhcfileshare//_Interdepartmental//COOOfficeCollab//Payment Integrity//JHHC Data Scientist//NMurrayVendors//Seidel//Files Jan 2023//"
strfilename     = 'JH EndofMonth YTD NovDec22.xlsx'
strfiledate     = '20231223'
strnowdated     = '20231201'
strVendorName   = "Carewise" 
 
prod_server = "JHHCSQLDWBI"
prod_db     = 'JHHC_BIDW_PROD'
prod_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + prod_server + ';DATABASE=' + prod_db + ';Trusted_Connection=yes')

prod_cursor= prod_conn.cursor()

prod_query = """ SET NOCOUNT ON;
               
                                
                IF OBJECT_ID(N'tempdb..#BASECLMS0') IS NOT NULL DROP TABLE #BASECLMS0; 

                select '0000000000000000'AS ClaimNbr ,'1900101' AS IdentifiedDate, '19000101' as VendorFileDate, 0 as VendorAmt
                INTO #BASECLMS0
                union all select '20181026F1545390', '20221201','20221201',629.15
                union all select '20190923G0225440', '20221201','20221201',177.9
                union all select '20191101G1241028', '20221201','20221201',87.05
                union all select '20200529G6641958', '20221201','20221201',37.4
                union all select '20200723G7697504', '20221201','20221201',27.2
                union all select '20200809G8715708', '20221201','20221201',427.92
                union all select '20210811H8471852', '20221201','20221201',98.72
                union all select '20220121I3425810', '20221201','20221201',173.08
                union all select '20211129I4107016', '20221201','20221201',40.36
                union all select '20220330I5599700', '20221201','20221201',5.13
                union all select '20220312I5388756', '20221201','20221201',161.8
                union all select '20220322I5597362', '20221201','20221201',228.93
                union all select '20220122I4455830', '20221201','20221201',38.89
                union all select '20220314I5458432', '20221201','20221201',144.82
                union all select '20220421I6399558', '20221201','20221201',210.37
                union all select '20220603I7761182', '20221201','20221201',5.71
                union all select '20220621I8183368', '20221201','20221201',20.51
                union all select '20220626I8183388', '20221201','20221201',127.56
                union all select '20220622I8061248', '20221201','20221201',60.2
                union all select '20220107I3624924', '20221201','20221201',27.14
                union all select '20211207I3505670', '20221201','20221201',186.69
                union all select '20200728G7696860', '20221101','20221101',38.12
                union all select '20220601I7981850', '20221101','20221101',464.26




                IF OBJECT_ID(N'tempdb..#BASECLMS') IS NOT NULL DROP TABLE #BASECLMS; 

                select claimnbr as ClaimNbr_Original, 
                case when len(claimnbr) = 14 then '20' + ClaimNbr 
                when len(claimnbr) = 15 then  '2' + ClaimNbr 
                else claimnbr end AS claimnbr, 
                IdentifiedDate,  VendorFileDate, VendorAmt
                INTO #BASECLMS
                from #BASECLMS0


                IF OBJECT_ID(N'tempdb..#temp1') IS NOT NULL DROP TABLE #temp1; 

                select distinct a.ClaimNbr_Original, a.ClaimNbr, bidwclaimnbr, lob.lineofbusinessname, IdentifiedDate, VendorFileDate, VendorAmt
                into #temp1
                from #Baseclms a
                left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                on a.claimnbr = clm.sourceoriginalclaimnbr
                left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness]  (nolock)  lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where lineofbusinessname in ('pp','ehp','hep')
                union
                select distinct a.ClaimNbr_Original, a.ClaimNbr, bidwclaimnbr, lob.lineofbusinessname, IdentifiedDate, VendorFileDate, VendorAmt
                from #Baseclms a
                left join [JHHC_BIDW_PROD].clm.factclaim  (nolock) clm
                on a.claimnbr = sourceoriginalclaimnbr
                left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness]  (nolock) lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where lineofbusinessnamE = 'MA'
                union
                select distinct a.ClaimNbr_Original,a.ClaimNbr,bidwclaimnbr, lob.lineofbusinessname, IdentifiedDate, VendorFileDate, VendorAmt
                from #Baseclms a
                left join [JHHC_BIDW_PROD].clm.factclaim  (nolock) clm
                on a.claimnbr = right(sourceoriginalclaimnbr,9) 
                left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness]  (nolock)  lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where lineofbusinessnamE = 'USFHP'


                IF OBJECT_ID(N'tempdb..#temp2') IS NOT NULL DROP TABLE #temp2; 

                select a.ClaimNbr, a.bidwclaimnbr, clm.bidwclaimnbr as clmbidwclaimnbr,	a.lineofbusinessname, a.IdentifiedDate, a.VendorFileDate, a.VendorAmt,
                min(case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end) as CheckDate_APPostDate
                into #temp2
                from #temp1 a
                left join [JHHC_BIDW_PROD].clm.factclaim  (nolock) clm
                on a.bidwclaimnbr = clm.bidwclaimnbr
                left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness]  (nolock) lob
                on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                where paidamtactual <0
                and case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate  end > IdentifiedDate
                group by a.ClaimNbr, clm.bidwclaimnbr,	a.bidwclaimnbr, a.lineofbusinessname, a.IdentifiedDate, a.VendorFileDate, a.VendorAmt
                --case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end




                IF OBJECT_ID(N'tempdb..#temp3') IS NOT NULL DROP TABLE #temp3;

                select a.ClaimNbr_Original as VendorClaimNbr, x.ClaimNbr as EDWClaimNbr,	x.bidwclaimnbr as EDW_BIDWClaimNbr,	x.lineofbusinessname, CheckDate_APPostDate  as retractiondate, x.VendorFileDate, isnull(x.PaidAmtActual,0) as PaidAmtActual,
                a.IdentifiedDate, a.VendorAmt, case when abs(isnull(x.PaidAmtActual,0) ) < a.VendorAmt then isnull(x.PaidAmtActual,0) else a.VendorAmt end as FinalAmt
                into #temp3
                from #BASECLMS a left join
                        (
                        select a.ClaimNbr,	a.bidwclaimnbr,	'' as Blank, clm.BIDWClaimNbr as clmbidwclaimnbr,	a.lineofbusinessname, a.VendorFileDate,
                        CheckDate_APPostDate, sum(paidamtactual) as PaidAmtActual

                        from #temp2 a
                        left join [JHHC_BIDW_PROD].clm.factclaim  (nolock) clm
                        on a.bidwclaimnbr = clm.bidwclaimnbr
                        and case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end >= CheckDate_APPostDate
                        left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness]  (nolock)  lob
                        on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                        --where paidamtactual <0
                        --and case when sk_checkdate = -1 then sk_appostdate else sk_checkdate end >= '20210215'
                        group by a.ClaimNbr,	a.bidwclaimnbr,	clm.BIDWClaimNbr,	a.lineofbusinessname, a.VendorFileDate, CheckDate_APPostDate
                        ) x
                        on a.claimnbr = x.claimnbr
                        where x.ClaimNbr <> '0000000000000000'
                        --case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end


                        select distinct a.IdentifiedDate, case when a.RetractionDate is null then '19000101' else a.RetractionDate end as RetractionDate, 
                        a.VendorClaimNbr, a.EDWClaimNbr, a.EDW_BIDWClaimNbr, a.lineofbusinessname, a.PaidAmtActual, a.VendorAmt, a.FinalAmt, a.VendorFileDate
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
                VendorFileName     = strfilename 
                ValidationDate     = strnowdated
                IdentifiedDate     = row[0]
                RetractionDate     = row[1]
                VendorClaimNbr     = row[2]
                EDWClaimNbr        = row[3]
                EDW_BIDWClaimNbr   = row[4]
                lineofbusinessname = row[5]
                EDW_PaidAmtActual  = row[6]
                VendorAmt          = row[7]
                FinalAmt           = row[8]
                VendorFileDate     = row[9]
  
                
                dev_values = (VendorName, VendorFileName, VendorFileDate, ValidationDate,  IdentifiedDate, RetractionDate, VendorClaimNbr, EDWClaimNbr, EDW_BIDWClaimNbr, lineofbusinessname, EDW_PaidAmtActual, VendorAmt, FinalAmt)
                
                print(dev_values)
                dev_query = """INSERT INTO dbo.NM_PI_VendorRecoveries 
                        (VendorName, VendorFileName, VendorFileDate, ValidationDate, IdentifiedDate, RetractionDate, VendorClaimNbr, EDWClaimNbr, EDW_BIDWClaimNbr, lineofbusinessname, EDW_PaidAmtActual, VendorAmt, FinalAmt)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"""
                
                
                dev_cursor1 = dev_conn.cursor()
                dev_cursor1.execute(dev_query, dev_values)
                print(f"{dev_cursor1.rowcount}, details inserted")
                dev_cursor1.commit()  
else:
        print('This run already done. quit ' + strfilename + strVendorName) 
        
                

    
        
        
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

