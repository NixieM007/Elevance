import snowflake.connector
import shelve
from pathlib import Path
import shutil
import os
import win32com.client
from datetime import datetime, timedelta
from snowflake.connector.errors import Error as SnowflakeError
import pandas as pd
import xlwings as xw
import tkinter as tk
from tkinter import simpledialog


FilePath = r"\\va10pavfle009\Transparency\PTDM\PDL\Quality\QLTY Table Validation\QLTY_SCORG PQSM validation\QLTY_SCORG_validation_Template.xlsx"
today_date = datetime.now().strftime('%Y-%m-%d')
SHELVE_FILENAME = 'credentials_shelve'


# -------------------------------------------------------------------
# SQL QUERIES
# -------------------------------------------------------------------

strsql_stg1 = """SELECT snap_year_mnth_nbr as snap_period, 
            'QLTY_SCORG_INPT_MDL' as label1, 'Quality Scoring Input Model' as label2, 
            COUNT(*) AS totalcount
            FROM P01_PDL.PDL_STG.qlty_scorg_inpt_mdl_stg
            WHERE snap_year_mnth_nbr = (
                    SELECT MAX(snap_year_mnth_nbr) 
                    FROM P01_PDL.PDL_STG.qlty_scorg_inpt_mdl_stg)
                    GROUP BY snap_year_mnth_nbr
            """
strsql_stg2 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_DATA_EXCLSN' as label1, 'Quality Scoring Data Excl' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_STG.qlty_scorg_data_exclsn_stg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_data_exclsn_stg)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_stg3 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_DOMN_TIER' as label1, 'Quality Scoring DOMN Tier' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_STG.qlty_scorg_domn_tier_stg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_domn_tier_stg)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_stg4 = """SELECT snap_year_mnth_nbr as snap_period, 
                  'QLTY_SCORG_MSR_TIER' as label1, 'Quality Scoring MSR Tier' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_STG.qlty_scorg_msr_tier_stg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_msr_tier_stg)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_stg5 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_PROV_SMRY' as label1, 'Quality Scoring Prov Summ' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_stg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_stg)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_stg6 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_PROV_RULE_AGG' AS label1, 
                 'Quality Scoring Prov Rule Agg' AS label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg)
                        GROUP BY snap_year_mnth_nbr
                """

strsql_tar1 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_INPT_MDL' as label1, 'Quality Scoring Input Model' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.QLTY_SCORG_INPT_MDL
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.QLTY_SCORG_INPT_MDL)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_tar2 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_DATA_EXCLSN' as label1, 'Quality Scoring Data Excl' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.qlty_scorg_data_exclsn
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.qlty_scorg_data_exclsn)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_tar3 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_DOMN_TIER' as label1, 'Quality Scoring DOMN Tier' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.qlty_scorg_domn_tier
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.qlty_scorg_domn_tier)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_tar4 = """SELECT snap_year_mnth_nbr as snap_period, 
                  'QLTY_SCORG_MSR_TIER' as label1, 'Quality Scoring MSR Tier' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.qlty_scorg_msr_tier
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.qlty_scorg_msr_tier)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_tar5 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_PROV_SMRY' as label1, 'Quality Scoring Prov Summ' as label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.qlty_scorg_prov_smry
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.qlty_scorg_prov_smry)
                        GROUP BY snap_year_mnth_nbr
                """
strsql_tar6 = """SELECT snap_year_mnth_nbr as snap_period, 
                 'QLTY_SCORG_PROV_RULE_AGG' AS label1, 
                 'Quality Scoring Prov Rule Agg' AS label2, 
                  COUNT(*) AS totalcount
                  FROM P01_PDL.PDL_ALLPHI.qlty_scorg_prov_rule_agg
                  WHERE snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_ALLPHI.qlty_scorg_prov_rule_agg)
                        GROUP BY snap_year_mnth_nbr
                """

strsql_step01_part1 = """
            --Step 1 Part 1 - check Source Code for rules - currently all rules should be from CRE

            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label, 'qlty_scorg_INPT_MDL' as Label1, 
            SOR_CD as SOR_CD, min(rule_id) as MIN_RULEID, max(rule_id) as MAX_RULEID
            from P01_PDL.PDL_STG.qlty_scorg_INPT_MDL_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG )
            group by 1,2,3,4
            
            union all
            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label,'qlty_scorg_msr_tier' as Label1, 
            SOR_CD, min(rule_id), max(rule_id)
            from P01_PDL.PDL_STG.qlty_scorg_msr_tier_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG )
            group by 1,2,3,4
            
            union all
            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label,'qlty_scorg_prov_rule_agg' as Label1, 
            SOR_CD, min(rule_id), max(rule_id)
            from P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG )
            group by 1,2,3,4
            
            union all
            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label,'qlty_scorg_DATA_EXCLSN' as Label1, SOR_CD, min(rule_id), max(rule_id)
            from P01_PDL.PDL_STG.qlty_scorg_DATA_EXCLSN_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG )
            group by 1,2,3,4
            """

strsql_step01_part2 = """
            --Step 1 Part 2 - Source Code should be NA because these tables don't include rule detail
            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label, 'qlty_scorg_DOMN_TIER' as Label1, SOR_CD as SOR_CD
            from P01_PDL.PDL_STG.qlty_scorg_DOMN_TIER_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_DOMN_TIER_STG)
            group by 1, 2, 3,4
            
            union all
            select distinct snap_year_mnth_nbr as snap_period, 'Staging' as Label, 'qlty_scorg_PROV_SMRY' as Label1, SOR_CD
            from P01_PDL.PDL_STG.qlty_scorg_PROV_SMRY_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
            group by 1, 2, 3,4  
            """

strsql_step02 = """
                --Step 2 - Tables should have 60 combinations of data 
                --(5 aggregation levels, 2 benchmarks, 2 peer markets, 3 LOB).  
                --DATA_EXCLSN won't always have 60, usually 54
                SELECT snap_year_mnth_nbr as snap_period, 
                                'QLTY_SCORG_DATA_EXCLSN' as label1, 'Quality Scoring Data Excl Stg' as label2, 
                                count (distinct agrgtn_type_cd||bnchmrk_type_cd||peer_mrkt_cd||pcr_lob_desc) AS recordcount
                                FROM P01_PDL.PDL_STG.qlty_scorg_data_exclsn_stg
                                WHERE snap_year_mnth_nbr = (
                                        SELECT MAX(snap_year_mnth_nbr) 
                                        FROM P01_PDL.PDL_STG.qlty_scorg_data_exclsn_stg)
                                        GROUP BY snap_year_mnth_nbr
                union all 
                SELECT snap_year_mnth_nbr as snap_period, 
                                'QLTY_SCORG_DOMN_TIER' as label1, 'Quality Scoring DOMN Tier' as label2, 
                                count (distinct agrgtn_type_cd||bnchmrk_type_cd||peer_mrkt_cd||pcr_lob_desc) AS recordcount
                                FROM P01_PDL.PDL_STG.qlty_scorg_domn_tier_stg
                                WHERE snap_year_mnth_nbr = (
                                        SELECT MAX(snap_year_mnth_nbr) 
                                        FROM P01_PDL.PDL_STG.qlty_scorg_domn_tier_stg)
                                        GROUP BY snap_year_mnth_nbr
                union all 
                SELECT snap_year_mnth_nbr as snap_period, 
                                'QLTY_SCORG_MSR_TIER' as label1, 'Quality Scoring MSR Tier' as label2, 
                                count (distinct agrgtn_type_cd||bnchmrk_type_cd||peer_mrkt_cd||pcr_lob_desc) AS recordcount
                                FROM P01_PDL.PDL_STG.qlty_scorg_msr_tier_stg
                                WHERE snap_year_mnth_nbr = (
                                        SELECT MAX(snap_year_mnth_nbr) 
                                        FROM P01_PDL.PDL_STG.qlty_scorg_msr_tier_stg)
                                        GROUP BY snap_year_mnth_nbr
                union all 
                SELECT snap_year_mnth_nbr as snap_period, 
                                'QLTY_SCORG_PROV_SMRY' as label1, 'Quality Scoring Prov Summ' as label2, 
                                count (distinct agrgtn_type_cd||bnchmrk_type_cd||peer_mrkt_cd||pcr_lob_desc) AS recordcount
                                FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_stg
                                WHERE snap_year_mnth_nbr = (
                                        SELECT MAX(snap_year_mnth_nbr) 
                                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_stg)
                                        GROUP BY snap_year_mnth_nbr
                union all 
                SELECT snap_year_mnth_nbr as snap_period, 
                                'QLTY_SCORG_PROV_RULE_AGG' AS label1, 
                                'Quality Scoring Prov Rule Agg' AS label2, 
                                count (distinct agrgtn_type_cd||bnchmrk_type_cd||peer_mrkt_cd||pcr_lob_desc) AS recordcount
                                FROM P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg
                                WHERE snap_year_mnth_nbr = (
                                        SELECT MAX(snap_year_mnth_nbr) 
                                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg)
                                        GROUP BY snap_year_mnth_nbr
                                """

strsql_step03 = """
            -- Step 3 - PROV_SMRY should only have 1 row for each snap, peer mkt, lob, state, spec, agg type, bnchmrk, TIN, NPI, domain.  
            -- This step looks for outliers.  Zero records expected
            select 'qlty_scorg_prov_smry staging' as Label,
            snap_year_mnth_nbr as snap_period,
            peer_mrkt_cd as peer_market_code,
            pcr_lob_desc as pcr_lob_code,
            cntrctd_st_cd as contracted_state_code,
            spclty_cd as specialty_code,
            agrgtn_type_cd as agg_type_code,
            bnchmrk_type_cd as bnchmark_type_code,
            tax_id as tax_id,
            npi as npi,
            rule_domn_nm as rule_domaim_name,
            '' as rule_id,
            count(*)
            from P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG
            where qlty_tier_txt <> 'Not Scorable' 
            and snap_year_mnth_nbr = (
                                    SELECT MAX(snap_year_mnth_nbr) 
                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
            group by 1,2,3,4,5,6,7,8,9,10,11
            having count(*) >1

            union all

            select 'qlty_scorg_prov_rule_agg staging' as Label,
            snap_year_mnth_nbr as snap_period,
            peer_mrkt_cd as peer_market_code,
            pcr_lob_desc as pcr_lob_code,
            cntrctd_st_cd as contracted_state_code,
            spclty_cd as specialty_code,
            agrgtn_type_cd as agg_type_code,
            bnchmrk_type_cd as bnchmark_type_code,
            tax_id as tax_id,
            npi as npi,
            rule_domn_nm as rule_domaim_name,
            rule_id as rule_id,
            count(*)
            from P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg
            where totl_mbr_cnt >=5 and snap_year_mnth_nbr = (
                                    SELECT MAX(snap_year_mnth_nbr) 
                                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_stg)
            group by 1,2,3,4,5,6,7,8,9,10,11,12
            having count(*) >1
            """

strsql_step04 = """
            -- Step 4 - Check QLTY_TIER calculation using LCL and UCL values.   UCL <1 should be Low.  
            -- LCL >1 should be High.  LCL <=1 and UCL >=1 should be As Expected.  
            -- This step looks for outliers.  Zero results expected..
         
                select  
                QLTY_TIER_TXT,
                QLTY_CNFDNC_INTRVL_LOWR_NBR,
                QLTY_CNFDNC_INTRVL_UPR_NBR,
                count(*)
                from P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG
                where 
                (qlty_cnfdnc_intrvl_lowr_nbr >1 and QLTY_TIER_TXT not in ('High','Not Scorable'))
                or
                (QLTY_CNFDNC_INTRVL_UPR_NBR <1 and QLTY_TIER_TXT not in ('Low','Not Scorable'))
                or
                (qlty_cnfdnc_intrvl_lowr_nbr <=1 and qlty_cnfdnc_intrvl_upr_nbr >=1 and QLTY_TIER_TXT not in ('As Expected','Not Scorable'))
                group by 1,2,3
            """

strsql_step05 = """
            -- Summary of the domains should match the blended total.   
            -- This step searches for outliers.  Zero records expected

            select 
            snap_year_mnth_nbr as snap_period,
            'qlty_scorg_prov_stg ' as Label,
            peer_mrkt_cd as peer_market_code,
            pcr_lob_desc as pcr_lob_desc,
            cntrctd_st_cd as cntrctd_st_cd,
            spclty_cd as specialty_code,
            agrgtn_type_cd as aggregate_type_code,
            bnchmrk_type_cd as benchmark_type_code,
            tax_id as tax_id,
            npi as npi,
            sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN totl_scrbl_rule_cnt end) as domn_rule,
            sum(CASE WHEN rule_domn_nm = 'Blended' THEN totl_scrbl_rule_cnt end) as blend_rule,
            sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN totl_mbr_cnt end) as domn_totl_mbr,
            sum(CASE WHEN rule_domn_nm = 'Blended' THEN totl_mbr_cnt end) as blend_totl_mbr,
            sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN cmplynt_mbr_cnt end) as domn_compl_mbr,
            sum(CASE WHEN rule_domn_nm = 'Blended' THEN cmplynt_mbr_cnt end) as blend_cmplnt_mbr
            from 
            P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG 
            where snap_year_mnth_nbr = (
                    SELECT MAX(snap_year_mnth_nbr) 
                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG )
            group by 1,2,3,4,5,6,7,8,9,10
            having 
            sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN totl_scrbl_rule_cnt end) <> sum(CASE WHEN rule_domn_nm = 'Blended' THEN totl_scrbl_rule_cnt end) 
            or sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN totl_mbr_cnt end)  <> sum(CASE WHEN rule_domn_nm = 'Blended' THEN totl_mbr_cnt end) 
            or sum(CASE WHEN rule_domn_nm in ('Process','Outcomes','Overuse') THEN cmplynt_mbr_cnt end) <> sum(CASE WHEN rule_domn_nm = 'Blended' THEN cmplynt_mbr_cnt end)
            """

strsql_step06 = """
            -- OE should be between LCL and UCL. This step searches for outliers. 
            -- Anything less than 25 is OK.

            select snap_year_mnth_nbr as snap_period,
            'qlty_scorg_prov_smry' as Label,
            'Numerator' as Label1,
            count(*) as recordcount
            from 
            P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG 
            where qlty_scor_nbr not between qlty_cnfdnc_intrvL_lowr_nbr and qlty_cnfdnc_intrvl_upr_nbr
            and snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                  FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
            group by 1,2
            
            union all
            select snap_year_mnth_nbr as snap_period,
            'qlty_scorg_prov_smry' as Label,
            'Denominator' as Label1,
            count(*) as recordcount
            from 
            P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG 
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                                  FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
            group by 1,2
            """

strsql_step07 = """
            --If PROV_SMRY.QLTY_SCOR_NBR  (OE) = 0 (not scorable) then the QLTY_TIER should not be Low, As Expected or High.
            
            select 
            QLTY_CNFDNC_INTRVL_LOWR_NBR,
            QLTY_CNFDNC_INTRVL_UPR_NBR ,
            QLTY_TIER_TXT ,
            COUNT(*)
            from 
            P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG 
            where
            rule_domn_nm = 'Blended'
            AND qlty_SCOR_NBR = 0
            and QLTY_TIER_TXT <> 'Not Scorable'
            GROUP BY 1,2,3
        """


strsql_step08_Part1 = """
            -- Step 8 Part 1 - Check compliance rate calculation (CMPLNC_RT / BNCMRK_CMPLNC_RT).   
            -- This step looks for outliers.   Zero results expected.

           select distinct
            snap_year_mnth_nbr as snap_period,
            'qlty_scorg_prov_RULE_AGG_stg' as Label,
            CMPLYNT_MBR_CNT as comp_member_count,
            TOTL_MBR_CNT as total_member_count,
            CMPLNC_RT as compliance_rate,
            CASE when TOTL_MBR_CNT <> 0 THEN 
                  CAST(CMPLYNT_MBR_CNT AS DECIMAL(10,4)) / cast(totl_mbr_cnt as decimal(10,4)) 
                  ELSE CAST (0 AS DECIMAL(10,4))
            END AS Result1,  
            CAST(Result1 - CMPLNC_RT AS DECIMAL(10,4)) as Result2  
            from P01_PDL.PDL_STG.qlty_scorg_prov_RULE_AGG_stg
            where Result2 <> 0  
            and Result2 <> 0.0001  
            and Result2 <> -0.0001 
            and snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr) 
                                      FROM P01_PDL.PDL_STG.qlty_scorg_prov_RULE_AGG_stg)
        """

strsql_step08_Part2 = """
            -- Step 8 Part 2 - Check Rule OE calculation (CMPLNC_RT / BNCMRK_CMPLNC_RT).  
            -- This step looks for outliers.  Zero results expected.

            select distinct
            snap_year_mnth_nbr as snap_period,
            'qlty_scorg_prov_RULE_AGG_stg' as Label,
            CMPLYNT_MBR_CNT as comp_member_count,
            TOTL_MBR_CNT as total_member_count,
            CMPLNC_RT as compliance_rate,
            CASE when TOTL_MBR_CNT <> 0 THEN 
                  CAST(CMPLYNT_MBR_CNT AS DECIMAL(10,4)) / cast(totl_mbr_cnt as decimal(10,4)) 
                  ELSE CAST (0 AS DECIMAL(10,4))
            END AS Result1,  
            CAST(Result1 - CMPLNC_RT AS DECIMAL(10,4)) as Result2  
            from P01_PDL.PDL_STG.qlty_scorg_prov_RULE_AGG_stg
            where Result2 <> 0  
            and Result2 <> 0.0001  
            and Result2 <> -0.0001 
            and snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr)
                                      FROM P01_PDL.PDL_STG.qlty_scorg_prov_RULE_AGG_stg)
        """

strsql_step09_Part1 = """
            -- Step 9 Part 1  All PROV_SMRY combinations with domains 
            -- (Outcomes, Process, Overuse) should also have a Blended score.  The two counts should match. 
            
            select 
            case when RULE_DOMN_NM in ('Overuse','Outcomes','Process') then '3 Domains'
                when RULE_DOMN_NM = 'Blended' then 'Blended'  else 'x' end as Domain,
            count(distinct peer_mrkt_cd||pcr_lob_desc||cntrctd_st_cd||agrgtn_type_cd||bnchmrk_type_cd||tax_id) as recordcount
            from P01_PDL.PDL_STG.qlty_scorg_PROV_SMRY_STG
            where snap_year_mnth_nbr = (SELECT MAX(snap_year_mnth_nbr)
                                      FROM P01_PDL.PDL_STG.qlty_scorg_PROV_SMRY_STG)
            group by 1
            order by 1

        """

strsql_step09_Part2 = """
            -- Step 9 Part 2 - Benchmarks from MSR_TIER should match RULE_AGG.  
            -- This step looks for outliers.  Zero records expected.

            select 
            msr.snap_year_mnth_nbr as snap_period,
            'peer_mrkt_cd||pcr_lob_desc||cntrctd_st_cd||agrgtn_type_cd||bnchmrk_type_cd||tax_id' as Label,
            'msr_cmplnc_rt<>prov.bncmrk_cmplnc_rt' as label1,
            msr.peer_mrkt_cd as peer_mrkt_cd, 
            msr.pcr_lob_desc as pcr_lob_desc,
            msr.sor_cd as sor_cd,
            msr.cntrctd_st_cd as cntrctd_st_cd, 
            msr.spclty_cd as spclty_cd,
            msr.agrgtn_type_cd as agrgtn_type_cd, 
            msr.bnchmrk_type_cd as bnchmrk_type_cd,
            msr.rule_domn_nm as rule_domn_nm,
            msr.totl_mbr_cnt as totl_mbr_cnt,
            msr.cmplynt_mbr_cnt as cmplynt_mbr_cnt,
            msr.cmplnc_rt as cmplnc_rt,
            msr.sor_dtm as sor_dtm,
            prov.bncmrk_cmplnc_rt
            from P01_PDL.PDL_STG.qlty_scorg_MSR_TIER_STG as MSR,
                    P01_PDL.PDL_STG.qlty_scorg_prov_rule_agg_STG as PROV
            where msr.snap_year_mnth_nbr = PROV.snap_year_mnth_nbr
            and msr.peer_mrkt_cd = PROV.peer_mrkt_cd
            and msr.pcr_lob_desc = PROV.pcr_lob_desc
            and msr.cntrctd_st_cd = Prov.cntrctd_st_cd
            and msr.spclty_cd = prov.spclty_cd
            and msr.agrgtn_type_cd = prov.agrgtn_type_cd
            and msr.bnchmrk_type_cd = prov.bnchmrk_type_cd
            and msr.rule_id = prov.rule_id
            and msr.cmplnc_rt <> prov.bncmrk_cmplnc_rt
            and msr.snap_year_mnth_nbr = (
                    SELECT MAX(snap_year_mnth_nbr) 
                    FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
        """

strsql_step10_Part1 = """
                -- When PROV_SMRY Quality Tier is "Not Scoreable", OE, LCL and UCL should be set to 0.  
                -- This step looks for outliers.  Zero records expected.

                select snap_year_mnth_nbr as snap_period,
                'peer_mrkt_cd||pcr_lob_desc||cntrctd_st_cd||agrgtn_type_cd||bnchmrk_type_cd||tax_id' as Label,
                msr.peer_mrkt_cd as peer_mrkt_cd, 
                msr.pcr_lob_desc as pcr_lob_desc,
                msr.qlty_tier_txt as qlty_tier_txt,
                msr.sor_cd as sor_cd,
                msr.cntrctd_st_cd as cntrctd_st_cd, 
                msr.spclty_cd as spclty_cd,
                msr.agrgtn_type_cd as agrgtn_type_cd, 
                msr.bnchmrk_type_cd as bnchmrk_type_cd,
                msr.tax_id as tax_id,
                msr.npi as npi,
                msr.rule_domn_nm as rule_domn_nm,
                msr.totl_scrbl_rule_cnt as totl_scrbl_rule_cnt,
                msr.totl_mbr_cnt as totl_mbr_cnt,
                msr.cmplynt_mbr_cnt as cmplynt_mbr_cnt,
                msr.cmplnc_rt as cmplnc_rt,
                msr.qlty_scor_nbr as qlty_scor_nbr,
                msr.sor_dtm as sor_dtm,
                msr.qlty_cnfdnc_intrvl_lowr_nbr as qlty_cnfdnc_intrvl_lowr_nbr,
                msr.qlty_cnfdnc_intrvl_upr_nbr as qlty_cnfdnc_intrvl_upr_nbr
                from P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG msr
                where qlty_tier_txt = 'Not Scorable' 
                and (qlty_scor_nbr <> 0 or 
                     QLTY_CNFDNC_INTRVL_LOWR_NBR <> 0 or 
                     QLTY_CNFDNC_INTRVL_UPR_NBR <> 0)
                and msr.snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
        """

strsql_step10_Part2 = """
        -- When PROV_SMRY Quality Tier <> "Not Scoreable", the OE should always be populated (not 0).  
        -- This step looks for outliers.  Zero records expected

                select msr.snap_year_mnth_nbr as snap_period,
                'peer_mrkt_cd||pcr_lob_desc||cntrctd_st_cd||agrgtn_type_cd||bnchmrk_type_cd||tax_id' as Label,
                msr.peer_mrkt_cd as peer_mrkt_cd, 
                msr.pcr_lob_desc as pcr_lob_desc,
                msr.qlty_tier_txt as qlty_tier_txt,
                msr.sor_cd as sor_cd,
                msr.cntrctd_st_cd as cntrctd_st_cd, 
                msr.spclty_cd as spclty_cd,
                msr.agrgtn_type_cd as agrgtn_type_cd, 
                msr.bnchmrk_type_cd as bnchmrk_type_cd,
                msr.tax_id as tax_id,
                msr.npi as npi,
                msr.rule_domn_nm as rule_domn_nm,
                msr.totl_scrbl_rule_cnt as totl_scrbl_rule_cnt,
                msr.totl_mbr_cnt as totl_mbr_cnt,
                msr.cmplynt_mbr_cnt as cmplynt_mbr_cnt,
                msr.cmplnc_rt as cmplnc_rt,
                msr.qlty_scor_nbr as qlty_scor_nbr,
                msr.sor_dtm as sor_dtm,
                msr.qlty_cnfdnc_intrvl_lowr_nbr as qlty_cnfdnc_intrvl_lowr_nbr,
                msr.qlty_cnfdnc_intrvl_upr_nbr as qlty_cnfdnc_intrvl_upr_nbr
                from P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG msr
                where msr.qlty_tier_txt <> 'Not Scorable' 
                and msr.qlty_scor_nbr = 0
                and msr.snap_year_mnth_nbr = (
                        SELECT MAX(snap_year_mnth_nbr) 
                        FROM P01_PDL.PDL_STG.qlty_scorg_prov_smry_STG)
        """

# -------------------------------------------------------------------
# SQL QUERIES END
# -------------------------------------------------------------------



# -------------------------------------------------------------------
# MESSAGES
# -------------------------------------------------------------------

msg_step01_part1 = """ Step 1 Part 1 - check Source Code for rules - currently all rules should be from CRE."""
msg_step01_part2 = """Step 1 Part 2 - Source Code should be NA because these tables don't include rule detail."""
msg_step02 = """ Step 2 - Tables should have 60 combinations of data (5 aggregation levels, 2 benchmarks, 2 peer markets, 3 LOB). DATA_EXCLSN won't always have 60, usually 54."""
msg_step03 = """ Step 3 - PROV_SMRY should only have 1 row for each snap, peer mkt, lob, state, spec, agg type, bnchmrk, TIN, NPI, domain. This step looks for outliers.  Zero records expected."""
msg_step04 = """ Step 4 - Check QLTY_TIER calculation using LCL and UCL values. UCL <1 should be Low.  LCL >1 should be High.  LCL <=1 and UCL >=1 should be As Expected. This step looks for outliers.  Zero results expected."""
msg_step05 = """ Step 5 - Summary of the domains should match the blended total. This step searches for outliers.  Zero records expected."""
msg_step06 = """ Step 6 - OE should be between LCL and UCL. This step searches for outliers. Anything less than 25 is OK."""
msg_step07 = """ Step 7 - If PROV_SMRY.QLTY_SCOR_NBR  (OE) = 0 (not scorable) then the QLTY_TIER should not be Low, As Expected or High."""
msg_step08_part1 = """ Step 8 Part 1 - Check compliance rate calculation (CMPLNC_RT / BNCMRK_CMPLNC_RT).   This step looks for outliers.   Zero results expected."""
msg_step08_part2 = """ Step 8 Part 2 - Check Rule OE calculation (CMPLNC_RT / BNCMRK_CMPLNC_RT).  This step looks for outliers.  Zero results expected."""
msg_step09_part1 = """Step 9 Part 1  All PROV_SMRY combinations with domains (Outcomes, Process, Overuse) should also have a Blended score.  The two counts should match."""
msg_step09_part2 = """ Step 9 Part 2 - Benchmarks from MSR_TIER should match RULE_AGG.  This step looks for outliers.  Zero records expected."""
msg_step10_part1 = """ Step 10 Part 1 - When PROV_SMRY Quality Tier is "Not Scoreable", OE, LCL and UCL should be set to 0.  This step looks for outliers.  Zero records expected."""
msg_step10_part2 = """ Step 10 Part 2 - When PROV_SMRY Quality Tier <> "Not Scoreable", the OE should always be populated (not 0).  This step looks for outliers.  Zero records expected."""


# -------------------------------------------------------------------
# MESSAGES END
# -------------------------------------------------------------------
# -------------------------------------------------------------------
# CREDENTIALS / CONNECTION
# -------------------------------------------------------------------

def get_credentials():
    with shelve.open(SHELVE_FILENAME) as creds:
        stored_date = creds.get('date', None)
        today_date_local = datetime.now().strftime('%Y-%m-%d')

        if stored_date == today_date_local:
            username = creds.get('username', None)
            password = creds.get('password', None)
            if username is not None and password is not None:
                return username, password

        username, password = prompt_credentials()
        creds['username'] = username
        creds['password'] = password
        creds['date'] = today_date_local

    return username, password

# USERNAME = "AN522610AD"
# PASSWORD = "Ju!7J6gvM-PH4rNQRFzI"

def set_credentials_to_env(username, password):
    os.environ['USERNAME'] = username
    os.environ['PASSWORD'] = password
    os.environ['CREDENTIALS_DATE'] = datetime.now().strftime('%Y-%m-%d')


def prompt_credentials():
    root = tk.Tk()
    root.withdraw()

    username = simpledialog.askstring("Input", "Enter your username:", parent=root)
    password = simpledialog.askstring("Input", "Enter your password:", parent=root, show='*')

    return username, password


USERNAME, PASSWORD = get_credentials()
ACCOUNT = "carelon-edaprod1.privatelink"
AUTHENTICATOR = "https://portalsso.elevancehealth.com?snowflake=okta"

WAREHOUSE = "DL_MDO_USER_WH_M"
DATABASE = "P01_PDL"
SCHEMA = "P01_EDL_NOHAPHI"
ROLE = "P01_EDL_NOHAPHI_USER"


def get_snowflake_connection(username, password, account, authenticator, warehouse, database, schema, role):
    try:
        conn = snowflake.connector.connect(
            user=username,
            password=password,
            account=account,
            authenticator=authenticator,
            warehouse=warehouse,
            schema=schema,
            role=role,
            database=database
        )
        return conn
    except SnowflakeError as error:
        print(f"Failed to connect to Snowflake: {error}")
        return None


def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        df = cursor.fetch_pandas_all()
        return df
    except Exception as e:
        print(f"Error executing query: {e}")
        return pd.DataFrame()
    finally:
        cursor.close()


# -------------------------------------------------------------------
# DATA PROCESSING
# -------------------------------------------------------------------

def main_stg(conn):
    sql_queries_stg = [strsql_stg1, strsql_stg2, strsql_stg3, strsql_stg4, strsql_stg5, strsql_stg6]
    df_stg_list = []

    for query in sql_queries_stg:
        df = execute_query(conn, query)
        df_stg_list.append(df)

    if df_stg_list:
        return pd.concat(df_stg_list, ignore_index=True)
    return pd.DataFrame()


def main_tar(conn):
    sql_queries_tar = [strsql_tar1, strsql_tar2, strsql_tar3, strsql_tar4, strsql_tar5, strsql_tar6]
    df_tar_list = []

    for query in sql_queries_tar:
        df_tar = execute_query(conn, query)
        df_tar_list.append(df_tar)

    if df_tar_list:
        return pd.concat(df_tar_list, ignore_index=True)
    return pd.DataFrame()


def step_00_main(connection):
    if not connection:
        print("Failed to connect to Snowflake")
        return None, None, None, None

    global glsnap
    global gsheetname

    print("Connected to Snowflake")

    staging_df = main_stg(connection)
    target_df = main_tar(connection)

    step00_df = pd.merge(
        staging_df,
        target_df,
        on='LABEL1',
        suffixes=('_staging', '_target')
    )

    # Staging minus target so negative values remain negative when staging is lower.
    step00_df['totalcount_difference'] = (
        step00_df['TOTALCOUNT_staging'] - step00_df['TOTALCOUNT_target']
    )

    # Percent difference = (staging - target) / target.
    # Return NA when the target count is zero to avoid division-by-zero errors.
    step00_df['totalcount_percent_difference'] = (
        step00_df['totalcount_difference']
        / step00_df['TOTALCOUNT_target'].replace(0, pd.NA)
    )

    if 'LABEL2_staging' in step00_df.columns and 'LABEL2_target' in step00_df.columns:
        step00_df['LABEL2'] = step00_df['LABEL2_staging'].combine_first(step00_df['LABEL2_target'])
        step00_df.drop(columns=['LABEL2_staging', 'LABEL2_target'], inplace=True)
    elif 'LABEL2_staging' in step00_df.columns:
        step00_df.rename(columns={'LABEL2_staging': 'LABEL2'}, inplace=True)
    elif 'LABEL2_target' in step00_df.columns:
        step00_df.rename(columns={'LABEL2_target': 'LABEL2'}, inplace=True)

    keep_cols = [
        'SNAP_PERIOD_staging',
        'LABEL1',
        'LABEL2',
        'TOTALCOUNT_staging',
        'SNAP_PERIOD_target',
        'TOTALCOUNT_target',
        'totalcount_difference',
        'totalcount_percent_difference'
    ]

    missing = [c for c in keep_cols if c not in step00_df.columns]
    if missing:
        raise KeyError(f"Missing expected columns after merge: {missing}")

    step00_df = step00_df.loc[:, keep_cols]

    snap_period = step00_df['SNAP_PERIOD_staging'].iloc[0]
    glsnap = snap_period
    sheet_name = f"PQSM_Validation_Snap_{snap_period}"
    gsheetname = sheet_name
    title = "Step 00 Part 1 - Compare record counts to previous snap."

    return step00_df, sheet_name, title, snap_period


def process_step(conn, query, sheet_prefix):
    df = execute_query(conn, query)
    title = f"{sheet_prefix}"

    if df.empty:
        message = f"{title} --> Zero (0) records expected"
        return df, message
    return df, title


# -------------------------------------------------------------------
# EXCEL HELPERS
# -------------------------------------------------------------------

# Tracks the next title row while this script is running. This lets us
# preserve intentional blank spacing even when Excel would otherwise ignore
# blank rows while finding the last used row.
NEXT_TITLE_ROW_BY_WORKBOOK_SHEET = {}

def _workbook_sheet_key(file_path, sheet_name):
    return (str(Path(file_path).resolve()), sheet_name)

def _rows_written_by_dataframe(df):
    # xlwings writes a pandas DataFrame with a header row even when there are
    # zero records. Keep at least one row reserved for the displayed empty set.
    if df is None or df.empty:
        return 1
    return len(df.index) + 1

def _format_negative_difference_columns(sheet, df, data_start_row):
    """Format Step 00 difference columns after the DataFrame is written."""
    if df is None or df.empty:
        return

    format_columns = {
        'totalcount_difference': '0',
        'totalcount_percent_difference': '0.00%',
    }

    # xlwings writes the DataFrame index in column A, followed by DataFrame columns.
    for column_name, number_format in format_columns.items():
        if column_name not in df.columns:
            continue

        excel_col = df.columns.get_loc(column_name) + 2
        first_data_row = data_start_row + 1
        last_data_row = data_start_row + len(df.index)
        data_range = sheet.range(
            (first_data_row, excel_col),
            (last_data_row, excel_col)
        )
        data_range.number_format = number_format

        # Keep normal values black and show only negative values in red.
        for row_offset, value in enumerate(df[column_name], start=first_data_row):
            cell = sheet.cells(row_offset, excel_col)
            cell.api.Font.Color = 255 if pd.notna(value) and value < 0 else 0


def sheet_exists_in_workbook(file_path, sheet_name):
    app = xw.App(visible=False)
    wb = None
    try:
        wb = app.books.open(file_path)
        return sheet_name in [sht.name for sht in wb.sheets]
    finally:
        if wb is not None:
            wb.close()
        app.quit()


def get_available_sheet_name(file_path, base_sheet_name):
    """Return base_sheet_name unless it already exists, then add _01, _02, etc."""
    app = xw.App(visible=False)
    wb = None
    try:
        wb = app.books.open(file_path)
        existing_sheet_names = {sht.name for sht in wb.sheets}

        # Excel worksheet names max out at 31 characters.
        if base_sheet_name not in existing_sheet_names:
            return base_sheet_name[:31]

        for i in range(1, 100):
            suffix = f"_{i:02d}"
            candidate = f"{base_sheet_name[:31 - len(suffix)]}{suffix}"
            if candidate not in existing_sheet_names:
                return candidate

        raise ValueError(f"Unable to create a unique sheet name for: {base_sheet_name}")
    finally:
        if wb is not None:
            wb.close()
        app.quit()


def add_data_to_excel(file_path, sheet_name, title, df):
    svalue = 1
    evalue = 100

    app = xw.App(visible=False)
    wb = None

    try:
        wb = app.books.open(file_path)
        key = _workbook_sheet_key(file_path, sheet_name)

        if sheet_name in [sht.name for sht in wb.sheets]:
            sheet = wb.sheets[sheet_name]

            title_exists = any(
                title == cell_value
                for row in sheet.range(f'A{svalue}:Z{evalue}').value
                for cell_value in row
                if cell_value is not None
            )

            if title_exists:
                print(f"The title '{title}' already exists. Exiting without making changes.")
                return

            last_row = sheet.range('A' + str(sheet.cells.last_cell.row)).end('up').row
            title_row = max(last_row + 3, NEXT_TITLE_ROW_BY_WORKBOOK_SHEET.get(key, last_row + 3))
            data_start_row = title_row + 3

            sheet.range(f'A{title_row}').value = title
            sheet.range(f'A{data_start_row}').value = df
            _format_negative_difference_columns(sheet, df, data_start_row)

        else:
            sheet = wb.sheets.add(sheet_name, after=wb.sheets[-1])
            title_row = 1
            data_start_row = 3

            sheet.range(f'A{title_row}').value = title
            sheet.range(f'A{data_start_row}').value = df
            _format_negative_difference_columns(sheet, df, data_start_row)

        rows_written = _rows_written_by_dataframe(df)

        if df is not None and df.empty:
            # Empty SQL result: leave 4 blank rows before the next step title.
            NEXT_TITLE_ROW_BY_WORKBOOK_SHEET[key] = data_start_row + rows_written + 4
        else:
            # Non-empty result: keep the existing spacing behavior.
            NEXT_TITLE_ROW_BY_WORKBOOK_SHEET[key] = data_start_row + rows_written + 3

        wb.save()

    finally:
        if wb is not None:
            wb.close()
        app.quit()


def generate_output_filepath(template_path, snap_period):
    """
    Build a unique, versioned output file name for each run.

    The original workbook should be treated as the clean template. Each run
    creates a copy first, then writes validation results into that copy.
    """
    src = Path(template_path)
    run_stamp = datetime.now().strftime("%Y%m%d")
    return src.with_name(f"{src.stem}_SNAP_{snap_period}_RUN_{run_stamp}{src.suffix}")


def create_dated_copy(source_file_path, output_file_path):
    src = Path(source_file_path)
    dst = Path(output_file_path)

    dst.parent.mkdir(parents=True, exist_ok=True)

    if dst.exists():
        dst.unlink()

    shutil.copy2(src, dst)
    print(f"Created dated copy: {dst}")


# -------------------------------------------------------------------
# EMAIL
# -------------------------------------------------------------------

def send_email_mapi(subject, body, to_email, cc_email=None, attachment_path=None):
    outlook = win32com.client.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)

    mail.Subject = subject
    mail.Body = body
    mail.To = to_email

    if cc_email:
        mail.CC = cc_email

    if attachment_path:
        attachment_path = os.fspath(attachment_path)
        if not os.path.isfile(attachment_path):
            raise FileNotFoundError(f"Attachment not found: {attachment_path}")
        mail.Attachments.Add(attachment_path)

    mail.Send()


# -------------------------------------------------------------------
# MAIN RUNNER
# -------------------------------------------------------------------

def run_validation():
    connection1 = get_snowflake_connection(
        USERNAME,
        PASSWORD,
        ACCOUNT,
        AUTHENTICATOR,
        WAREHOUSE,
        DATABASE,
        SCHEMA,
        ROLE
    )

    if not connection1:
        print("Connection could not be established.")
        return

    output_file_path = None

    try:
        step00_df, sheet_name, title, snap_period = step_00_main(connection1)

        if step00_df is None:
            print("Step 00 has not completed")
            return

        # Create the versioned workbook first.
        # This keeps FilePath as the clean template and writes results only to the run copy.
        output_file_path = generate_output_filepath(FilePath, snap_period)
        create_dated_copy(FilePath, output_file_path)

        # If the copied workbook already has this sheet from a prior manual edit,
        # use a safe alternate sheet name instead of stopping the run.
        sheet_name = get_available_sheet_name(output_file_path, sheet_name)
        global gsheetname
        gsheetname = sheet_name

        # Write all results to the versioned output workbook.
        add_data_to_excel(output_file_path, sheet_name, title, step00_df)
        print(f"{title} has completed in output workbook: {output_file_path}")

        step_queries = [
            #(strsql_part_00, "Step 0"),
            (strsql_step01_part1, msg_step01_part1),
            (strsql_step01_part2, msg_step01_part2),
            (strsql_step02, msg_step02),
            (strsql_step03, msg_step03),
            (strsql_step04, msg_step04),
            (strsql_step05, msg_step05),
            (strsql_step06, msg_step06),
            (strsql_step07, msg_step07),
            (strsql_step08_Part1, msg_step08_part1),
            (strsql_step08_Part2, msg_step08_part2),
            (strsql_step09_Part1, msg_step09_part1),
            (strsql_step09_Part2, msg_step09_part2),
            (strsql_step10_Part1, msg_step10_part1),
            (strsql_step10_Part2, msg_step10_part2),
        ]

        for query, step_name in step_queries:
            df, new_title = process_step(connection1, query, step_name)
            if df is not None:
                add_data_to_excel(output_file_path, sheet_name, new_title, df)
                print(f"{new_title} has completed")
                #print(f"{new_title} has completed in output workbook: {output_file_path}")
            else:
                print(f"{new_title} has not completed")

    finally:
        connection1.close()

        
    # Email the same output file you wrote to
    to_email = "kristi.chaput@elevancehealth.com;"
    cc_email = "nicole.murray@elevancehealth.com;"

    subject = f"PQSM Validation for SNAP period: {glsnap}"
    body = f"""Hello Team,

                Validation for the current snap is attached.

                Please see the sheet {gsheetname} in the document.

                Attachment:
                {output_file_path}

                Thanks,

                Nicole Murray
                Business Info Consultant
                Health Economics, Provider Insights
                W@H GA
                C: (404) 593-1539
                elevancehealth.com
                """

    send_email_mapi(subject, body, to_email, cc_email, output_file_path)
    print(f"Email sent with attachment: {output_file_path}")


if __name__ == "__main__":
    run_validation()