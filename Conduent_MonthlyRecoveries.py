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
strfilename     = 'Conduent_JHHC-ALL LOBS_20230607_Validated.xlsx'
strfiledate     = '20230302'
strnowdated     = '20230601'
strVendorName   = "Conduent Credit Balance Solutions, LLC" 
 
prod_server = "JHHCSQLDWBI"
prod_db     = 'JHHC_BIDW_PROD'
prod_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + prod_server + ';DATABASE=' + prod_db + ';Trusted_Connection=yes')

prod_cursor= prod_conn.cursor()

prod_query = """    SET NOCOUNT ON;
                     
                    IF OBJECT_ID(N'tempdb..#BASECLMS0') IS NOT NULL DROP TABLE #BASECLMS0;

                    select '0000000000000000' AS ClaimNbr,'19000101'as IdentifiedDate, '19000100' AS VendorFileDate, '' as LOB, 0 as VendorAmt
                    INTO #BASECLMS0
                    UNION ALL SELECT '200760028400','20201028','20230302','Medicare Advantage',688.66
                    UNION ALL SELECT '200640018700','20200902','20230302','Medicare Advantage',465.64
                    UNION ALL SELECT '193650002601','20211124','20230302','Medicare Advantage',822.58
                    UNION ALL SELECT '191220005200','20200915','20230302','Medicare Advantage',68.59
                    UNION ALL SELECT '192830001200','20200731','20230302','Medicare Advantage',559.05
                    UNION ALL SELECT '201110011000','20200914','20230302','Medicare Advantage',215.21
                    UNION ALL SELECT '193310030801','20210621','20230302','Medicare Advantage',340.5
                    UNION ALL SELECT '193310030800','20200428','20230302','Medicare Advantage',602.23
                    UNION ALL SELECT '190990012100','20200915','20230302','Medicare Advantage',76.94
                    UNION ALL SELECT '180720037001','20201207','20230302','Medicare Advantage',115.51
                    UNION ALL SELECT '212020005601','20220526','20230302','Medicare Advantage',51.31
                    UNION ALL SELECT '210370024901','20220526','20230302','Medicare Advantage',51.31
                    UNION ALL SELECT '210860004800','20220526','20230302','Medicare Advantage',51.31
                    UNION ALL SELECT '212060001201','20220526','20230302','Medicare Advantage',51.31
                    UNION ALL SELECT '192350009801','20201030','20230302','Medicare Advantage',351.05
                    UNION ALL SELECT '213640025001','20220628','20230302','Medicare Advantage',49.21
                    UNION ALL SELECT '220750028800','20220719','20230302','Medicare Advantage',39.58
                    UNION ALL SELECT '192980030100','20191220','20230302','Medicare Advantage',162.4
                    UNION ALL SELECT '20220418I8550228','20220927','20230302',' Priority Partners',62.25
                    UNION ALL SELECT '20220717I8743544','20220928','20230302',' Priority Partners',3096.38
                    UNION ALL SELECT '20220716I9329142','20220928','20230302',' Priority Partners',117.09
                    UNION ALL SELECT '20220522I7000186','20220728','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220610I7556562','20220728','20230302',' Priority Partners',43.68
                    UNION ALL SELECT '20220626I8464874','20220808','20230302',' Priority Partners',704.54
                    UNION ALL SELECT '20210519H6070790','20220728','20230302',' Priority Partners',1209.98
                    UNION ALL SELECT '20220210I4094380','20220808','20230302',' Priority Partners',1751.16
                    UNION ALL SELECT '20211221I6708768','20220817','20230302',' Priority Partners',34.76
                    UNION ALL SELECT '20200225G9395176','20220817','20230302',' Priority Partners',17.48
                    UNION ALL SELECT '20200521G6293230','20220817','20230302',' Priority Partners',10.65
                    UNION ALL SELECT '20220213I6504444','20220714','20230302',' Priority Partners',1928.5
                    UNION ALL SELECT '20220505I7292578','20220628','20230302',' Priority Partners',10.95
                    UNION ALL SELECT '20220430I6508210','20220705','20230302',' Priority Partners',770.82
                    UNION ALL SELECT '20220304I7376496','20220826','20230302',' Priority Partners',129.13
                    UNION ALL SELECT '20191019G0628884','20220726','20230302',' Priority Partners',72.84
                    UNION ALL SELECT '20211220I4086246','20220301','20230302',' Priority Partners',86.67
                    UNION ALL SELECT '20220808I9207458','20221011','20230302',' Priority Partners',75.61
                    UNION ALL SELECT '20211025I7623456','20220817','20230302',' Priority Partners',10.15
                    UNION ALL SELECT '20210713H8140578','20221005','20230302',' Priority Partners',153.2
                    UNION ALL SELECT '20220329I5594672','20220525','20230302',' Priority Partners',1893.28
                    UNION ALL SELECT '20220723I9240012','20220909','20230302',' Priority Partners',24.24
                    UNION ALL SELECT '20220301I4653720','20221018','20230302',' Priority Partners',223.18
                    UNION ALL SELECT '09232021H9675590','20220125','20230302',' Priority Partners',498.93
                    UNION ALL SELECT '20220623I9176568','20220826','20230302',' Priority Partners',103.37
                    UNION ALL SELECT '20220324I5340224','20221020','20230302',' Priority Partners',122.31
                    UNION ALL SELECT '20190801F8593421','20220531','20230302',' Priority Partners',988.04
                    UNION ALL SELECT '20210423H5433864','20220531','20230302',' Priority Partners',972.14
                    UNION ALL SELECT '20220610I7511108','20220930','20230302',' Priority Partners',655.66
                    UNION ALL SELECT '20220215I6774982','20220707','20230302',' Priority Partners',106.02
                    UNION ALL SELECT '20200920G9699764','20220531','20230302',' Priority Partners',1042.29
                    UNION ALL SELECT '20220627I8015686','20220906','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '20220823I9840412','20221004','20230302',' Priority Partners',5.68
                    UNION ALL SELECT '20220531I7676878','20220727','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220531I7980872','20220727','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220405I8820216','20220912','20230302',' Priority Partners',215.19
                    UNION ALL SELECT '20210808I1123872','20220627','20230302',' Priority Partners',119.69
                    UNION ALL SELECT '20220823I9840412','20221004','20230302',' Priority Partners',5.68
                    UNION ALL SELECT '20220406I6383934','20220628','20230302',' Priority Partners',823.72
                    UNION ALL SELECT '20211021I0432726','20220110','20230302',' Priority Partners',129.09
                    UNION ALL SELECT '20220503I7077904','20220826','20230302',' Priority Partners',237.64
                    UNION ALL SELECT '20220628I8185934','20220817','20230302',' Priority Partners',129.22
                    UNION ALL SELECT '20190929G0097344','20220222','20230302',' Priority Partners',96.5
                    UNION ALL SELECT '20220416I7588618','20220908','20230302',' Priority Partners',133.82
                    UNION ALL SELECT '20220214I4263024','20220629','20230302',' Priority Partners',13.43
                    UNION ALL SELECT '20220520I7720938','20220801','20230302',' Priority Partners',1023.01
                    UNION ALL SELECT '20220511I6668448','20220726','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220321I7282388','20220728','20230302',' Priority Partners',15
                    UNION ALL SELECT '20220607I7637766','20220726','20230302',' Priority Partners',766.26
                    UNION ALL SELECT '20210321H4856742','20220502','20230302',' Priority Partners',1295.28
                    UNION ALL SELECT '20220428I8054908','20220805','20230302',' Priority Partners',836.45
                    UNION ALL SELECT '20220713I8361410','20220919','20230302',' Priority Partners',156.18
                    UNION ALL SELECT '20180920E9828618','20221013','20230302',' Priority Partners',140.1
                    UNION ALL SELECT '20211213I2320808','20220610','20230302',' Priority Partners',64.06
                    UNION ALL SELECT '20191125G2379126','20220817','20230302',' Priority Partners',8.31
                    UNION ALL SELECT '20220627I7957690','20220823','20230302',' Priority Partners',67.48
                    UNION ALL SELECT '20220718I8495684','20220915','20230302',' Priority Partners',40.43
                    UNION ALL SELECT '20210808H9640586','20220613','20230302',' Priority Partners',233.39
                    UNION ALL SELECT '20211012I0126990','20220110','20230302',' Priority Partners',103.86
                    UNION ALL SELECT '20211012I2861884','20220314','20230302',' Priority Partners',92.09
                    UNION ALL SELECT '20210302H3651970','20220831','20230302',' Priority Partners',346.96
                    UNION ALL SELECT '20220404I9115928','20220819','20230302',' Priority Partners',22.38
                    UNION ALL SELECT '20220708I8477368','20220808','20230302',' Priority Partners',1952.36
                    UNION ALL SELECT '20220706I8232154','20220927','20230302',' Priority Partners',55.19
                    UNION ALL SELECT '20220702I8300150','20220808','20230302',' Priority Partners',1292.1
                    UNION ALL SELECT '20220706I8331914','20220808','20230302',' Priority Partners',1033.61
                    UNION ALL SELECT '20220307I6756700','20220718','20230302',' Priority Partners',981.35
                    UNION ALL SELECT '20220306I4869408','20220712','20230302',' Priority Partners',105.68
                    UNION ALL SELECT '20210619H6948692','20210927','20230302',' Priority Partners',25.36
                    UNION ALL SELECT '20220318I5486828','20221011','20230302',' Priority Partners',187.63
                    UNION ALL SELECT '20220515I7296982','20220628','20230302',' Priority Partners',1227.93
                    UNION ALL SELECT '20220412I7296984','20220628','20230302',' Priority Partners',692.02
                    UNION ALL SELECT '20220109I5241880','20220722','20230302',' Priority Partners',94.18
                    UNION ALL SELECT '20211226I3619408','20220607','20230302',' Priority Partners',127.6
                    UNION ALL SELECT '20220318I5389744','20220808','20230302',' Priority Partners',477.62
                    UNION ALL SELECT '20210310H9207430','20221007','20230302',' Priority Partners',78.38
                    UNION ALL SELECT '20220117I3346472','20220726','20230302',' Priority Partners',669.35
                    UNION ALL SELECT '20220117I7151578','20220726','20230302',' Priority Partners',9.94
                    UNION ALL SELECT '20210719H8500398','20211109','20230302',' Priority Partners',149.09
                    UNION ALL SELECT '20220628I8288142','20220930','20230302',' Priority Partners',119.47
                    UNION ALL SELECT '20220411I5995552','20220526','20230302',' Priority Partners',29.35
                    UNION ALL SELECT '20210210H8030102','20220817','20230302',' Priority Partners',129.53
                    UNION ALL SELECT '20220122I3565476','20220725','20230302',' Priority Partners',352.42
                    UNION ALL SELECT '20220416I6435362','20220713','20230302',' Priority Partners',312.9
                    UNION ALL SELECT '20220406I7178228','20220726','20230302',' Priority Partners',16.73
                    UNION ALL SELECT '20220302I4653798','20220822','20230302',' Priority Partners',72.84
                    UNION ALL SELECT '20210619H7201716','20220524','20230302',' Priority Partners',244.26
                    UNION ALL SELECT '20220208I7530980','20220810','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220804I9828584','20220919','20230302',' Priority Partners',11.36
                    UNION ALL SELECT '20220804I9828584','20220919','20230302',' Priority Partners',6.71
                    UNION ALL SELECT '20210613H7141836','20220524','20230302',' Priority Partners',4253.85
                    UNION ALL SELECT '20220412I7624100','20220810','20230302',' Priority Partners',72.09
                    UNION ALL SELECT '20210608H6710466','20220502','20230302',' Priority Partners',3118.09
                    UNION ALL SELECT '20220620I8905560','20220928','20230302',' Priority Partners',20
                    UNION ALL SELECT '20210917I0187544','20220824','20230302',' Priority Partners',1643.99
                    UNION ALL SELECT '20220315I5003988','20221005','20230302',' Priority Partners',5.68
                    UNION ALL SELECT '20220403I9828920','20221004','20230302',' Priority Partners',5.68
                    UNION ALL SELECT '20211211I4993918','20220824','20230302',' Priority Partners',1650.29
                    UNION ALL SELECT '20220519I9967124','20221013','20230302',' Priority Partners',10
                    UNION ALL SELECT '20210422H5473066','20220511','20230302',' Priority Partners',879.46
                    UNION ALL SELECT '20210331H5211478','20220808','20230302',' Priority Partners',171.17
                    UNION ALL SELECT '20211103I2152194','20220713','20230302',' Priority Partners',241
                    UNION ALL SELECT '20210916I8546532','20220817','20230302',' Priority Partners',2905.32
                    UNION ALL SELECT '20220219I4312460','20220831','20230302',' Priority Partners',149.76
                    UNION ALL SELECT '20220112I3200520','20220804','20230302',' Priority Partners',100.76
                    UNION ALL SELECT '20190926G6459170','20220516','20230302',' Priority Partners',53.63
                    UNION ALL SELECT '20210308H3831474','20220831','20230302',' Priority Partners',264.05
                    UNION ALL SELECT '20220311I6431344','20220801','20230302',' Priority Partners',63.39
                    UNION ALL SELECT '20220610I7590136','20220808','20230302',' Priority Partners',72.84
                    UNION ALL SELECT '20220611I7563638','20220808','20230302',' Priority Partners',72.84
                    UNION ALL SELECT '20220526I7523514','20220803','20230302',' Priority Partners',1683.15
                    UNION ALL SELECT '20220527I7229074','20220804','20230302',' Priority Partners',3743.06
                    UNION ALL SELECT '20220621I7954572','20220906','20230302',' Priority Partners',1597.27
                    UNION ALL SELECT '20220808I9071896','20221012','20230302',' Priority Partners',108.61
                    UNION ALL SELECT '20220105I4442216','20220629','20230302',' Priority Partners',803.81
                    UNION ALL SELECT '20211016I1437094','20220729','20230302',' Priority Partners',5.81
                    UNION ALL SELECT '20211016I0531942','20220815','20230302',' Priority Partners',2.87
                    UNION ALL SELECT '20220614I7758760','20220722','20230302',' Priority Partners',33.74
                    UNION ALL SELECT '20220109I6671748','20220607','20230302',' Priority Partners',953.46
                    UNION ALL SELECT '20210719I7623454','20220801','20230302',' Priority Partners',230.53
                    UNION ALL SELECT '06222020G6940620','20220202','20230302',' Priority Partners',43.73
                    UNION ALL SELECT '20210713I1158972','20220127','20230302',' Priority Partners',9.9
                    UNION ALL SELECT '20220109I6061368','20220527','20230302',' Priority Partners',1786.47
                    UNION ALL SELECT '20210624H7464738','20220502','20230302',' Priority Partners',2014.65
                    UNION ALL SELECT '20210908H9488204','20220524','20230302',' Priority Partners',790.81
                    UNION ALL SELECT '20220402I7225734','20221011','20230302',' Priority Partners',145.68
                    UNION ALL SELECT '20220403I7288538','20221011','20230302',' Priority Partners',72.84
                    UNION ALL SELECT '20210406H4735328','20220817','20230302',' Priority Partners',269.27
                    UNION ALL SELECT '20210422I0408638','20220817','20230302',' Priority Partners',9.01
                    UNION ALL SELECT '20220601I7288674','20220808','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '20220715I8842636','20220817','20230302',' Priority Partners',2641.42
                    UNION ALL SELECT '20220429I6634180','20220808','20230302',' Priority Partners',243.79
                    UNION ALL SELECT '20210608H7059008','20220330','20230302',' Priority Partners',3757.69
                    UNION ALL SELECT '20220531I7864456','20220808','20230302',' Priority Partners',26.77
                    UNION ALL SELECT '20210616H7468110','20211019','20230302',' Priority Partners',10
                    UNION ALL SELECT '20190110F3835946','20220808','20230302',' Priority Partners',1134.4
                    UNION ALL SELECT '20210729I3389702','20220520','20230302',' Priority Partners',75.84
                    UNION ALL SELECT '20220618I8913348','20220812','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220618I8913350','20220812','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220610I7728242','20220726','20230302',' Priority Partners',812.06
                    UNION ALL SELECT '20200825H5888586','20220817','20230302',' Priority Partners',25.19
                    UNION ALL SELECT '20200728G8199888','20220817','20230302',' Priority Partners',3.22
                    UNION ALL SELECT '20220722I9214054','20220916','20230302',' Priority Partners',21.85
                    UNION ALL SELECT '20220425I8683140','20220914','20230302',' Priority Partners',464.56
                    UNION ALL SELECT '20220808I9067368','20221021','20230302',' Priority Partners',114.12
                    UNION ALL SELECT '20201119H1244038','20220606','20230302',' Priority Partners',779.95
                    UNION ALL SELECT '20220208I6630604','20220615','20230302',' Priority Partners',4454.23
                    UNION ALL SELECT '20220323I7216180','20220613','20230302',' Priority Partners',494.09
                    UNION ALL SELECT '20220103I3056058','20220805','20230302',' Priority Partners',295.17
                    UNION ALL SELECT '20220711I8293974','20220902','20230302',' Priority Partners',71.65
                    UNION ALL SELECT '20220714I8394536','20220919','20230302',' Priority Partners',104.86
                    UNION ALL SELECT '20220817I9323398','20221031','20230302',' Priority Partners',41.22
                    UNION ALL SELECT '20210613H7135000','20220524','20230302',' Priority Partners',484.92
                    UNION ALL SELECT '20220409I6078406','20220727','20230302',' Priority Partners',135.92
                    UNION ALL SELECT '20210329H4525260','20211210','20230302',' Priority Partners',232.81
                    UNION ALL SELECT '20220516I7117234','20220922','20230302',' Priority Partners',182.27
                    UNION ALL SELECT '20220303I6911262','20220613','20230302',' Priority Partners',2139.19
                    UNION ALL SELECT '20220127I5798780','20220609','20230302',' Priority Partners',2217.08
                    UNION ALL SELECT '20220304I4791214','20220922','20230302',' Priority Partners',3147
                    UNION ALL SELECT '08182021H8599394','20211015','20230302',' Priority Partners',465.54
                    UNION ALL SELECT '20220712I8506938','20220808','20230302',' Priority Partners',38.94
                    UNION ALL SELECT '20220407I8424024','20220920','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20220518I7292494','20220817','20230302',' Priority Partners',2992.85
                    UNION ALL SELECT '20211229I2737094','20220925','20230302',' Priority Partners',43.68
                    UNION ALL SELECT '20220509I8902026','20220922','20230302',' Priority Partners',198.96
                    UNION ALL SELECT '20220310I6431432','20220613','20230302',' Priority Partners',41.83
                    UNION ALL SELECT '20220129I3659800','20220712','20230302',' Priority Partners',503.04
                    UNION ALL SELECT '20210202H3302146','20220916','20230302',' Priority Partners',152.81
                    UNION ALL SELECT '04182022I6181422','20220818','20230302',' Priority Partners',787.72
                    UNION ALL SELECT '20210830H9053970','20220524','20230302',' Priority Partners',263.61
                    UNION ALL SELECT '20200326G9204328','20211110','20230302',' Priority Partners',8.25
                    UNION ALL SELECT '06252020G7125836','20210930','20230302',' Priority Partners',183.21
                    UNION ALL SELECT '20220531I7783794','20220817','20230302',' Priority Partners',11.89
                    UNION ALL SELECT '20220624I8123310','20220808','20230302',' Priority Partners',78.06
                    UNION ALL SELECT '20220511I6836544','20220824','20230302',' Priority Partners',587.43
                    UNION ALL SELECT '20210816H8837616','20220524','20230302',' Priority Partners',527.2
                    UNION ALL SELECT '20220601I7254016','20220808','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '12302021I3244016','20220706','20230302',' Priority Partners',718.46
                    UNION ALL SELECT '20220512I6762322','20220916','20230302',' Priority Partners',299.35
                    UNION ALL SELECT '20220410I7338696','20220817','20230302',' Priority Partners',101.32
                    UNION ALL SELECT '20220415I6178188','20220804','20230302',' Priority Partners',1824.82
                    UNION ALL SELECT '20220119I8705402','20220920','20230302',' Priority Partners',63.08
                    UNION ALL SELECT '20211227I2719580','20220927','20230302',' Priority Partners',23.08
                    UNION ALL SELECT '20220613I7796630','20220717','20230302',' Priority Partners',2451.54
                    UNION ALL SELECT '20220425I6183548','20220807','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20210409H8467566','20220908','20230302',' Priority Partners',236.26
                    UNION ALL SELECT '20220525I8557636','20220817','20230302',' Priority Partners',8.61
                    UNION ALL SELECT '20220601I8557640','20220817','20230302',' Priority Partners',8.61
                    UNION ALL SELECT '20220608I8557638','20220817','20230302',' Priority Partners',8.6
                    UNION ALL SELECT '20211107I1353126','20220808','20230302',' Priority Partners',864.06
                    UNION ALL SELECT '20220407I6836448','20220811','20230302',' Priority Partners',1021.31
                    UNION ALL SELECT '20220711I9151276','20220914','20230302',' Priority Partners',2.85
                    UNION ALL SELECT '20220212I4128464','20220607','20230302',' Priority Partners',126.16
                    UNION ALL SELECT '20200701G7245274','20221101','20230302',' Priority Partners',8.72
                    UNION ALL SELECT '20220118I3657962','20220610','20230302',' Priority Partners',156.36
                    UNION ALL SELECT '20220720I8779678','20220824','20230302',' Priority Partners',39.28
                    UNION ALL SELECT '20220721I8916800','20220830','20230302',' Priority Partners',2640.2
                    UNION ALL SELECT '20220412I7117244','20220721','20230302',' Priority Partners',380.14
                    UNION ALL SELECT '20211227I2540070','20221003','20230302',' Priority Partners',16.97
                    UNION ALL SELECT '20211227I3324390','20221004','20230302',' Priority Partners',1.88
                    UNION ALL SELECT '20220223I4400622','20221012','20230302',' Priority Partners',122.12
                    UNION ALL SELECT '20220428I6469672','20221011','20230302',' Priority Partners',527.5
                    UNION ALL SELECT '20220815I9330754','20220908','20230302',' Priority Partners',146.14
                    UNION ALL SELECT '20220812I9287220','20220908','20230302',' Priority Partners',146.14
                    UNION ALL SELECT '20220810I9165294','20220908','20230302',' Priority Partners',146.14
                    UNION ALL SELECT '20220819I9452980','20220908','20230302',' Priority Partners',146.14
                    UNION ALL SELECT '20220808I9127786','20220908','20230302',' Priority Partners',146.14
                    UNION ALL SELECT '20200712G7380284','20220715','20230302',' Priority Partners',408.93
                    UNION ALL SELECT '20200508G9314048','20220817','20230302',' Priority Partners',28.06
                    UNION ALL SELECT '20210917H9481884','20220824','20230302',' Priority Partners',941.93
                    UNION ALL SELECT '20220202I7602462','20221111','20230302',' Priority Partners',6.56
                    UNION ALL SELECT '20201022H0111572','20220817','20230302',' Priority Partners',46.71
                    UNION ALL SELECT '20190731F8346858','20220816','20230302',' Priority Partners',39.3
                    UNION ALL SELECT '20211026I2365066','20220629','20230302',' Priority Partners',26.65
                    UNION ALL SELECT '20211026I1754748','20220629','20230302',' Priority Partners',6.53
                    UNION ALL SELECT '20210422H5330128','20220516','20230302',' Priority Partners',620.23
                    UNION ALL SELECT '20220228I7530966','20220830','20230302',' Priority Partners',30
                    UNION ALL SELECT '20220301I7446412','20220714','20230302',' Priority Partners',2455.09
                    UNION ALL SELECT '20220708I8320396','20220824','20230302',' Priority Partners',1272
                    UNION ALL SELECT '20220204I9037282','20220914','20230302',' Priority Partners',16.43
                    UNION ALL SELECT '20211018I3815680','20220713','20230302',' Priority Partners',234.44
                    UNION ALL SELECT '20220422I6301988','20220524','20230302',' Priority Partners',3545.78
                    UNION ALL SELECT '20210906H9487314','20220502','20230302',' Priority Partners',1823.92
                    UNION ALL SELECT '20220612I8230994','20220811','20230302',' Priority Partners',679.47
                    UNION ALL SELECT '20220708I8369306','20220908','20230302',' Priority Partners',9357.45
                    UNION ALL SELECT '20210627H7259454','20220330','20230302',' Priority Partners',5379.72
                    UNION ALL SELECT '20220628I8150418','20220808','20230302',' Priority Partners',50.9
                    UNION ALL SELECT '20211218I3614282','20220414','20230302',' Priority Partners',1652.43
                    UNION ALL SELECT '20211018I2429138','20220629','20230302',' Priority Partners',172.62
                    UNION ALL SELECT '20210709H7901564','20220502','20230302',' Priority Partners',1431.01
                    UNION ALL SELECT '20220202I4744010','20220603','20230302',' Priority Partners',478.4
                    UNION ALL SELECT '20220519I7120588','20220808','20230302',' Priority Partners',129.22
                    UNION ALL SELECT '20220208I6743966','20220615','20230302',' Priority Partners',522.27
                    UNION ALL SELECT '20200101G3286942','20220516','20230302',' Priority Partners',678.96
                    UNION ALL SELECT '20220511I6689920','20220718','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '20210701H9186532','20220609','20230302',' Priority Partners',675.79
                    UNION ALL SELECT '20220612I7720906','20220805','20230302',' Priority Partners',1605.7
                    UNION ALL SELECT '20220208I4303228','20220421','20230302',' Priority Partners',421.12
                    UNION ALL SELECT '20200605H6468750','20220817','20230302',' Priority Partners',115.24
                    UNION ALL SELECT '20200611G6704548','20220817','20230302',' Priority Partners',55.35
                    UNION ALL SELECT '20220426I6323068','20220807','20230302',' Priority Partners',218.37
                    UNION ALL SELECT '20210831H9028702','20220524','20230302',' Priority Partners',1327.54
                    UNION ALL SELECT '20220306I5119012','20220725','20230302',' Priority Partners',327.01
                    UNION ALL SELECT '20220606I8094492','20220810','20230302',' Priority Partners',337.16
                    UNION ALL SELECT '20220516I7120590','20220621','20230302',' Priority Partners',222.99
                    UNION ALL SELECT '20220425I6836420','20220627','20230302',' Priority Partners',243.87
                    UNION ALL SELECT '20220320I5424012','20220718','20230302',' Priority Partners',2517.46
                    UNION ALL SELECT '20211210I3472972','20220718','20230302',' Priority Partners',2443.95
                    UNION ALL SELECT '20220206I6756718','20220627','20230302',' Priority Partners',725.09
                    UNION ALL SELECT '20220410I6665630','20220630','20230302',' Priority Partners',764.62
                    UNION ALL SELECT '20220509I6799374','20220722','20230302',' Priority Partners',46.49
                    UNION ALL SELECT '20220423I6665612','20220805','20230302',' Priority Partners',683.55
                    UNION ALL SELECT '20220401I6228672','20220824','20230302',' Priority Partners',1636.48
                    UNION ALL SELECT '20220119I5241830','20220527','20230302',' Priority Partners',384.5
                    UNION ALL SELECT '20220125I7035376','20220623','20230302',' Priority Partners',30.92
                    UNION ALL SELECT '20220310I5006834','20220712','20230302',' Priority Partners',993.6
                    UNION ALL SELECT '20210722H8516674','20220629','20230302',' Priority Partners',16.54
                    UNION ALL SELECT '20220624I7986926','20220920','20230302',' Priority Partners',127.37
                    UNION ALL SELECT '20220512I6710714','20220726','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220722I8618034','20220927','20230302',' Priority Partners',122.3
                    UNION ALL SELECT '20220601I8300216','20220817','20230302',' Priority Partners',172.71
                    UNION ALL SELECT '20210430H5938572','20220421','20230302',' Priority Partners',6441.06
                    UNION ALL SELECT '20220420I6874766','20220826','20230302',' Priority Partners',1438.92
                    UNION ALL SELECT '20220511I6915292','20220621','20230302',' Priority Partners',2794.02
                    UNION ALL SELECT '20220612I8061196','20220810','20230302',' Priority Partners',58.41
                    UNION ALL SELECT '20220404I6504750','20220801','20230302',' Priority Partners',2700.24
                    UNION ALL SELECT '20220428I6469670','20220623','20230302',' Priority Partners',406.9
                    UNION ALL SELECT '20220511I9464456','20220914','20230302',' Priority Partners',380.32
                    UNION ALL SELECT '20210202H4808332','20220927','20230302',' Priority Partners',79.76
                    UNION ALL SELECT '20210724I0675972','20220914','20230302',' Priority Partners',719.02
                    UNION ALL SELECT '20220308I7035472','20220627','20230302',' Priority Partners',1897.26
                    UNION ALL SELECT '20210629H7268756','20220524','20230302',' Priority Partners',1791.09
                    UNION ALL SELECT '20220714I8394530','20220920','20230302',' Priority Partners',104.86
                    UNION ALL SELECT '20220419I7292560','20220708','20230302',' Priority Partners',994.83
                    UNION ALL SELECT '20220313I5496334','20220627','20230302',' Priority Partners',7.44
                    UNION ALL SELECT '20220421I6196794','20220802','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220120I3571866','20220712','20230302',' Priority Partners',523.81
                    UNION ALL SELECT '20220408I5876134','20220719','20230302',' Priority Partners',518.92
                    UNION ALL SELECT '01052022I4855510','20220523','20230302',' Priority Partners',55.07
                    UNION ALL SELECT '20211226I3244160','20220315','20230302',' Priority Partners',61.1
                    UNION ALL SELECT '20220711I8819384','20220913','20230302',' Priority Partners',87.61
                    UNION ALL SELECT '20201220H5901642','20220614','20230302',' Priority Partners',161.78
                    UNION ALL SELECT '20220309I6864538','20220712','20230302',' Priority Partners',765.66
                    UNION ALL SELECT '20211224I6296590','20220621','20230302',' Priority Partners',2047.18
                    UNION ALL SELECT '20220706I8216784','20220831','20230302',' Priority Partners',75.61
                    UNION ALL SELECT '20220428I6556104','20220524','20230302',' Priority Partners',2411.74
                    UNION ALL SELECT '20220104I7247488','20220808','20230302',' Priority Partners',87.79
                    UNION ALL SELECT '20220706I8262280','20220920','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20220409I5876178','20220720','20230302',' Priority Partners',47.36
                    UNION ALL SELECT '20220614I7724530','20220914','20230302',' Priority Partners',589.98
                    UNION ALL SELECT '20220614I7906308','20220913','20230302',' Priority Partners',55.2
                    UNION ALL SELECT '05312022I7569664','20220705','20230302',' Priority Partners',4845.31
                    UNION ALL SELECT '20211206I3154858','20220706','20230302',' Priority Partners',18.56
                    UNION ALL SELECT '20201201H1414688','20220614','20230302',' Priority Partners',45.12
                    UNION ALL SELECT '20220123I6175163','20220811','20230302',' Priority Partners',639.09
                    UNION ALL SELECT '20190816G2247570','20220404','20230302',' Priority Partners',84.95
                    UNION ALL SELECT '20220324I5461394','20220621','20230302',' Priority Partners',1453.6
                    UNION ALL SELECT '20200114G4236744','20220614','20230302',' Priority Partners',192.31
                    UNION ALL SELECT '20220322I5260980','20220923','20230302',' Priority Partners',120.61
                    UNION ALL SELECT '20220322I5260346','20221012','20230302',' Priority Partners',137.84
                    UNION ALL SELECT '20220127I4217084','20220908','20230302',' Priority Partners',29.33
                    UNION ALL SELECT '20220719I9036096','20220914','20230302',' Priority Partners',1711.68
                    UNION ALL SELECT '20220808I9129720','20221003','20230302',' Priority Partners',327.37
                    UNION ALL SELECT '20220619I7911156','20220808','20230302',' Priority Partners',1424.19
                    UNION ALL SELECT '20220202I5943832','20220830','20230302',' Priority Partners',32.09
                    UNION ALL SELECT '20211201I2032236','20220801','20230302',' Priority Partners',1556.31
                    UNION ALL SELECT '20220418I6963722','20220805','20230302',' Priority Partners',3
                    UNION ALL SELECT '20220524I7070580','20220826','20230302',' Priority Partners',109.4
                    UNION ALL SELECT '20220502I6594848','20220628','20230302',' Priority Partners',29.21
                    UNION ALL SELECT '20220504I6665418','20220803','20230302',' Priority Partners',242.62
                    UNION ALL SELECT '20220713I8524768','20220908','20230302',' Priority Partners',165.99
                    UNION ALL SELECT '20220301I4743978','20220607','20230302',' Priority Partners',104.06
                    UNION ALL SELECT '20211020I3279392','20220811','20230302',' Priority Partners',49.87
                    UNION ALL SELECT '20220321I8182812','20220914','20230302',' Priority Partners',175.72
                    UNION ALL SELECT '20210520H9437406','20220908','20230302',' Priority Partners',218.85
                    UNION ALL SELECT '20200401G6968276','20220707','20230302',' Priority Partners',51.29
                    UNION ALL SELECT '20220413I6027160','20220627','20230302',' Priority Partners',46.85
                    UNION ALL SELECT '20210509H6274472','20220502','20230302',' Priority Partners',1179.88
                    UNION ALL SELECT '20191001G0600794','20220621','20230302',' Priority Partners',453.4
                    UNION ALL SELECT '20220331I5531568','20220825','20230302',' Priority Partners',77.2
                    UNION ALL SELECT '20220606I7974732','20220826','20230302',' Priority Partners',119.47
                    UNION ALL SELECT '20200810H7133938','20220425','20230302',' Priority Partners',1671.44
                    UNION ALL SELECT '20220505I6532946','20220712','20230302',' Priority Partners',136.02
                    UNION ALL SELECT '20220507I6915302','20220621','20230302',' Priority Partners',1598.95
                    UNION ALL SELECT '20220508I7569012','20220810','20230302',' Priority Partners',76.2
                    UNION ALL SELECT '20200515G6963572','20221005','20230302',' Priority Partners',40
                    UNION ALL SELECT '20220318I6431464','20220629','20230302',' Priority Partners',46.49
                    UNION ALL SELECT '20220621I8172656','20220919','20230302',' Priority Partners',266.68
                    UNION ALL SELECT '20201013G9817262','20220524','20230302',' Priority Partners',571.69
                    UNION ALL SELECT '20220604I7942874','20220914','20230302',' Priority Partners',221.52
                    UNION ALL SELECT '20220330I7565540','20220808','20230302',' Priority Partners',786.44
                    UNION ALL SELECT '20220331I7523354','20220830','20230302',' Priority Partners',105.19
                    UNION ALL SELECT '20210317H4123170','20220831','20230302',' Priority Partners',287.3
                    UNION ALL SELECT '20220102I3896316','20220921','20230302',' Priority Partners',25.27
                    UNION ALL SELECT '20210925I0408656','20220808','20230302',' Priority Partners',1205.66
                    UNION ALL SELECT '20210912I2537690','20220714','20230302',' Priority Partners',50
                    UNION ALL SELECT '20210929I1070902','20220712','20230302',' Priority Partners',884.88
                    UNION ALL SELECT '20220624I8023264','20220817','20230302',' Priority Partners',2069.83
                    UNION ALL SELECT '20220401I6826102','20220627','20230302',' Priority Partners',40.09
                    UNION ALL SELECT '20220321I8182490','20220914','20230302',' Priority Partners',247.14
                    UNION ALL SELECT '20211201I2787554','20220627','20230302',' Priority Partners',86.95
                    UNION ALL SELECT '20220420I7282096','20220720','20230302',' Priority Partners',26.77
                    UNION ALL SELECT '20210918I7796638','20220810','20230302',' Priority Partners',14626.23
                    UNION ALL SELECT '20211129I6556274','20220628','20230302',' Priority Partners',98.61
                    UNION ALL SELECT '20220203I3876618','20220810','20230302',' Priority Partners',9.81
                    UNION ALL SELECT '20220614I8684602','20220909','20230302',' Priority Partners',23.93
                    UNION ALL SELECT '20220313I6874886','20220721','20230302',' Priority Partners',1021.89
                    UNION ALL SELECT '20210706H7542086','20220502','20230302',' Priority Partners',2236.87
                    UNION ALL SELECT '20220714I8394728','20220929','20230302',' Priority Partners',108.61
                    UNION ALL SELECT '12142021I4382824','20220601','20230302',' Priority Partners',93.24
                    UNION ALL SELECT '20220522I7195542','20220621','20230302',' Priority Partners',1223.81
                    UNION ALL SELECT '20210815I1976370','20220628','20230302',' Priority Partners',15.18
                    UNION ALL SELECT '20220330I5636820','20220628','20230302',' Priority Partners',189.92
                    UNION ALL SELECT '20210713H9015042','20220919','20230302',' Priority Partners',92.09
                    UNION ALL SELECT '20200824H1732386','20220628','20230302',' Priority Partners',18.51
                    UNION ALL SELECT '20210518H6668626','20220502','20230302',' Priority Partners',1419.74
                    UNION ALL SELECT '20220512I6710058','20220713','20230302',' Priority Partners',169.09
                    UNION ALL SELECT '20210915H9951236','20220502','20230302',' Priority Partners',2337.38
                    UNION ALL SELECT '20210907H9258970','20220502','20230302',' Priority Partners',2225.4
                    UNION ALL SELECT '20220208I4314984','20220323','20230302',' Priority Partners',509.32
                    UNION ALL SELECT '20220725I8683090','20220929','20230302',' Priority Partners',75.61
                    UNION ALL SELECT '20210630H7259462','20220502','20230302',' Priority Partners',1108.67
                    UNION ALL SELECT '20220713I8361416','20220919','20230302',' Priority Partners',156.18
                    UNION ALL SELECT '20210624H7135028','20220516','20230302',' Priority Partners',653.7
                    UNION ALL SELECT '20210720H8879210','20220502','20230302',' Priority Partners',1753.36
                    UNION ALL SELECT '20210321H4859350','20220511','20230302',' Priority Partners',940.04
                    UNION ALL SELECT '20220608I7527204','20220920','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20220519I6934208','20220719','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '20220421I8169808','20220913','20230302',' Priority Partners',3.86
                    UNION ALL SELECT '20220617I7827744','20220721','20230302',' Priority Partners',37.34
                    UNION ALL SELECT '20220318I5549548','20221011','20230302',' Priority Partners',11.73
                    UNION ALL SELECT '20220718I8495062','20220921','20230302',' Priority Partners',113.74
                    UNION ALL SELECT '20200901G8705816','20220502','20230302',' Priority Partners',1180.29
                    UNION ALL SELECT '20211128I1802618','20220506','20230302',' Priority Partners',407.82
                    UNION ALL SELECT '20220122I3512274','20220727','20230302',' Priority Partners',771.08
                    UNION ALL SELECT '20220117I3389850','20220613','20230302',' Priority Partners',1372.89
                    UNION ALL SELECT '20220315I5161664','20220711','20230302',' Priority Partners',825.33
                    UNION ALL SELECT '20220201I3835792','20220727','20230302',' Priority Partners',294.01
                    UNION ALL SELECT '03292022I5594624','20220810','20230302',' Priority Partners',1057.96
                    UNION ALL SELECT '20211129I1700204','20220718','20230302',' Priority Partners',122.12
                    UNION ALL SELECT '20220527I7376752','20220624','20230302',' Priority Partners',49.76
                    UNION ALL SELECT '20210514H5870676','20220908','20230302',' Priority Partners',192.14
                    UNION ALL SELECT '20220506I6665580','20220722','20230302',' Priority Partners',166.34
                    UNION ALL SELECT '20220316I5632430','20220623','20230302',' Priority Partners',776.7
                    UNION ALL SELECT '20220417I6597526','20220726','20230302',' Priority Partners',8980.92
                    UNION ALL SELECT '20190720F8159980','20220914','20230302',' Priority Partners',177.94
                    UNION ALL SELECT '20210303H4202880','20220511','20230302',' Priority Partners',827.41
                    UNION ALL SELECT '20220616I7669668','20220826','20230302',' Priority Partners',186.29
                    UNION ALL SELECT '20220211I6262476','20220909','20230302',' Priority Partners',61.26
                    UNION ALL SELECT '20211008I0318718','20220817','20230302',' Priority Partners',212.14
                    UNION ALL SELECT '20211201I4992110','20220518','20230302',' Priority Partners',244.11
                    UNION ALL SELECT '20220208I5843642','20220927','20230302',' Priority Partners',23.08
                    UNION ALL SELECT '20210723I0442780','20220603','20230302',' Priority Partners',1458.05
                    UNION ALL SELECT '20220522I7450280','20220810','20230302',' Priority Partners',13.32
                    UNION ALL SELECT '20210611H6876380','20220628','20230302',' Priority Partners',36.74
                    UNION ALL SELECT '20200812G8199882','20220614','20230302',' Priority Partners',219.47
                    UNION ALL SELECT '20210526H6253510','20220810','20230302',' Priority Partners',7.07
                    UNION ALL SELECT '07162022I8916786','20220830','20230302',' Priority Partners',7281.34
                    UNION ALL SELECT '20220712I8721018','20220817','20230302',' Priority Partners',981.55
                    UNION ALL SELECT '20210801H8178324','20220628','20230302',' Priority Partners',114.73
                    UNION ALL SELECT '20210808H8314454','20220712','20230302',' Priority Partners',340.22
                    UNION ALL SELECT '20201230H2191120','20220511','20230302',' Priority Partners',878.78
                    UNION ALL SELECT '20220517I7523680','20220628','20230302',' Priority Partners',16.9
                    UNION ALL SELECT '20190703F7793732','20220614','20230302',' Priority Partners',74.91
                    UNION ALL SELECT '20220131I6704766','20220826','20230302',' Priority Partners',278.77
                    UNION ALL SELECT '20211209I2122470','20220613','20230302',' Priority Partners',98.62
                    UNION ALL SELECT '20220627I8777810','20220914','20230302',' Priority Partners',1067.72
                    UNION ALL SELECT '20220707I8368626','20220808','20230302',' Priority Partners',1488.86
                    UNION ALL SELECT '20170803D8697236','20220131','20230302',' Priority Partners',13843.39
                    UNION ALL SELECT '20210803H8352378','20220502','20230302',' Priority Partners',3123.31
                    UNION ALL SELECT '20220307I5742254','20220502','20230302',' Priority Partners',133.15
                    UNION ALL SELECT '20220516I7075256','20220803','20230302',' Priority Partners',4.86
                    UNION ALL SELECT '20220526I7197540','20220927','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20211026I0839888','20220808','20230302',' Priority Partners',1326.72
                    UNION ALL SELECT '02282022I4749276','20220811','20230302',' Priority Partners',465.38
                    UNION ALL SELECT '20220323I5290284','20220909','20230302',' Priority Partners',109.75
                    UNION ALL SELECT '20220417I6396704','20220630','20230302',' Priority Partners',883.55
                    UNION ALL SELECT '20220128I7907226','20220808','20230302',' Priority Partners',90.51
                    UNION ALL SELECT '20220825I9552686','20221028','20230302',' Priority Partners',156.18
                    UNION ALL SELECT '20210629I0662124','20221012','20230302',' Priority Partners',227.46
                    UNION ALL SELECT '20220601I7677106','20220721','20230302',' Priority Partners',3.04
                    UNION ALL SELECT '20210722H8681952','20220808','20230302',' Priority Partners',1249.39
                    UNION ALL SELECT '20220216I4270268','20220713','20230302',' Priority Partners',276.9
                    UNION ALL SELECT '20200912G9395146','20220705','20230302',' Priority Partners',479.7
                    UNION ALL SELECT '20220612I8021502','20220810','20230302',' Priority Partners',147.15
                    UNION ALL SELECT '20220106I6431332','20220818','20230302',' Priority Partners',258.2
                    UNION ALL SELECT '20220728I8789568','20221003','20230302',' Priority Partners',101.53
                    UNION ALL SELECT '20220106I4773810','20220922','20230302',' Priority Partners',192.5
                    UNION ALL SELECT '20211216I7146170','20220810','20230302',' Priority Partners',102.92
                    UNION ALL SELECT '20210610I2349396','20221011','20230302',' Priority Partners',10
                    UNION ALL SELECT '20220619I8375896','20220808','20230302',' Priority Partners',19.64
                    UNION ALL SELECT '20210323H4303126','20220630','20230302',' Priority Partners',34.26
                    UNION ALL SELECT '20220124I3381144','20221011','20230302',' Priority Partners',130.48
                    UNION ALL SELECT '20220315I5247030','20220429','20230302',' Priority Partners',1083.26
                    UNION ALL SELECT '20200321G7756524','20210928','20230302',' Priority Partners',413.45
                    UNION ALL SELECT '20220501I6593462','20220725','20230302',' Priority Partners',223.18
                    UNION ALL SELECT '20220327I6594912','20220826','20230302',' Priority Partners',634.02
                    UNION ALL SELECT '20220125I3540136','20220901','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220630I8053336','20220929','20230302',' Priority Partners',108.04
                    UNION ALL SELECT '20220306I6944342','20220630','20230302',' Priority Partners',58.68
                    UNION ALL SELECT '20211117I1893578','20220826','20230302',' Priority Partners',226.13
                    UNION ALL SELECT '20210504H6339416','20221011','20230302',' Priority Partners',20
                    UNION ALL SELECT '20220831I9756692','20221031','20230302',' Priority Partners',231.34
                    UNION ALL SELECT '20220412I5831064','20220808','20230302',' Priority Partners',108.04
                    UNION ALL SELECT '20220505I6756466','20220623','20230302',' Priority Partners',273.65
                    UNION ALL SELECT '20220811I9182608','20221012','20230302',' Priority Partners',40.08
                    UNION ALL SELECT '20220811I9182608','20221024','20230302',' Priority Partners',40.08
                    UNION ALL SELECT '20220602I7374726','20221028','20230302',' Priority Partners',94.35
                    UNION ALL SELECT '20220707I8316268','20220808','20230302',' Priority Partners',38.94
                    UNION ALL SELECT '20220519I7784032','20221019','20230302',' Priority Partners',103.09
                    UNION ALL SELECT '20211209I2464925','20220404','20230302',' Priority Partners',959.9
                    UNION ALL SELECT '20220505I7523726','20220725','20230302',' Priority Partners',600.05
                    UNION ALL SELECT '20220603I7981692','20220822','20230302',' Priority Partners',665.46
                    UNION ALL SELECT '20211119I6661988','20220725','20230302',' Priority Partners',113.7
                    UNION ALL SELECT '20210329H4381516','20220802','20230302',' Priority Partners',131.77
                    UNION ALL SELECT '20220325I5425690','20220920','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20211126I1802554','20221017','20230302',' Priority Partners',46.08
                    UNION ALL SELECT '20220506I7292670','20220727','20230302',' Priority Partners',148.7
                    UNION ALL SELECT '20210722H9617496','20220914','20230302',' Priority Partners',838.08
                    UNION ALL SELECT '20220210I3992388','20221011','20230302',' Priority Partners',1.49
                    UNION ALL SELECT '20220607I7523506','20220721','20230302',' Priority Partners',3004.77
                    UNION ALL SELECT '20220310I7564748','20220628','20230302',' Priority Partners',12.34
                    UNION ALL SELECT '20220311I7624332','20220721','20230302',' Priority Partners',22.87
                    UNION ALL SELECT '20220709I8256394','20220928','20230302',' Priority Partners',108.61
                    UNION ALL SELECT '20220608I7563570','20220804','20230302',' Priority Partners',63.08
                    UNION ALL SELECT '20220113I5707938','20220921','20230302',' Priority Partners',789.93
                    UNION ALL SELECT '20220518I7480244','20220628','20230302',' Priority Partners',15.11
                    UNION ALL SELECT '20220128I4744350','20220721','20230302',' Priority Partners',7.87
                    UNION ALL SELECT '20220603I7480074','20220805','20230302',' Priority Partners',608.6
                    UNION ALL SELECT '04012022I5707830','20220609','20230302',' Priority Partners',3401.45
                    UNION ALL SELECT '20220522I9783312','20221006','20230302',' Priority Partners',839.25
                    UNION ALL SELECT '20210414H5091876','20221006','20230302',' Priority Partners',132.48
                    UNION ALL SELECT '20220517I7043034','20220726','20230302',' Priority Partners',787.5
                    UNION ALL SELECT '01252022I3619500','20220609','20230302',' Priority Partners',220.25
                    UNION ALL SELECT '20220222I4498644','20220609','20230302',' Priority Partners',173.46
                    UNION ALL SELECT '08012022I9058906','20220921','20230302',' Priority Partners',1052.07
                    UNION ALL SELECT '20220125I3750888','20220808','20230302',' Priority Partners',1665.06
                    UNION ALL SELECT '20220624I7886250','20220810','20230302',' Priority Partners',67.19
                    UNION ALL SELECT '20210302H3592098','20220719','20230302',' Priority Partners',117.65
                    UNION ALL SELECT '20200103G4245564','20220822','20230302',' Priority Partners',62.03
                    UNION ALL SELECT '20220811I9169114','20221017','20230302',' Priority Partners',41.22
                    UNION ALL SELECT '20200501G6163106','20220516','20230302',' Priority Partners',603.25
                    UNION ALL SELECT '20220812I9602470','20221014','20230302',' Priority Partners',630.58
                    UNION ALL SELECT '20220125I3452038','20220725','20230302',' Priority Partners',105.94
                    UNION ALL SELECT '20211122I2349264','20220217','20230302',' Priority Partners',50.83
                    UNION ALL SELECT '06192022I8188276','20221007','20230302',' Priority Partners',98.44
                    UNION ALL SELECT '20220719I8625696','20221018','20230302',' Priority Partners',130.68
                    UNION ALL SELECT '20220311I6911300','20220628','20230302',' Priority Partners',802.78
                    UNION ALL SELECT '20220811I9403260','20220908','20230302',' Priority Partners',971.03
                    UNION ALL SELECT '20200904H9675762','20220615','20230302',' Priority Partners',115.51
                    UNION ALL SELECT '20191226G2738698','20220831','20230302',' Priority Partners',119.04
                    UNION ALL SELECT '20191226G2738702','20220831','20230302',' Priority Partners',7.62
                    UNION ALL SELECT '20220131I8255750','20220830','20230302',' Priority Partners',494.9
                    UNION ALL SELECT '20220714I8441836','20221028','20230302',' Priority Partners',107.59
                    UNION ALL SELECT '20220722I8819438','20220927','20230302',' Priority Partners',1204.07
                    UNION ALL SELECT '20220702I9149388','20220927','20230302',' Priority Partners',69.99
                    UNION ALL SELECT '20220718I8495570','20220912','20230302',' Priority Partners',98.58
                    UNION ALL SELECT '20220725I8681770','20220915','20230302',' Priority Partners',98.58
                    UNION ALL SELECT '20210518H6668650','20220524','20230302',' Priority Partners',239.86
                    UNION ALL SELECT '20210407H4735846','20211117','20230302',' Priority Partners',57.82
                    UNION ALL SELECT '20210721H7872670','20220524','20230302',' Priority Partners',1194.06
                    UNION ALL SELECT '20210623H7134996','20220524','20230302',' Priority Partners',325.8
                    UNION ALL SELECT '20220519I7117290','20220801','20230302',' Priority Partners',1747.47
                    UNION ALL SELECT '20220818I9552680','20221025','20230302',' Priority Partners',156.18
                    UNION ALL SELECT '20220622I8353120','20220928','20230302',' Priority Partners',1127.24
                    UNION ALL SELECT '20220621I8963532','20220928','20230302',' Priority Partners',745.13
                    UNION ALL SELECT '20220601I7569666','20220705','20230302',' Priority Partners',1174.62
                    UNION ALL SELECT '20210330H4603698','20220516','20230302',' Priority Partners',700.18
                    UNION ALL SELECT '20220818I9357894','20221025','20230302',' Priority Partners',104.86
                    UNION ALL SELECT '20220818I9357886','20221025','20230302',' Priority Partners',104.86
                    UNION ALL SELECT '20190718G2046130','20220817','20230302',' Priority Partners',5.84
                    UNION ALL SELECT '20220406I5798838','20220816','20230302',' Priority Partners',359.45
                    UNION ALL SELECT '05132022I7292548','20220823','20230302',' Priority Partners',934.7
                    UNION ALL SELECT '03132020I0530572','20211108','20230302',' Priority Partners',1890
                    UNION ALL SELECT '20220330I6536658','20220908','20230302',' Priority Partners',130.48
                    UNION ALL SELECT '20200828G8840484','20220511','20230302',' Priority Partners',810.22
                    UNION ALL SELECT '20220816I9290856','20221017','20230302',' Priority Partners',111.73
                    UNION ALL SELECT '20220711I8287988','20220923','20230302',' Priority Partners',126.88
                    UNION ALL SELECT '20220116I5707808','20220629','20230302',' Priority Partners',24.42
                    UNION ALL SELECT '20220124I5037560','20220328','20230302',' Priority Partners',2619.75
                    UNION ALL SELECT '20220419I7720704','20220824','20230302',' Priority Partners',1666.11
                    UNION ALL SELECT '20220624I8191304','20220817','20230302',' Priority Partners',858.03
                    UNION ALL SELECT '20220209I5390300','20221011','20230302',' Priority Partners',223.14
                    UNION ALL SELECT '20220601I7413708','20220726','20230302',' Priority Partners',362.62
                    UNION ALL SELECT '20210801H8549284','20220524','20230302',' Priority Partners',2537.38
                    UNION ALL SELECT '20220627I8150134','20220921','20230302',' Priority Partners',662.1
                    UNION ALL SELECT '20220331I6697084','20220927','20230302',' Priority Partners',54.13
                    UNION ALL SELECT '12042021I2790266','20220705','20230302',' Priority Partners',374.05
                    UNION ALL SELECT '20220608I7720734','20220816','20230302',' Priority Partners',54.18
                    UNION ALL SELECT '20220804I9000142','20221011','20230302',' Priority Partners',41.22
                    UNION ALL SELECT '20220317I5281558','20221011','20230302',' Priority Partners',125.43
                    UNION ALL SELECT '20220403I5908784','20220725','20230302',' Priority Partners',206.92
                    UNION ALL SELECT '20220226I8438904','20220927','20230302',' Priority Partners',64.01
                    UNION ALL SELECT '20220215I4262765','20220613','20230302',' Priority Partners',15446.97
                    UNION ALL SELECT '20220510I9352868','20221108','20230302',' Priority Partners',110.55
                    UNION ALL SELECT '20210130H2999266','20220511','20230302',' Priority Partners',912.2
                    UNION ALL SELECT '20220705I8598274','20220922','20230302',' Priority Partners',178.82
                    UNION ALL SELECT '20201127H1478398','20220511','20230302',' Priority Partners',747.92
                    UNION ALL SELECT '20220507I7258040','20220622','20230302',' Priority Partners',241.19
                    UNION ALL SELECT '20220616I8021128','20220817','20230302',' Priority Partners',336.87
                    UNION ALL SELECT '20220408I5998874','20220808','20230302',' Priority Partners',1116.06
                    UNION ALL SELECT '20211119I2451658','20220628','20230302',' Priority Partners',77.56
                    UNION ALL SELECT '20220421I6592800','20221025','20230302',' Priority Partners',99.18
                    UNION ALL SELECT '20210913H9297194','20220804','20230302',' Priority Partners',122.12
                    UNION ALL SELECT '20201025H0112778','20220804','20230302',' Priority Partners',63.05
                    UNION ALL SELECT '20220104I8353572','20220826','20230302',' Priority Partners',236.09
                    UNION ALL SELECT '20220222I6536530','20220909','20230302',' Priority Partners',99.27
                    UNION ALL SELECT '20220414I6086160','20220926','20230302',' Priority Partners',119.47
                    UNION ALL SELECT '20220627I8180762','20220808','20230302',' Priority Partners',37.34
                    UNION ALL SELECT '20210623H7112248','20220524','20230302',' Priority Partners',1119.43
                    UNION ALL SELECT '20220216I4688792','20220705','20230302',' Priority Partners',382.47
                    UNION ALL SELECT '20220417I6178214','20220714','20230302',' Priority Partners',24.52
                    UNION ALL SELECT '20220725I8682072','20220919','20230302',' Priority Partners',71.65
                    UNION ALL SELECT '20220810I9171030','20221018','20230302',' Priority Partners',8.86
                    UNION ALL SELECT '20220509I6958770','20220715','20230302',' Priority Partners',1257.01
                    UNION ALL SELECT '20220518I6906294','20220719','20230302',' Priority Partners',184.74
                    UNION ALL SELECT '20220107I8169932','20221010','20230302',' Priority Partners',50.43
                    UNION ALL SELECT '20220801I9828760','20221004','20230302',' Priority Partners',6.71
                    UNION ALL SELECT '20220323I9828970','20221004','20230302',' Priority Partners',5.68
                    UNION ALL SELECT '20210827H8890232','20220628','20230302',' Priority Partners',958.12
                    UNION ALL SELECT '20211227I5508244','20221006','20230302',' Priority Partners',63.75
                    UNION ALL SELECT '20220717I8782748','20221021','20230302',' Priority Partners',941.93
                    UNION ALL SELECT '20211030I5154142','20220629','20230302',' Priority Partners',151.29
                    UNION ALL SELECT '20220511I9577658','20221021','20230302',' Priority Partners',194.5
                    UNION ALL SELECT '20220602I7758590','20221011','20230302',' Priority Partners',827.44
                    UNION ALL SELECT '20220113I8182254','20220816','20230302',' Priority Partners',131.67
                    UNION ALL SELECT '20220308I5659096','20220926','20230302',' Priority Partners',76.91
                    UNION ALL SELECT '20211102I3017840','20220616','20230302',' Priority Partners',9.84
                    UNION ALL SELECT '20220506I7748296','20220712','20230302',' Priority Partners',9236.63
                    UNION ALL SELECT '20220801I8982870','20220920','20230302',' Priority Partners',138.45
                    UNION ALL SELECT '20220703I8149580','20221108','20230302',' Priority Partners',124.37
                    UNION ALL SELECT '20210626H8178280','20220826','20230302',' Priority Partners',76796.74
                    UNION ALL SELECT '20220518I6906300','20220718','20230302',' Priority Partners',146.11
                    UNION ALL SELECT '20210323H4301078','20221013','20230302',' Priority Partners',454.54
                    UNION ALL SELECT '20220819I9757494','20221026','20230302',' Priority Partners',108.61
                    UNION ALL SELECT '20210713H8310788','20220629','20230302',' Priority Partners',26
                    UNION ALL SELECT '20210912I0221402','20220628','20230302',' Priority Partners',10.42
                    UNION ALL SELECT '20220514I7260578','20220810','20230302',' Priority Partners',3.56
                    UNION ALL SELECT '03242020G5300516','20220303','20230302',' Priority Partners',14268.28
                    UNION ALL SELECT '20220607I7402916','20220808','20230302',' Priority Partners',130.48
                    UNION ALL SELECT '20220116I5343142','20220615','20230302',' Priority Partners',1335.69
                    UNION ALL SELECT '20220328I5598268','20220810','20230302',' Priority Partners',4072.54
                    UNION ALL SELECT '20210802I0445716','20221013','20230302',' Priority Partners',987.9
                    UNION ALL SELECT '20220510I9464714','20220920','20230302',' Priority Partners',120.55
                    UNION ALL SELECT '20220307I4967532','20220705','20230302',' Priority Partners',401.54
                    UNION ALL SELECT '20220605I7758804','20220725','20230302',' Priority Partners',99.85
                    UNION ALL SELECT '20220620I7756012','20220830','20230302',' Priority Partners',104.33
                    UNION ALL SELECT '20220503I6434144','20220720','20230302',' Priority Partners',130.48
                    UNION ALL SELECT '20220311I4899148','20220803','20230302',' Priority Partners',130.48
                    UNION ALL SELECT '20211102I1588146','20220516','20230302',' Priority Partners',539.86
                    UNION ALL SELECT '20211228I4960374','20220628','20230302',' Priority Partners',21.43
                    UNION ALL SELECT '20220718I9195922','20221012','20230302',' Priority Partners',275.68
                    UNION ALL SELECT '20220406I6836464','20220616','20230302',' Priority Partners',2.36
                    UNION ALL SELECT '20220301I8587638','20220922','20230302',' Priority Partners',669.8
                    UNION ALL SELECT '20220317I8915530','20220916','20230302',' Priority Partners',152.08
                    UNION ALL SELECT '20220721I8684210','20221108','20230302',' Priority Partners',21.15
                    UNION ALL SELECT '20220321I5429090','20220902','20230302',' Priority Partners',73.4
                    UNION ALL SELECT '20220321I5387302','20220902','20230302',' Priority Partners',73.4
                    UNION ALL SELECT '20220805I9049234','20221017','20230302',' Priority Partners',138.61
                    UNION ALL SELECT '20211215I2714812','20220627','20230302',' Priority Partners',1098.47
                    UNION ALL SELECT '20220321I8054910','20220808','20230302',' Priority Partners',2.86
                    UNION ALL SELECT '20220321I8257082','20220808','20230302',' Priority Partners',5.35
                    UNION ALL SELECT '20210721H9142744','20220714','20230302',' Priority Partners',73.47
                    UNION ALL SELECT '20220211I7598730','20220824','20230302',' Priority Partners',2541
                    UNION ALL SELECT '20220211I4826848','20220824','20230302',' Priority Partners',945.28
                    UNION ALL SELECT '20220301I4552850','20220928','20230302',' Priority Partners',6.56
                    UNION ALL SELECT '20220524I7335106','20220628','20230302',' Priority Partners',1800.54
                    UNION ALL SELECT '20220524I7598732','20220628','20230302',' Priority Partners',75.94
                    UNION ALL SELECT '20200618G7082868','20220524','20230302',' Priority Partners',628.65
                    UNION ALL SELECT '20220203I7867334','20220817','20230302',' Priority Partners',87.17
                    UNION ALL SELECT '20210106I6266590','20220817','20230302',' Priority Partners',73.26
                    UNION ALL SELECT '20220221I4592380','20220922','20230302',' Priority Partners',46.32
                    UNION ALL SELECT '20220510I7257522','20220712','20230302',' Priority Partners',498.42
                    UNION ALL SELECT '20211229I2749860','20220927','20230302',' Priority Partners',23.08
                    UNION ALL SELECT '20210423H5688380','20220516','20230302',' Priority Partners',700.18
                    UNION ALL SELECT '20210131H3170874','20220311','20230302',' Priority Partners',1596.4
                    UNION ALL SELECT '20210825I0044722','20220627','20230302',' Priority Partners',481.9
                    UNION ALL SELECT '20211007I7282442','20220929','20230302',' Priority Partners',47.81
                    UNION ALL SELECT '20220419I6086224','20221004','20230302',' Priority Partners',2.77
                    UNION ALL SELECT '20220518I7115434','20220726','20230302',' Priority Partners',413.52
                    UNION ALL SELECT '20220608I7482702','20221020','20230302',' Priority Partners',23.28
                    UNION ALL SELECT '20220629I8152602','20220914','20230302',' Priority Partners',420.25
                    UNION ALL SELECT '20211012I2973026','20220616','20230302',' Priority Partners',1.75
                    UNION ALL SELECT '20210616H7140448','20220524','20230302',' Priority Partners',241.76
                    UNION ALL SELECT '20220418I8182736','20220930','20230302',' Priority Partners',143.62
                    UNION ALL SELECT '20200805H4383222','20220808','20230302',' Priority Partners',170.28
                    UNION ALL SELECT '20201019H0370832','20220524','20230302',' Priority Partners',253.81
                    UNION ALL SELECT '08272021H9055296','20220614','20230302',' Priority Partners',1675.75
                    UNION ALL SELECT '20211207I3240982','20220824','20230302',' Priority Partners',47.91
                    UNION ALL SELECT '20220331I8420600','20220914','20230302',' Priority Partners',277.96
                    UNION ALL SELECT '20220812I9208868','20221010','20230302',' Priority Partners',41.22
                    UNION ALL SELECT '20220322I5344442','20220713','20230302',' Priority Partners',301.82
                    UNION ALL SELECT '20220318I5245432','20220914','20230302',' Priority Partners',457.54
                    UNION ALL SELECT '20210518H6668678','20220524','20230302',' Priority Partners',479.71
                    UNION ALL SELECT '20220720I8779566','20220921','20230302',' Priority Partners',2166.63
                    UNION ALL SELECT '20220125I3619574','20220822','20230302',' Priority Partners',183
                    UNION ALL SELECT '20220728I8981388','20220908','20230302',' Priority Partners',794.91
                    UNION ALL SELECT '20220728I8783216','20221006','20230302',' Priority Partners',113.74
                    UNION ALL SELECT '20211214I4586622','20220811','20230302',' Priority Partners',486.09
                    UNION ALL SELECT '20220614I7756938','20220811','20230302',' Priority Partners',67.19
                    UNION ALL SELECT '20210630H7298248','20220927','20230302',' Priority Partners',6088.33
                    UNION ALL SELECT '20220620I7848342','20220902','20230302',' Priority Partners',122.12
                    UNION ALL SELECT '06252019G2046728','20211110','20230302',' Priority Partners',22.91
                    UNION ALL SELECT '20211228I2749886','20220927','20230302',' Priority Partners',23.08
                    UNION ALL SELECT '20220715I8916672','20221011','20230302',' Priority Partners',834.67
                    UNION ALL SELECT '20220804I9276272','20221020','20230302',' Priority Partners',1195.26
                    UNION ALL SELECT '20220722I8996594','20220927','20230302',' Priority Partners',13.8
                    UNION ALL SELECT '20220511I6915808','20220726','20230302',' Priority Partners',1356.39
                    UNION ALL SELECT '20211218I6874816','20220728','20230302',' Priority Partners',134.79
                    UNION ALL SELECT '04032022I5802746','20220726','20230302',' Priority Partners',1042.26
                    UNION ALL SELECT '20211228I5878594','20220817','20230302',' Priority Partners',147.16
                    UNION ALL SELECT '20220406I8182300','20220914','20230302',' Priority Partners',189.22
                    UNION ALL SELECT '20201009I6945956','20220713','20230302',' Priority Partners',358.84
                    UNION ALL SELECT '20220605I7686270','20220817','20230302',' Priority Partners',654.45
                    UNION ALL SELECT '20220215I7523678','20220629','20230302',' Priority Partners',9.33
                    UNION ALL SELECT '20220811I9210606','20221017','20230302',' Priority Partners',104.86
                    UNION ALL SELECT '06052021H7628306','20220628','20230302',' Priority Partners',46146.46
                    UNION ALL SELECT '20211030I0913702','20221003','20230302',' Priority Partners',78.35
                    UNION ALL SELECT '20220119I5496180','20220919','20230302',' Priority Partners',248.64
                    UNION ALL SELECT '01012017D3482516','20220512','20230302',' Priority Partners',1257.94
                    UNION ALL SELECT '10182021I1290156','20220609','20230302',' Priority Partners',195.77
                    UNION ALL SELECT '20210518H6021918','20220916','20230302',' Priority Partners',208.81
                    UNION ALL SELECT '20220706I8316146','20220805','20230302',' Priority Partners',1524.81
                    UNION ALL SELECT '20220403I6100732','20220623','20230302',' Priority Partners',11.53
                    UNION ALL SELECT '02012022I7248120','20220811','20230302',' Priority Partners',495
                    UNION ALL SELECT '20220606I7758710','20220822','20230302',' Priority Partners',378.41
                    UNION ALL SELECT '20220701I8427274','20220808','20230302',' Priority Partners',22.62
                    UNION ALL SELECT '20210916I6437716','20220810','20230302',' Priority Partners',48.72
                    UNION ALL SELECT '20211030I3341010','20220627','20230302',' Priority Partners',93.2
                    UNION ALL SELECT '20220522I7446474','20220629','20230302',' Priority Partners',209.6
                    UNION ALL SELECT '20210828H8927228','20220929','20230302',' Priority Partners',1205.95
                    UNION ALL SELECT '20220527I7888352','20221108','20230302',' Priority Partners',148.14
                    UNION ALL SELECT '20220302I6747352','20220629','20230302',' Priority Partners',355.86
                    UNION ALL SELECT '20211216I4781804','20220725','20230302',' Priority Partners',776.88
                    UNION ALL SELECT '20220510I6840316','20220920','20230302',' Priority Partners',103.38
                    UNION ALL SELECT '20220519I7551706','20220830','20230302',' Priority Partners',92.09
                    UNION ALL SELECT '20220214I4217548','20220920','20230302',' Priority Partners',92.09
                    UNION ALL SELECT '20220501I6911236','20220826','20230302',' Priority Partners',735.02
                    UNION ALL SELECT '20211006I0059662','20220831','20230302',' Priority Partners',264.05
                    UNION ALL SELECT '20220216I4144018','20220822','20230302',' Priority Partners',39.46
                    UNION ALL SELECT '20220101I4960364','20220629','20230302',' Priority Partners',7.33
                    UNION ALL SELECT '20211206I7623066','20220810','20230302',' Priority Partners',42.09
                    UNION ALL SELECT '20220818I9768682','20221103','20230302',' Priority Partners',210.23
                    UNION ALL SELECT '20220301I4662364','20220916','20230302',' Priority Partners',112.4
                    UNION ALL SELECT '20220214I7399248','20220805','20230302',' Priority Partners',2.61
                    UNION ALL SELECT '20220222I6504446','20220620','20230302',' Priority Partners',544.07
                    UNION ALL SELECT '20220205I5205798','20220711','20230302',' Priority Partners',332.83
                    UNION ALL SELECT '20220325I7565042','20220719','20230302',' Priority Partners',455.31
                    UNION ALL SELECT '20220328I5589338','20220818','20230302','Employee Health Plan',145.98
                    UNION ALL SELECT '20220328I5589338','20220818','20230302','Employee Health Plan',145.98
                    UNION ALL SELECT '20210917H9391846','20220202','20230302','Employee Health Plan',6.57
                    UNION ALL SELECT '20200922G9421768','20220824','20230302','Employee Health Plan',170.66
                    UNION ALL SELECT '20210719H7999212','20220708','20230302','Employee Health Plan',1532.2
                    UNION ALL SELECT '20190612F7302054','20220831','20230302','Employee Health Plan',345.16
                    UNION ALL SELECT '20220526I7136656','20220823','20230302','Employee Health Plan',672
                    UNION ALL SELECT '20220526I7137818','20220823','20230302','Employee Health Plan',672
                    UNION ALL SELECT '20220525I7110938','20220826','20230302','Employee Health Plan',11.83
                    UNION ALL SELECT '20210917H9895996','20220203','20230302','Employee Health Plan',157.64
                    UNION ALL SELECT '20210719H9123090','20220825','20230302','Employee Health Plan',453.01
                    UNION ALL SELECT '20220718I8680520','20220926','20230302','Employee Health Plan',167.19
                    UNION ALL SELECT '20220701I8147636','20220907','20230302','Employee Health Plan',55
                    UNION ALL SELECT '20180506E7116644','20220829','20230302','Employee Health Plan',171.62
                    UNION ALL SELECT '05082018E6218008','20220830','20230302','Employee Health Plan',154.46
                    UNION ALL SELECT '20180509E6256022','20220830','20230302','Employee Health Plan',154.46
                    UNION ALL SELECT '20210830I2598484','20220717','20230302','Employee Health Plan',10.16
                    UNION ALL SELECT '20210830I2598484','20220717','20230302','Employee Health Plan',10.16
                    UNION ALL SELECT '20210915H9296060','20220909','20230302','Employee Health Plan',11.21
                    UNION ALL SELECT '20220705I9851436','20221004','20230302','Employee Health Plan',11.85
                    UNION ALL SELECT '20190712F7915414','20220831','20230302','Employee Health Plan',306.17
                    UNION ALL SELECT '20220323I5382456','20220805','20230302','Employee Health Plan',964.01
                    UNION ALL SELECT '20220323I5382456','20220805','20230302','Employee Health Plan',964.01
                    UNION ALL SELECT '20220425I6216046','20220912','20230302','Employee Health Plan',343.18
                    UNION ALL SELECT '20210616H6904372','20220914','20230302','Employee Health Plan',6.57
                    UNION ALL SELECT '20220318I5287564','20220909','20230302','Employee Health Plan',424.74
                    UNION ALL SELECT '20211222I6928974','20220902','20230302','Employee Health Plan',40.65
                    UNION ALL SELECT '20220704I9878300','20220920','20230302','Employee Health Plan',117.02
                    UNION ALL SELECT '20210923H9643010','20221011','20230302','Employee Health Plan',6.57
                    UNION ALL SELECT '20210923H9644788','20221011','20230302','Employee Health Plan',6.57
                    UNION ALL SELECT '20211011I0616080','20220809','20230302','Employee Health Plan',309.88
                    UNION ALL SELECT '20211011I0616080','20220809','20230302','Employee Health Plan',309.88
                    UNION ALL SELECT '20220712I8390440','20220912','20230302','Employee Health Plan',332.88
                    UNION ALL SELECT '20220809I9094024','20221115','20230302','Employee Health Plan',135
                    UNION ALL SELECT '20220411I5995274','20220913','20230302','Employee Health Plan',267.61
                    UNION ALL SELECT '20220406I5663486','20220826','20230302','Employee Health Plan',236.97
                    UNION ALL SELECT '20220406I5663486','20220826','20230302','Employee Health Plan',236.97
                    UNION ALL SELECT '20210226H3430154','20221102','20230302','Employee Health Plan',151.97
                    UNION ALL SELECT '20220703I8147422','20220909','20230302','Employee Health Plan',258.45
                    UNION ALL SELECT '20220703I8147422','20220909','20230302','Employee Health Plan',258.45
                    UNION ALL SELECT '20220531I7222234','20220811','20230302','Employee Health Plan',91.76
                    UNION ALL SELECT '20220531I7222234','20220811','20230302','Employee Health Plan',91.76
                    UNION ALL SELECT '20211118I1576642','20220118','20230302','Employee Health Plan',143.05
                    UNION ALL SELECT '20220209I4503468','20220808','20230302','Employee Health Plan',218.28
                    UNION ALL SELECT '20220209I4503468','20220808','20230302','Employee Health Plan',218.28
                    UNION ALL SELECT '20220818I9383468','20221031','20230302','Employee Health Plan',20.88
                    UNION ALL SELECT '20210709H7338928','20221107','20230302','Employee Health Plan',144.58
                    UNION ALL SELECT '04132021H4965414','20220929','20230302','Employee Health Plan',267.8
                    UNION ALL SELECT '20220411I5834164','20220810','20230302','Employee Health Plan',13.31
                    UNION ALL SELECT '20220411I5834164','20220810','20230302','Employee Health Plan',13.31
                    UNION ALL SELECT '20200530H0120218','20221011','20230302','Employee Health Plan',367.37
                    UNION ALL SELECT '20210112H2819446','20221026','20230302','Employee Health Plan',5.66
                    UNION ALL SELECT '20210719H7741748','20220811','20230302','Employee Health Plan',299.13
                    UNION ALL SELECT '20210804I2111120','20220811','20230302','Employee Health Plan',320.41
                    UNION ALL SELECT '20210804I2111120','20220811','20230302','Employee Health Plan',320.41
                    UNION ALL SELECT '20210928H9717054','20221121','20230302','Employee Health Plan',137.94
                    UNION ALL SELECT '20210817H8463906','20221121','20230302','Employee Health Plan',65.89
                    UNION ALL SELECT '20220720I9001986','20221020','20230302','Employee Health Plan',206.55
                    UNION ALL SELECT '20220530I7589394','20220823','20230302','Employee Health Plan',182.88
                    UNION ALL SELECT '20220530I7589394','20220823','20230302','Employee Health Plan',182.88
                    UNION ALL SELECT '20220530I7484708','20221031','20230302','Employee Health Plan',258.84
                    UNION ALL SELECT '20220530I7511086','20221107','20230302','Employee Health Plan',127.32
                    UNION ALL SELECT '20220421I6592808','20221025','20230302','Employee Health Plan',138.21
                    UNION ALL SELECT '20220610I8177240','20221013','20230302','Employee Health Plan',120.66
                    UNION ALL SELECT '20220517I9022290','20221010','20230302','Employee Health Plan',15.54
                    UNION ALL SELECT '20220317I5496252','20220725','20230302','Employee Health Plan',1909.75
                    UNION ALL SELECT '20220317I5496252','20220725','20230302','Employee Health Plan',1909.75
                    UNION ALL SELECT '20201218H1475274','20221026','20230302','Employee Health Plan',162.6
                    UNION ALL SELECT '582232821','20220210','20230302','US Family Health Plan',874.95
                    UNION ALL SELECT '535382056','20220323','20230302','US Family Health Plan',54.42
                    UNION ALL SELECT '127061063','20220309','20230302','US Family Health Plan',247.32
                    UNION ALL SELECT '913218804','20220817','20230302','US Family Health Plan',6393.47
                    UNION ALL SELECT '224017400','20220511','20230302','US Family Health Plan',1636.33
                    UNION ALL SELECT '764023601','20220830','20230302','US Family Health Plan',1306.34
                    UNION ALL SELECT '955609375','20220608','20230302','US Family Health Plan',203.24
                    UNION ALL SELECT '748651229','20220511','20230302','US Family Health Plan',193.95
                    UNION ALL SELECT '336698016','20220713','20230302','US Family Health Plan',28.27
                    UNION ALL SELECT '527562078','20220511','20230302','US Family Health Plan',541.56











                    IF OBJECT_ID(N'tempdb..#baseclms') IS NOT NULL DROP TABLE #baseclms; 

                    select a.ClaimNbr, a.VendorFileDate, a.IdentifiedDate, a.lob as lob, sum(a.VendorAmt) as VendorAmt
                    into #BaseClms
                    from #BaseClms0 a 
                    where ClaimNbr <> '0000000000000000'
                    group by a.ClaimNbr, a.VendorFileDate,  a.IdentifiedDate, a.lob


                    IF OBJECT_ID(N'tempdb..#temp1') IS NOT NULL DROP TABLE #temp1;


                    select distinct a.ClaimNbr,bidwclaimnbr,lob.lineofbusinessname,IdentifiedDate,SourceOriginalClaimNbr, a.VendorFileDate, a.VendorAmt
                    into #temp1
                    from #Baseclms a
                    left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                    on right(a.claimnbr,8) = right(clm.sourceoriginalclaimnbr,8)
                    left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness] (nolock) lob
                    on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                    where lob.lineofbusinessname in ('pp','ehp','hep')
                    and SUBSTRING(SourceOriginalClaimNbr,9,1)  IN ('E','D','C','M','H','G','F','I')
                    and a.lob in ('Priority Partners','Employee Health Plan')

                    union
                    select distinct a.ClaimNbr,bidwclaimnbr,lob.lineofbusinessname,IdentifiedDate,SourceOriginalClaimNbr, a.VendorFileDate, a.VendorAmt
                    from #Baseclms a
                    left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                    on a.claimnbr = right(sourceoriginalclaimnbr,12) 
                    left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness] (nolock) lob
                    on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                    where lob.lineofbusinessname = 'MA'
                    AND NOT (SUBSTRING(SourceOriginalClaimNbr,9,1)  IN ('E','D','C','M','H','G','F','I'))
                    and a.LOB = 'Medicare Advantage'
                    union
                    select distinct a.ClaimNbr,bidwclaimnbr,lob.lineofbusinessname,IdentifiedDate,SourceOriginalClaimNbr, a.VendorFileDate, a.VendorAmt
                    from #Baseclms a
                    left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                    on left(a.claimnbr,9) = right(sourceoriginalclaimnbr,9) 
                    left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness] (nolock) lob
                    on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                    where lob.lineofbusinessname = 'USFHP'
                    AND NOT (SUBSTRING(SourceOriginalClaimNbr,9,1)  IN ('E','D','C','M','H','G','F','I'))
                    and a.LOB like '%US Family Health Plan%'


                    IF OBJECT_ID(N'tempdb..#temp2') IS NOT NULL DROP TABLE #temp2;

                    select a.ClaimNbr,	SK_Member,SK_ProviderBilling,SK_ProviderRendering,SK_AdmitDate,a.bidwclaimnbr,	IdentifiedDate, clm.SourceOriginalClaimNbr, a.VendorFileDate, a.VendorAmt,
                    a.lineofbusinessname,min(case when sk_checkdate = -1 and sk_appostdate = -1 then [SK_ClaimAddDate] when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end) as CheckDate_APPostDate
                    into #temp2
                    from #temp1 a
                    left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                    on a.bidwclaimnbr = clm.bidwclaimnbr
                    left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness] (nolock) lob
                    on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                    where paidamtactual <0
                    and case when sk_checkdate = -1 and sk_appostdate = -1 then [SK_ClaimAddDate] when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate  end > IdentifiedDate
                    group by a.ClaimNbr,	SK_Member,SK_ProviderBilling,SK_ProviderRendering,SK_AdmitDate,a.bidwclaimnbr, a.lineofbusinessname, 	IdentifiedDate, clm.SourceOriginalClaimNbr, a.VendorFileDate, a.VendorAmt,
                    case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end
       
                    IF OBJECT_ID(N'tempdb..#temp3') IS NOT NULL DROP TABLE #temp3;

                    select a.ClaimNbr as VendorClaimNbr, clm.SourceOriginalClaimNbr as EDWClaimNbr, a.bidwclaimnbr as EDW_BIDWClaimNbr,	a.LineOfBusinessName, a.IdentifiedDate, a.VendorFileDate, a.VendorAmt,
                    sum(paidamtactual) as PaidAmtActual, 
                    max(case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimlineadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate  end ) as RetractionDate
                    into #temp3
                    from #temp2 a
                    left join [JHHC_BIDW_PROD].clm.factclaim (nolock) clm
                    on a.ClaimNbr = clm.SourceOriginalClaimNbr
                    and a.SK_Member = clm.SK_Member
                    and a.SK_ProviderBilling = clm.SK_ProviderBilling
                    and a.SK_ProviderRendering = clm.SK_ProviderRendering
                    and a.SK_AdmitDate = clm.SK_AdmitDate
                    and clm.SK_LineStatus	in ('2','4','5','9')	
                    and case when sk_checkdate = -1 and sk_appostdate = -1 then sk_claimadddate when sk_checkdate = -1 and sk_appostdate <> -1 then sk_appostdate else sk_checkdate end >= CheckDate_APPostDate
                    left join [JHHC_BIDW_PROD].[MEM].[dimLineOfBusiness] (nolock) lob
                    on clm.sk_lineofbusiness = lob.sk_lineofbusiness
                    where paidamtactual < 0
                    and case when sk_checkdate = -1 then sk_appostdate else sk_checkdate end >= '20210215'
                    group by a.ClaimNbr, clm.SourceOriginalClaimNbr , a.bidwclaimnbr,a.lineofbusinessname, a.IdentifiedDate, a.VendorFileDate,  a.VendorAmt



                    select distinct a.IdentifiedDate, case when a.RetractionDate is null then '19000101' else a.RetractionDate end as RetractionDate, a.VendorFileDate as VendorFileDate,
                    a.VendorClaimNbr, a.EDWClaimNbr, a.EDW_BIDWClaimNbr, a.lineofbusinessname, a.PaidAmtActual, a.VendorAmt,
                    case when abs(isnull(a.PaidAmtActual,0) ) < a.VendorAmt then abs(isnull(a.PaidAmtActual,0)) else a.VendorAmt end as FinalAmt
                    from #temp3 a
                                            

                        
                        
                """ 

prod_datarow = prod_cursor.execute (prod_query)
prod_data    = prod_cursor.fetchall()
# print(prod_data)


dev_server = 'VMSQLDWBIDEV'
dev_db     = 'Sandbox_ConceptDevelopment'
dev_conn   = pyodbc.connect('DRIVER={SQL Server};SERVER=' + dev_server + ';DATABASE=' + dev_db + ';Trusted_Connection=yes')

#dev_query  = "select VendorName, VedorClaimNbr from [Sandbox_ConceptDevelopment].[dbo].[NM_PI_VendorRecoveries] where VendorFileDate = '" + strfiledate + "' and  VendorName = '""" + strVendorName + "'"

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
                VendorFileDate     = row[2]
                VendorClaimNbr     = row[3]
                EDWClaimNbr        = row[4]
                EDW_BIDWClaimNbr   = row[5]
                lineofbusinessname = row[6]
                EDW_PaidAmtActual  = row[7]
                VendorAmt          = row[8]
                FinalAmt           = row[9]
  
                
                dev_values = (VendorName, VendorFileName, VendorFileDate, ValidationDate,  IdentifiedDate, RetractionDate, VendorClaimNbr, EDWClaimNbr, EDW_BIDWClaimNbr, lineofbusinessname, EDW_PaidAmtActual, VendorAmt, FinalAmt)
                
                print(dev_values)
                dev_query =     """INSERT INTO dbo.NM_PI_VendorRecoveries 
                                (VendorName, VendorFileName, VendorFileDate, ValidationDate, IdentifiedDate, RetractionDate, VendorClaimNbr, 
                                 EDWClaimNbr, EDW_BIDWClaimNbr, lineofbusinessname, EDW_PaidAmtActual, VendorAmt, FinalAmt)
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

