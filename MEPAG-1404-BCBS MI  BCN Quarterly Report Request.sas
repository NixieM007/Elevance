
**************************************MEPAG-1377- Customer 13
*/;



proc sql;
connect to odbc as rs1 
      (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table W_OutreachableFlags as
select *
from connection to rs1 (

with
/* Determine members that are new to the plan each month and the date they were first scored */

newtoplan 
as 
	(
		select 
			m.customerid, ms.contractprofileid, ms.mcocontractid,
	       	ms.id as membershipid,
	       	ms.createddate as mship_createddt,
	       	min(msh.activedate) as date_scored
		from pre_pop.membership ms
		inner join mms_staging.member m
		    on ms.memberid = m.id
		left join mms_staging.membershipscorehistory msh
		    on ms.id = msh.membershipid
		    and ms.createddate <= msh.activedate
		where 1=1
		and ms.createddate between trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years')) and  add_months(date_trunc('month', CURRENT_DATE), -1)  
		and ms.mcocontractid in ('H9572', 'S5584') 
		and ms.contractprofileID in (238, 393, 8634)
		and m.customerid = 13
		group by m.customerid,contractprofileid, mcocontractid,
		    ms.Id,
		    ms.createddate
	)

, newtoplan_mm
as (
	select  np.customerid , epd.contractprofileid, epd.mcocontractid
		    , epd.membershipid
		    , np.mship_createddt
		    , np.date_scored
		    , coalesce(np.date_scored,np.mship_createddt ) as ReportStartingPoint
		    , min(epd.month) as Firstmembership_month


		from pre_pop.enrolled_population_detail epd
		inner join newtoplan np
		    on epd.membershipid = np.membershipid and epd.contractprofileid = np.contractprofileid and epd.mcocontractid = np.mcocontractid
		    and epd.month >= date_trunc('month',np.mship_createddt)
		where  
			epd.mcocontractid in ('H9572', 'S5584') 
			and  epd.contractprofileID in (238, 393, 8634)
			and np.customerid = 13
		group by np.customerid , epd.contractprofileid, epd.mcocontractid
		    , epd.membershipid
		    , np.mship_createddt
		    , np.date_scored

	)

/* Use pre_pop tables to determine outreach status, need to find corresponding earliest membership_month*/
select 	ms.score, ms.bucketid,
		case when ms.bucketid is null then 'Not Scored'
			 when ms.bucketid = 3 then 'High'
			 when ms.bucketid = 2 then 'Med' 
			 else 'Low' end as ReachScoreCat, 
        mm.* , trunc(date_trunc('month',trunc(ReportStartingPoint))) as  ReportStartingMonth

	 , case when trunc(date_trunc('month',trunc(ReportStartingPoint))) = Firstmembership_month then '' else 'WHY' end as MthDiscord

     , case when (deaF.f_msc_outreachable_init = 1 or f_msc_outreachable_reapp=1) then 'DEA Marketable' else 'DEA Not Marketable' end as DEA_MarketableFlag

     , case when (deaF.f_rc_eligible_first_recert_outr = 1 or f_rc_assisted_sub_recert_outr =1) then 'RC Marketable' else 'RC Not Marketable' end as RC_MarketableFlag


from newtoplan_mm mm
left join pre_pop.enrolled_population_detail epd
    on mm.membershipid = epd.membershipid and mm.Firstmembership_month = epd.month
left join me_pop.membership_score ms
	on mm.membershipid = ms.membershipid and trunc(date_trunc('month',trunc(mm.ReportStartingPoint))) = ms.membership_month
left join pre_pop.dea_population_flag deaF on deaF.id=epd.dea_population_flag_id
left join pre_pop.lis_population_flag lisF on lisF.id=epd.lis_population_flag_id
left join pre_pop.ca_population_flag caF on caF.id=epd.ca_population_flag_id


);
disconnect from rs1;
quit;


/*
     , case when lisF.f_lis_outreachable = 1 then 'LIS Marketable' else 'LIS Not Marketable' end as LIS_MarketableFlag
     , case when caf.cl_initial = 1 or caf.cl_retouch =1 then 'CA Offered' else 'CA Not Offered' end as CA_MarketableFlag
*/;


/* 
											proc sql;
											create table ___Anydups as
											select customerid, membershipid, count(*)
											from W_OutreachableFlags
											group by customerid, membershipid
											having count(*) >1;
											quit;
											* 0 dups;

proc sql;
create table ContractsInfo as
select contractprofileid, mcocontractid, count(distinct membershipid)
from W_OutreachableFlags
group by contractprofileid, mcocontractid;
quit; 



*/

/*MMS222*/
proc sql;
connect to odbc as rs1 
      (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table Pop_Exclusions as
select *
from connection to rs1 (
select ppm.id as membershipid, m.customerid,  ppm.isexcluded, p.isdeceased, coalesce(ppm.isdonotsolicit,ppm.isdonotcontact) as isdonotsolicit 
			, cms.hospiceIndicator, ppm.exclusionstatusid 
			, case when ppm.isexcluded = 1
	   	 			or p.isdeceased = 1
		 			or ppm.isdonotsolicit = true
		 			or ppm.isdonotcontact = true
		 			or cms.hospiceIndicator = 1
		 			or ppM.exclusionstatusid = 3
				 then 1 else 0 end as Exclusions_Flag
			 , ppm.mcocontractid
			 , ppm.contractprofileid
from pre_pop.membership ppm 
		left join mms_staging.member m
		on ppm.memberid = m.id
		left join mms_staging.person p
 		on m.personid = p.personid	
		left join mms_staging.cmsflags cms
		on ppm.id  = cms.membershipid
where  (	ppm.mcocontractid in ('H9572', 'S5584') 
			and  ppm.contractprofileID in (238, 393, 8634)
			and m.customerid = 13) 
			and (ppm.isexcluded = 1
	   	 			or p.isdeceased = 1
		 			or ppm.isdonotsolicit = true
		 			or ppm.isdonotcontact = true
		 			or cms.hospiceIndicator = 1
		 			or ppM.exclusionstatusid = 3)
		);
disconnect from rs1;
quit;

proc sql;
create table W2_OutreachableFlags as
select  b.Exclusions_Flag, b.isexcluded, b.isdeceased, b.isdonotsolicit, b.hospiceIndicator, b.exclusionstatusid , a.* 
from W_OutreachableFlags a left join Pop_Exclusions b
    on a.membershipid = b.membershipid and a.customerid = b.customerid and  a.contractprofileid = b.contractprofileid and a.mcocontractid = b.mcocontractid;
	quit;


/* ****************** Determine if a Good PHone or a DNC phone; */
proc sql;
connect to odbc (DSN='Medicare' user='SASUser' pwd='{sas002}D1E036445B7B103A24DA0C1527DCE088');
create table phonedata as
select distinct *
from connection to odbc 
(
with goodphone as (		
	SELECT distinct personid	
	FROM MMS.PersonPhone	
	WHERE (phonestatusid = 1 or phonestatusid = 2) and LEN(PhoneNumber) = 10	
	AND PhoneTypeID <> 6	
	)	
, 		
dncphone as		
(		
	SELECT distinct personid 
	FROM MMS.PersonPhone	
	WHERE (phonestatusid = 7 or phonestatusid = 8) and LEN(PhoneNumber) = 10	
	AND PhoneTypeID <> 6	
)		
		
select p.id, m.id as memberid, ms.ContractProfileID, ms.id as membershipid, c.[name] as customer, c.[id] as customerid, cp.[name] as contractProfile		
	, case when g.personid is not null then 'Y' else 'N' end as goodPhone	
	, case when d.personid is not null and g.personid is null then 'Y' else 'N' end as dncPhone	
	
from medicare.mms.person (nolock) as p		
join medicare.mms.member (nolock) as m		
on p.id = m.personid		
join medicare.mms.membership (nolock) as ms		
on m.id = ms.MemberID	
join medicare.mms.customer (nolock) as c		
on m.CustomerID = c.id		
join medicare.mms.ContractProfile (nolock) as cp		
on ms.ContractProfileID = cp.id		
left join mms.MembershipDoNotContact as mmdnc 
on mmdnc.membershipid = ms.id and mmdnc.DoNotContactTypeID=6 and mmdnc.DoNotContactValue =1	 

left join goodphone as g		
on p.id = g.PersonID		
left join dncphone as d		
on p.id = d.PersonID

where ms.enddate is null 		
and mmdnc.membershipid is null	
and c.IsDeleted = 0		
and cp.IsDeleted = 0		
and cp.IsOutreachExcluded = 0	

and ms.mcocontractid in ('H9572', 'S5584') 
			and  ms.contractprofileID in (238, 393, 8634)
			and c.id = 13	
);
disconnect from odbc;
quit;


proc sql;
create table PhoneStatus as
select *, 1 as PhoneIssueFlag 
from phonedata
where goodphone = 'N' or dncphone = 'Y';
quit;

 /*Pull outreach/case activity from me_prod */

proc sql;
connect to odbc as rs1 
      (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table Got_RPC_DEA as
select *
from connection to rs1 (
                select 
					mship.customerid as customerid,
					activity.caseid,
                    mship.customerid,
                    mship.memberid,
                    mship.membershipID,
                    activity.productid,
                    activity.casestatushistoryid as cshID,
                    activity.casesequence,
                    activity.casetypeid,
                    activity.casestatusid,
                    activity.createdby,
                    mship.mcocontractid,
                    case when activity.isalreadyenrolled=1 then 'RM' else 'MSA' end population,
                    cast(activity.activedate as datetime) as statusDate,
					cast(callcase.createddate as datetime) as CallcaseCreateddate,
					cast(calllog.callstart as datetime) as CalllogCallStart,
					calllog.callsourceid as callsourceid,
					activity.isivr,
					callsource.description as CallSourceDesc,
					cs.name as CaseStatusDesc,
					csc.name as CaseStatusCategory
                from me_prod.case_activity as activity
                left join me_prod.case_activity_metric_map as  ca on activity.casestatushistoryID=ca.casestatushistoryID
                left join  me_prod.metric_rollup as metric_rollup on metric_rollup.metric_order=ca.metric_order
				left join mms_staging.callcase as callcase on activity.caseid = callcase.caseid and activity.activedate = callcase.createddate
				left join mms_staging.calllog as calllog on callcase.calllogID =  calllog.id
				left join mms_staging.callsource as callsource on calllog.callsourceid = callsource.id
                	 join me_prod.case_activity_membership_map as mship on mship.casestatushistoryID=activity.casestatushistoryID
                	 join me_prod.case_activity_ownership_map as ownership on ownership.casestatushistoryID=activity.casestatushistoryID
                	 join me_prod.customer as c on c.customerid=mship.customerid
					 join mms_staging.casestatus cs on cs.id = activity.casestatusid
					 join mms_staging.casestatuscategory csc on cs.categoryid = csc.id
                where activity.activedate>=trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years')) and
                      rollup_order in (10101, 10102)
					  and productid  in (1)
					  and mship.customerid = 13

);
disconnect from rs1;
quit;
*                      activity.productid=1 and ;
proc sql;
create table Got_RPC_Case2 as
select distinct   membershipid, customerid
	, productid
	, min(statusDate) as RPC_Case_DT format = datetime25.  
from Got_RPC_DEA 
group by  membershipid, customerid
	, productid;
quit;


***********  Determining Agent RPC;
proc sql;
connect to odbc as rs1 
      (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table Got_RPC_Agent as
select *
from connection to rs1 (
select   membershipid, customerid
		, productid 
 		, cast(createddate as datetime) as RPC_Agent_DT
		, 0 as isivr
		, 'Agent' as RPC_type
from me_prod.workflow_right_party_contact a
	where createddate >=trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years')) 
		and productid = 1
		and customerid = 13
);
disconnect from rs1;
quit;

proc sql;
create table Got_RPC_Agent2 as
select distinct  membershipid, customerid
	, productid
	, min(RPC_Agent_DT) as RPC_Agent_DT format = datetime25.
from Got_RPC_Agent 
group by  membershipid, customerid
	, productid		
;
quit;

***********  Determining overall single RPC;
proc sql;
create table Got_RPC_0 as
select distinct  membershipid, customerid
	, productid
	, RPC_Case_DT as RPC_dt
from Got_RPC_Case2
union 
select distinct  membershipid, customerid  
	, productid
	, RPC_Agent_DT
from Got_RPC_Agent2
;
quit;

proc sql;
create table Got_RPC as
select membershipid, customerid, productid, min(RPC_dt) as RPC_dt format = datetime25. 
from Got_RPC_0
group by membershipid, customerid,  productid;
quit;

proc sql;
create table _finalDEA as
select a.ReachScoreCat
	, a.customerid
	, a.membershipid
	, a.dea_marketableflag
	, a.rc_marketableflag
	, a.mship_createddt
	, a.date_scored
	, a.reportstartingpoint
	, firstmembership_month
	, a.*
	, c.phoneissueflag
	, b.rpc_dt
    , case when b.rpc_dt is null then .
	       when b.rpc_dt >=  a.reportstartingpoint then intck('dtday',  a.reportstartingpoint, b.rpc_dt) 
		   when b.rpc_dt <  a.reportstartingpoint then intck('dtday',  a.mship_createddt, b.rpc_dt) 
	    end as DeltaDays_toRPC
from W2_OutreachableFlags a left join Got_RPC b
	on a.membershipid = b.membershipid 
	left join PhoneStatus c
	on a.membershipid = c.membershipid
where (a.dea_marketableflag = 'DEA Marketable' or a.RC_marketableflag = 'RC Marketable')
;

proc sql;
create table _finalDEA2 as
select a.* 
	   , case when DeltaDays_toRPC is null then 'No RPC'
			  when DeltaDays_toRPC >= 0 and DeltaDays_toRPC <= 7 then '0-7 days'
			  when DeltaDays_toRPC >= 8 and DeltaDays_toRPC <= 15 then '8-15 days'
			  when DeltaDays_toRPC >= 16 and DeltaDays_toRPC <= 23 then '16-23 days'
			  when DeltaDays_toRPC >= 24 and DeltaDays_toRPC <= 30 then '24-30 days'
			  when DeltaDays_toRPC >= 31 and DeltaDays_toRPC <= 60 then '31-60 days'
			  when DeltaDays_toRPC >= 61 and DeltaDays_toRPC <= 90 then '61-90 days'
			  when DeltaDays_toRPC >= 91 then 'Over 90 days' end as deltaInterval_toRPC   
from _finalDEA a;
quit;

/*
										proc sql;
										create table _DUPS as
										select customerid, membershipid, count(*) from _finalDEA2
										group by customerid, membershipid
										having count(*) >1;
										quit;
										*no dups;
*/



/*Get dialer calls */
proc sql;
connect to odbc as rs1 (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table dialer_calls as
select distinct *
from connection to rs1 (
select
    d.membershipid,
	'Dialer' as call_source,
    d.datetime as calldate
from telephony.dialer_detail d
join telephony.dialercallresult r on d.callresult=r.id
where r.ismemberattempt='true' and datetime>=trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years'))

union all

select 
ms.id as membershipid,
'Dialer' as call_source,
cl.Callstart as calldate
from mms_staging.CallLog cl
join mms_staging.CallLogDisposition cld  on cl.id  = cld.CallLogID
join mms_staging.callsource cs  on cs.id = cl.callsourceid
join mms_staging.Membership ms  on ms.ID=cld.MembershipID
join mms_staging.member as m  on m.ID=ms.memberid
join mms_staging.calldispositioncode cdc on cdc.id=cld.calldispositionid
where CallStart >='2021-01-01' 
			and cl.callsourceid = 3  /** Dialer calls that did make it to an agent ***/
			and ms.mcocontractid in ('H9572', 'S5584') 
			and ms.contractprofileID in (238, 393, 8634)
			and m.customerid = 13

)
;
disconnect from rs1;
quit;

/*Get ivr calls */
proc sql;
connect to odbc as rs1 (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table ivr_calls as
select distinct *
from connection to rs1 (
select
       membershipid,
	   'IVR' as call_source,
       whsc.calldate
      from
            mms_staging.webapihccallnotification  whsc
            join mms_staging.HCImportRun hci on whsc.importrunid=hci.ImportRunId
            join mms_staging.webapihcimporter imp  on imp.id=hci.importerid
            join  mms_staging.hcimportertype as itype on itype.id=imp.hcimportertypeid
            join mms_staging.membership ms on ms.id = whsc.membershipid
            join mms_staging.member m  on m.id = ms.memberid
where
    		CallDate>=trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years'))
			and ms.mcocontractid in ('H9572', 'S5584') 
			and ms.contractprofileID in (238, 393, 8634)
			and m.customerid = 13

)
;
disconnect from rs1;
quit;

/*Get advocate inbound/outbound calls from the previous week*/
proc sql;
connect to odbc as rs1 (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table calllog_calls as
select distinct *
from connection to rs1 (
select
                ms.id as membershipid,
				'Calllog' as call_source,
				cs.isinbound,
				cdc.ismemberattempt,
				cl.callstart as calldate
                from mms_staging.CallLog cl
                join mms_staging.CallLogDisposition cld  on cl.id  = cld.CallLogID
                join mms_staging.callsource cs  on cs.id = cl.callsourceid
                join mms_staging.Membership ms  on ms.ID=cld.MembershipID
                join mms_staging.member as m  on m.ID=ms.memberid
				join mms_staging.calldispositioncode cdc on cdc.id=cld.calldispositionid
                where CallStart >= trunc((date_trunc('year', CURRENT_DATE) - INTERVAL '1 years'))
				and  cl.callsourceid <> 3
				and ms.mcocontractid in ('H9572', 'S5584') 
				and ms.contractprofileID in (238, 393, 8634)
				and m.customerid = 13
)
;
disconnect from rs1;
quit;

proc sql;
create table unioned_calls as
select distinct
membershipid,
'Outbound' as call_source,
calldate
from calllog_calls
where isinbound=0
union all
select distinct
membershipid,
'Inbound' as call_source,
calldate
from calllog_calls
where isinbound=1
union all
select distinct
membershipid,
call_source,
calldate
from dialer_calls
union all
select distinct
membershipid,
call_source,
calldate
from ivr_calls
;
quit;

proc sql;
create table call_summary as
select distinct
membershipid,
min(calldate) as FirstCall format = datetime24.,
count(distinct calldate) as total_calls,
count(distinct datepart(calldate)) as unique_calldates,
count(distinct calldate)/count(distinct datepart(calldate)) as calls_per_day
from unioned_calls
group by
membershipid;
quit;



***********  Determining CustomerName;
proc sql;
connect to odbc as rs1 
      (DSN='redshift' user='pag_bi_user' pwd='{SAS002}954AF70E571907AB333CFB893C073A52');
create table Customer as
select *
from connection to rs1 (
select   customerid, customername
from mms_staging.customer
where customerid = 13
);
disconnect from rs1;
quit;

proc sql;
create table _finalDEA3 as
select c.customername, a.* , b.FirstCall, b.unique_calldates
	, case when b.firstcall is null then 'Not Called' else 'Called' end as CalledFlag
	, case when b.firstcall is null then .
	       when b.firstcall >=  a.reportstartingpoint then intck('dtday',  a.reportstartingpoint, b.firstcall) 
		   when b.firstcall <  a.reportstartingpoint then intck('dtday',  a.mship_createddt, b.firstcall) 
	    end as DeltaDays_toCall_1

from _finalDEA2 a
	left join call_summary b
	on a.membershipid = b.membershipid 
	left join customer c
	on a.customerid = c.customerid;
	quit;

proc sql ;
create table _finalDEA4  as
select  
  customername
, customerid
, membershipid
, dea_marketableflag
, rc_marketableflag
, mship_createddt
, date_scored
, case when date_scored is null then .  else intck('dtday', mship_createddt, date_scored) end as DeltaDays_toScore
, score
, bucketid
, reachscorecat
, reportstartingpoint
, firstmembership_month
, reportstartingmonth as StartingPoint
, exclusions_flag
, isexcluded
, isdeceased
, isdonotsolicit
, hospiceindicator
, exclusionstatusid
, PhoneIssueFlag
, RPC_dt
, DeltaDays_toRPC
, DeltaInterval_toRPC
, FirstCall as  FirstCall_dt
, unique_calldates
, DeltaDays_toCall_1

, case when FirstCall is not null and DeltaDays_toCall_1 >0 and DeltaDays_toCall_1 <= 7 then 1 else 0 end as Called7days_fStartingPoint
, case when FirstCall is null then 1 else 0 end as Mbr_notCalled 
, case when DeltaDays_toRPC >0 and DeltaDays_toRPC <= 90 then 1 else 0 end as RCP_w90days_fStartingPoint
, case when DeltaDays_toRPC > 90 then 1 else 0 end as RPC_90daysPLUS_fStartingPoint
, case when RPC_dt is null then 1 else 0 end as Mbr_notRPC
, case when RPC_dt is null and (PhoneIssueFlag =1 or exclusions_flag) then 1 
	   when RPC_dt is not null then 0
       end as NoRPC_becauseMMSExclusion

from _finalDEA3;
quit;


/*
									proc sql;
									create table __dups as
									select membershipid, count(*)
									from _finalDEA3
									group by membershipid
									having count(*) >1;
									quit;
*/


proc sql;
create table _Distribution_DEA4_byClients as
select distinct customerid
				, dea_marketableflag
				, ReachScoreCat
				, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) as MMSCreatedMth  format = mmddyy10.
				, count(distinct membershipid) as TotalMembers
				, avg(DeltaDays_toScore) as AVG_Days_toScore
				, avg(DeltaDays_toCall_1) as AVG_Days_toCall_1
				, avg(unique_calldates) as AVG_Unique_CallDates
				, avg(DeltaDays_toRPC) as AVG_Days_toRPC

				, sum(Called7days_fStartingPoint)  as Called7days_fStartingPoint
				, sum(Mbr_notCalled) as Mbr_notCalled
				, sum(RCP_w90days_fStartingPoint) as RCP_w90days_fStartingPoint
				, sum(RPC_90daysPLUS_fStartingPoint) as RPC_90daysPLUS_fStartingPoint
				, sum(Mbr_notRPC) as Mbr_notRPC
				, sum(NoRPC_becauseMMSExclusion) as NoRPC_becauseMMSExclusion

from _finalDEA4
where dea_marketableflag = 'DEA Marketable' 
group by  customerid, dea_marketableflag, ReachScoreCat, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) ;
quit;



proc sql;
create table _Distribution_DEA4_Overall as
select distinct  dea_marketableflag
				, ReachScoreCat
				, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) as MMSCreatedMth  format = mmddyy10.
				, count(distinct membershipid) as TotalMembers
				, avg(DeltaDays_toScore) as AVG_Days_toScore
				, avg(DeltaDays_toCall_1) as AVG_Days_toCall_1
				, avg(unique_calldates) as AVG_Unique_CallDates
				, avg(DeltaDays_toRPC) as AVG_Days_toRPC

				, sum(Called7days_fStartingPoint)  as Called7days_fStartingPoint
				, sum(Mbr_notCalled) as Mbr_notCalled
				, sum(RCP_w90days_fStartingPoint) as RCP_w90days_fStartingPoint
				, sum(RPC_90daysPLUS_fStartingPoint) as RPC_90daysPLUS_fStartingPoint
				, sum(Mbr_notRPC) as Mbr_notRPC
				, sum(NoRPC_becauseMMSExclusion) as NoRPC_becauseMMSExclusion

from _finalDEA4
where dea_marketableflag = 'DEA Marketable'   and customerid = 13
group by  dea_marketableflag, ReachScoreCat, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) ;
quit;



proc sql;
create table _Distribution_DEA4_Cus13 as
select distinct customerid
				, dea_marketableflag
				, ReachScoreCat
				, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) as MMSCreatedMth  format = mmddyy10.
				, count(distinct membershipid) as TotalMembers
				, avg(DeltaDays_toScore) as AVG_Days_toScore
				, avg(DeltaDays_toCall_1) as AVG_Days_toCall_1
				, avg(unique_calldates) as AVG_Unique_CallDates
				, avg(DeltaDays_toRPC) as AVG_Days_toRPC

				, sum(Called7days_fStartingPoint)  as Called7days_fStartingPoint
				, sum(Called7days_fStartingPoint) / count(distinct membershipid) as perc_7days 
				, sum(Mbr_notCalled) as Mbr_notCalled
				, sum(Mbr_notCalled) / count(distinct membershipid) as perc_notcalled
				, sum(RCP_w90days_fStartingPoint) as RCP_w90days_fStartingPoint
				, sum(RCP_w90days_fStartingPoint) / count(distinct membershipid) as perc_rpccalledin90
				, sum(RPC_90daysPLUS_fStartingPoint) as RPC_90daysPLUS_fStartingPoint
				, sum(RPC_90daysPLUS_fStartingPoint) / count(distinct membershipid) as  perc_rpccallednot90
				, sum(Mbr_notRPC) as Mbr_notRPC
				, sum(Mbr_notRPC) /  count(distinct membershipid) as perc_notrpccalled 
				, sum(NoRPC_becauseMMSExclusion) as NoRPC_becauseMMSExclusion

from _finalDEA4
where dea_marketableflag = 'DEA Marketable' and customerid = 13 and ReachScoreCat in ('High', 'Med')
group by  customerid, dea_marketableflag, ReachScoreCat, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) ;
quit;


proc sql;
create table _Detail_DEA4_Cus13 as
select * 
from _finalDEA4
where dea_marketableflag = 'DEA Marketable' and customerid = 13;
quit;





data _null_;
CALL SYMPUT('rptdate', COMPRESS(TRANWRD(put(today(),yymmDD10.), '-','')));
run;
%put &rptdate;


proc export data= _Detail_DEA4_Cus13
   outfile="\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics\Reporting\ClientProduction\MEPAG-1377 BCBSMI BCBSBCN Outreachable Population New\Customer13_DetailDEA_&rptdate..csv"
   dbms=csv replace;
run;






FILENAME myemail EMAIL 
from=(/*"norma.murray@changehealthcare.com"*/ "Customer Insights <donotreply@changehealthcare.com>")
encoding='wlatin2'  
to=(
'norma.murray@changehealthcare.com'
'josefina.riquelme@changehealthcare.com'
)
cc=( 
'Monica.Federman@changehealthcare.com'
)
subject = "UHC Member Exclusions Audit Report"
type = "text/html"
attach = "D:\production\IP_291_S\Reports\UHC_Member_Exclusions_Audit_Report_&today..xlsx";
ods _all_ close;; 
title ;
title1 ;

ods html3 body=myemail options(pagebreak="no") style=mystyle rs=none ; 

ods _all_ close;
run;


/*


proc export data= _Distribution_DEA4_NonUHC
   outfile='\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics
\Reporting\ClientProduction\MEPAG-1083 Priority Health Outrechable POP contact within 90 days\Non_UHC_Overall_DEA.csv'
   dbms=csv replace;
run;

proc export data= _Distribution_DEA4_Overall
   outfile='\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics
\Reporting\ClientProduction\MEPAG-1083 Priority Health Outrechable POP contact within 90 days\Overall_DEA.csv'
   dbms=csv replace;
run;

proc export data= _Distribution_DEA4_byClients
   outfile='\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics
\Reporting\ClientProduction\MEPAG-1083 Priority Health Outrechable POP contact within 90 days\Overall_Clients_DEA.csv'
   dbms=csv replace;
run;

proc export data= _Detail_DEA4_Cus38
   outfile='\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics
\Reporting\ClientProduction\MEPAG-1083 Priority Health Outrechable POP contact within 90 days\Priority_DetailDEA.csv'
   dbms=csv replace;
run;



proc export data= _Detail_DEA4_Cus13
   outfile='\\pbnaaefs003.sscincorporated.com\MMS-Prod\DFS\AltegraHealth\Performance Analytics
\Reporting\ClientProduction\MEPAG-1377 BCBSMI BCBSBCN Outreachable Population New\Customer13_DetailDEA.csv'
   dbms=csv replace;
run;



*/;



/*
								proc sql;
								create table ____Testing38 as
								select * from _Distribution_DEA4
								where customerid = 38;
								quit;
*/;

/*
proc sql;
create table _Distribution_RC as
select distinct customerid
				, dea_marketableflag
				, ReachScoreCat
				, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) as MMSCreatedMth  format = mmddyy10.
				, count(distinct membershipid)
				, avg(DeltaDays_toScore) as AVG_Days_toScore
				, avg(DeltaDays_toCall_1) as AVG_Days_toCall_1
				, avg(unique_calldates) as AVG_Unique_CallDates
				, avg(DeltaDays_toRPC) as AVG_Days_toRPC

				, sum(Called7days_fStartingPoint)  as Called7days_fStartingPoint
				, sum(Mbr_notCalled) as Mbr_notCalled
				, sum(RCP_w90days_fStartingPoint) as RCP_w90days_fStartingPoint
				, sum(RPC_90daysPLUS_fStartingPoint) as RPC_90daysPLUS_fStartingPoint
				, sum(Mbr_notRPC) as Mbr_notRPC
				, sum(NoRPC_becauseMMSExclusion) as NoRPC_becauseMMSExclusion
from _finalDEA4
where RC_marketableflag = 'RC Marketable'
group by  customerid, dea_marketableflag, ReachScoreCat, mdy(month(datepart(mship_createddt)),1,year(datepart(mship_createddt))) ;
quit;
*/;
