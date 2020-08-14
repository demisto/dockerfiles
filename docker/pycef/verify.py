import pycef

cef = "Jul 14 2020 00:49:42 myvxkp.manage.trendmicro.com CEF:0|Trend Micro|Apex Central|2019|WB:36|36|3|deviceExternalId=1 rt=Jun 21 2020 07:56:09 GMT+00:00 app=5 cnt=1 dpt=80 act=2 src=10.128.0.11 cs1Label=SLF_PolicyName cs1=Internal User Policy deviceDirection=2 cat=36 dvchost=CU-PRO1-8254-2 request=http://www.eicar.org/download/eicar.com.txt duser=TRENDMICROAPEX-\\admin shost=TRENDMICROAPEX- deviceProcessName=C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe cn3Label=Web_Reputation_Rating cn3=49 deviceFacility=Apex One cn2Label=SLF_SeverityLevel cn2=100 "
a = pycef.parse(cef)
