# -*- coding: utf-8 -*-
"""
Created on Fri May 04 12:17:07 2018

@author: Administrator
"""


from bs4 import BeautifulSoup
import json
import pandas as pd

thefile = open("C:\Users\Administrator\Desktop\source-EXPLOIT-DB.html","r")

with open('C:\Users\Administrator\Desktop\\nvdcve-1.0-2018.json') as json_data:
    d = json.load(json_data)


id_list = []
for i in range(len(d['CVE_Items'])):

    iden = (d['CVE_Items'][i]['cve']['CVE_data_meta']['ID'])
    id_list.append(iden)

desc_list = []
for i in range(len(d['CVE_Items'])):

    desc = (d['CVE_Items'][i]['cve']['description']['description_data'][0]['value'])
    desc_list.append(desc)
    
pub_list = []
for i in range(len(d['CVE_Items'])):

    pub = (d['CVE_Items'][i]['publishedDate'])
    pub_list.append(pub[:10])

mod_list = []
for i in range(len(d['CVE_Items'])):

    mod = (d['CVE_Items'][i]['lastModifiedDate'])
    mod_list.append(mod[:10])
    
base_list = []
for i in range(len(d['CVE_Items'])):
    
    try:
        base = (d['CVE_Items'][i]['impact']['baseMetricV2']['cvssV2']['baseScore'])
        base_list.append(base)
    except:
        base_list.append('NaN')
   
exp_list = []
for i in range(len(d['CVE_Items'])):

    try:
        exp = (d['CVE_Items'][i]['impact']['baseMetricV2']['exploitabilityScore'])
        exp_list.append(exp)
    except:
        exp_list.append('NaN')

imp_list = []
for i in range(len(d['CVE_Items'])):

    try:    
        imp = (d['CVE_Items'][i]['impact']['baseMetricV2']['impactScore'])
        imp_list.append(imp)
    except:
        imp_list.append('NaN')


ref_cnt_list = []
for i in range(len(d['CVE_Items'])):

    ref_cnt = (d['CVE_Items'][i]['cve']['references']['reference_data'])
    ref_cnt_list.append(len(ref_cnt))

soup = BeautifulSoup(thefile, 'html.parser')
rows = soup.findAll("tr")
text_data = []
      
for link in soup.find_all('a'):
    text_data.append(link.get('href'))       
        
del text_data[0]
exploit_db_cve_list = []

for i in range(len(text_data)):
    exploit_db_cve_list.append(text_data[i][46:])


flag_list=[]
for i in range(len(d['CVE_Items'])):
    if d['CVE_Items'][i]['cve']['CVE_data_meta']['ID'] in exploit_db_cve_list:
        flag_list.append(1)
    else:
        flag_list.append(0)



df_list = []
df_list.append(id_list)
df_list.append(desc_list)
df_list.append(pub_list)
df_list.append(mod_list)
df_list.append(base_list)
df_list.append(exp_list)
df_list.append(imp_list)
df_list.append(ref_cnt_list)
df_list.append(flag_list)

df=pd.DataFrame(df_list).T

df.columns = ['ID', 'Description','Publish Date', 'Last Modified Date','cvssV2_baseScore', 'cvssV2_exploitabilityScore','cvssV2_impactScore', 'reference_cnt','exploit_db_flag']

df.to_csv('tenable_df.csv')#, sep='\t')











