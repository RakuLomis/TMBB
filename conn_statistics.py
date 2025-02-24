import pandas as pd 
import os

columns = ['Address A', 'Port A', 'Address B', 'Port B', 'Packets', 'Bytes', 'Stream ID', 'Rel Start', 'Duration', 'Flows'] 
meta_columns = ['M ' + item for item in columns] 
wlan_columns = ['W ' + item for item in columns] 

def getSniInfo(df_ori: pd.DataFrame) -> dict: 
    """ Get Server Name Indication from original packet information. 
    """
    df_ori = df_ori.dropna(subset=['TCP Stream index']) 
    server_name_unique = df_ori['Server Name'].dropna().unique() 
    domain_stream_all = {key: [] for key in server_name_unique} 
    for name in domain_stream_all.keys(): # get the dictionary of sni: stream_ids
        stream_ids = df_ori.loc[df_ori['Server Name'] == name, 'TCP Stream index'] 
        domain_stream_all[name].extend(stream_ids) 
    stream_domain_all = {stream_id: domain for domain, stream_ids in domain_stream_all.items() for stream_id in stream_ids} # reverse the dictionary 
    return stream_domain_all 

def addSni(df_meta_statistics: pd.DataFrame, dict_stream_domain: dict) -> set: 
    df_meta_statistics['Server Name'] = df_meta_statistics['M Stream ID'].map(dict_stream_domain) 
    return set(df_meta_statistics['Server Name']) 

def extractColumns(df: pd.DataFrame, df_meta: pd.DataFrame, df_wlan: pd.DataFrame) -> pd.DataFrame:     
    if all(col in df.columns for col in columns): # examine whether the columns have been inplaced 
        df_temp = df[columns].copy() 
        if df.equals(df_meta): 
            col_transfer = {k: v for k, v in zip(columns, meta_columns)} 
            df_temp.rename(columns=col_transfer, inplace=True) 
        elif df.equals(df_wlan): 
            col_transfer = {k: v for k, v in zip(columns, wlan_columns)} 
            df_temp.rename(columns=col_transfer, inplace=True) 
    return df_temp 

def mergeData(df_conn: pd.DataFrame, df_meta: pd.DataFrame, df_wlan: pd.DataFrame) -> pd.DataFrame: 
    df_merge_1st = pd.merge(df_conn, df_meta, left_on='inRemotePort', right_on='M Port A', how='inner')
    df_merge_fin = pd.merge(df_merge_1st, df_wlan, left_on='outLocPort', right_on='W Port A', how='inner')
    return df_merge_fin 