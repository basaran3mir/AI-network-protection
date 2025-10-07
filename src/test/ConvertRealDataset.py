import pandas as pd
import numpy as np
from dateutil import parser

raw_csv = 'res/test/real_dataset.csv'
output_csv = 'res/test/real_dataset_formatted.csv'

df_raw = pd.read_csv(raw_csv)

df_flow = df_raw[df_raw['event_type'] == 'flow'].copy()

def calculate_duration(start_str, end_str):
    try:
        start = parser.parse(start_str)
        end = parser.parse(end_str)
        duration = (end - start).total_seconds()
        return duration if duration > 0 else np.nan
    except Exception as e:
        return np.nan

df_flow['TotBytes'] = df_flow['flow.bytes_toserver'] + df_flow['flow.bytes_toclient']

df_flow['SrcBytes'] = df_flow['flow.bytes_toserver']
df_flow['DstBytes'] = df_flow['flow.bytes_toclient']

df_flow['TotPkts'] = df_flow['flow.pkts_toserver'] + df_flow['flow.pkts_toclient']
df_flow['SrcPkts'] = df_flow['flow.pkts_toserver']
df_flow['DstPkts'] = df_flow['flow.pkts_toclient']

df_flow['Dur'] = df_flow.apply(lambda row: calculate_duration(row['flow.start'], row['flow.end']), axis=1)
df_flow['RunTime'] = df_flow['Dur']

df_flow['Rate'] = df_flow.apply(lambda row: row['TotBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)
df_flow['SrcRate'] = df_flow.apply(lambda row: row['SrcBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)
df_flow['DstRate'] = df_flow.apply(lambda row: row['DstBytes'] / row['Dur'] if row['Dur'] and row['Dur'] > 0 else 0.0, axis=1)

df_flow['TcpRtt'] = 0.0
df_flow['SynAck'] = 0.0
df_flow['AckDat'] = 0.0

df_flow['Seq'] = range(1, len(df_flow) + 1)

proto_types = ['icmp', 'ipv6-icmp', 'llc', 'lldp', 'sctp', 'tcp', 'udp']

def encode_proto(proto_value):
    proto_value = str(proto_value).lower().strip()
    encoding = {}
    for pt in proto_types:
        encoding[f"Proto_{pt}"] = (proto_value == pt)
    return pd.Series(encoding)

df_proto_encoded = df_flow['proto'].apply(encode_proto)
df_flow = pd.concat([df_flow, df_proto_encoded], axis=1)

final_columns = [
    "TotBytes",
    "SrcBytes",
    "DstBytes",
    "TotPkts",
    "SrcPkts",
    "DstPkts",
    "Rate",
    "SrcRate",
    "DstRate",
    "Dur",
    "RunTime",
    "TcpRtt",
    "SynAck",
    "AckDat",
    "Seq",
    "Proto_icmp",
    "Proto_ipv6-icmp",
    "Proto_llc",
    "Proto_lldp",
    "Proto_sctp",
    "Proto_tcp",
    "Proto_udp"
]

for col in final_columns:
    if col not in df_flow.columns:
        df_flow[col] = False

df_final = df_flow[final_columns]

df_final.to_csv(output_csv, index=False)
print(f"Raw veriler, eğitim veri seti formatına dönüştürüldü ve '{output_csv}' dosyasına kaydedildi.")
