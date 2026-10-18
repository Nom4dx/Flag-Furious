"""Streaming-style CSV/TSV/pipe parser with dialect and variable-width support."""
import csv,io
from .generic import event
def parse(data,source,context):
    """Sniff delimiters and retain overflow columns under explicit names."""
    text=data.decode(context.get('encoding','utf-8-sig'),'replace');sample=text[:8192]
    try:dialect=csv.Sniffer().sniff(sample,delimiters=',\t|;')
    except csv.Error:dialect=csv.excel_tab if '\t' in sample else csv.excel
    rows=list(csv.reader(io.StringIO(text),dialect));header=rows[0] if rows else [];has_header=bool(header and csv.Sniffer().has_header(sample))
    out=[]
    for index,row in enumerate(rows[1:] if has_header else rows,2 if has_header else 1):
        names=header if has_header else [f'column_{i}' for i in range(len(row))];fields={name:(row[i] if i<len(row) else None) for i,name in enumerate(names)}
        for i in range(len(names),len(row)):fields[f'extra_{i}']=row[i]
        ts=next((v for k,v in fields.items() if k.casefold() in {'timestamp','time','date','datetime'}),None);out.append(event(source,index,0,dialect.delimiter.join(row),fields,'csv_tsv',ts))
    return out
