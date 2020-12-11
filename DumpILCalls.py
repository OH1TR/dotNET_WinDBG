import sys
import re
import io
import chardet
import codecs
import os

if(len(sys.argv)==1):
  print("Decompile assembly with: ildasm target.exe /OUT=code.il /source /uni")
  print("Usage: DumpILCalls.py code.il [bp_list.txt]")
  exit()

bytes = min(32, os.path.getsize(sys.argv[1]))
raw = open(sys.argv[1], 'rb').read(bytes)

if raw.startswith(codecs.BOM_UTF8):
    encoding = 'utf-8-sig'
else:
    result = chardet.detect(raw)
    encoding = result['encoding']

with open(sys.argv[1], 'r', encoding=encoding) as f:
    lines = f.readlines()

targets=set()

for line in lines:
    if(line.find('pinvoke')>-1):
        print('WARN: Found pinvoke, cannot bp that:'+line)
        
    tok = line.split()
    method=next((t for t in tok if "(" in t), None)
    if(method!=None):
        m=re.search('\[(\w+?)\]([\w.]+?)::([\w.]+?)[\(<]', method)
        if m!=None and m.group(3)!='.ctor':
                targets.add(m.group(1)+'.dll!'+m.group(2)+'.'+m.group(3))

targets=sorted(targets)

if(len(sys.argv)==2):
  for t in targets:
    print(t)
else:
  with open(sys.argv[2], 'w') as f:
    for item in targets:
      f.write("%s\n" % item)
