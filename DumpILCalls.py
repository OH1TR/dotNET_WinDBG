import sys
import re

if(len(sys.argv)==1):
  print("Decompile assembly with: ildasm target.exe /OUT=code.il /source /quo /uni")
  print("Usage: DumpILCalls.py code.il [bp_list.txt]")
  exit()

with open(sys.argv[1], 'r') as f:
    lines = f.readlines()

targets=set()

for line in lines:
    tok = line.split()
    method=next((t for t in tok if "(" in t), None)
    if(method!=None):
        m=re.search('\[(\w+?)\]([\w.]+?)::([\w.]+?)[\(<]', method)
        if m!=None and m.group(3)!='.ctor':
                targets.add(m.group(1)+'.dll!'+m.group(2)+'.'+m.group(3))

if(len(sys.argv)==2):
  for t in targets:
    print(t)
else:
  with open(sys.argv[2], 'w') as f:
    for item in targets:
      f.write("%s\n" % item)
