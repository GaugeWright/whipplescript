from pathlib import Path
import marshal,hashlib,json,sys
if sys.version_info[:3] != (3, 14, 7):
 raise SystemExit("run with the pinned native CPython 3.14.7 build")
root=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[2]/"target"
library=root/'norm-cpython-wasi/Lib'
entries=[];manifest={}
excluded={'test','tests','idlelib','tkinter','turtledemo','ensurepip','venv'}
with (root/'norm-frozen-stdlib.h').open('w') as output:
 for path in sorted(library.rglob('*.py')):
  rel=path.relative_to(library)
  if any(part in excluded or part=='__pycache__' for part in rel.parts):continue
  package=rel.name=='__init__.py'
  parts=rel.parts[:-1] if package else (*rel.parts[:-1],rel.stem)
  if not parts:continue
  name='.'.join(parts)
  body=path.read_bytes()
  # The rule's hazard is unmarshalling data from an untrusted source. This
  # only DUMPS: it compiles stdlib `.py` files from the pinned CPython build
  # checked above and writes the bytes into a C header. Nothing here loads
  # marshal data, and the bytes never leave this build.
  # nosemgrep: python.lang.security.audit.marshal.marshal-usage
  code=marshal.dumps(compile(body,'<frozen '+name+'>','exec',dont_inherit=True,optimize=0))
  symbol='norm_frozen_'+str(len(entries))
  output.write('static const unsigned char '+symbol+'[] = {\n')
  for offset in range(0,len(code),24):output.write(','.join(str(byte) for byte in code[offset:offset+24])+',\n')
  output.write('};\n')
  entries.append((name,symbol,len(code),int(package)))
  manifest[name]={'source_sha256':hashlib.sha256(body).hexdigest(),'code_sha256':hashlib.sha256(code).hexdigest(),'package':package}
 output.write('static const struct _frozen norm_frozen_modules[] = {\n')
 for name,symbol,size,package in entries:output.write(f'{{"{name}", {symbol}, {size}, {package}}},\n')
 output.write('{NULL, NULL, 0, 0}\n};\n')
(root/'norm-frozen-stdlib.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print('froze',len(entries),'modules;',sum(entry[2] for entry in entries),'marshal bytes')
