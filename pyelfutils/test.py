from pprint import pprint
import elfutils
pprint(elfutils.parseelf('/bin/ls'))
#x = elfutils.parseelf('/lib/libc-2.14.so')
#elfutils.parseelf('/etc/ksc.conf')
#print len(x[0]['symtab'])
#data = elfutils.parseelf('/usr/lib/debug/lib64/libanl-2.14.90.so.debug')
#pprint(data[0]['sectionheader'])
