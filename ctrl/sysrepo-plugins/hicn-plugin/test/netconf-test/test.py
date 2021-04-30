import sys
import xml.etree.ElementTree as ET
from netconf.client import connect_ssh

def usage():
   print('usage: test.py host user password operation{route_dump, face_dump, face_add, route_add, punt_add, face_del, punt_del, route_del}')

def test(host,user,password,operation):
   with connect_ssh(host, 830, user, password) as session:
      if (operation=='face_dump'):
         config = session.get()
         for root in config:
            if root.tag=="{urn:sysrepo:hicn}hicn-state":
                  for entity in root:
                     if entity.tag=="{urn:sysrepo:hicn}faces":
                        print('Faces')
                        for face in entity:
                              for elem in face:
                                 print(elem.tag +" : "+ elem.text)
      elif (operation=='state_dump'):
         config = session.get()
         for root in config:
            if root.tag=="{urn:sysrepo:hicn}hicn-state":
                  for entity in root:
                     if entity.tag=="{urn:sysrepo:hicn}states":
                        print('States')
                        for state in entity:
                              print(state.tag +" : "+ state.text)
      elif (operation=='route_dump'):
         config = session.get()
         for root in config:
            if root.tag=="{urn:sysrepo:hicn}hicn-state":
                  for entity in root:
                     if entity.tag=="{urn:sysrepo:hicn}routes":
                        print('Routes')
                        for route in entity:
                              for elem in route:
                                 print(elem.tag +" : "+ elem.text)
      elif(operation=='face_add'):
         root = ET.parse('aface.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      elif(operation=='punt_add'):
         root = ET.parse('apunt.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      elif(operation=='route_add'):
         root = ET.parse('aroute.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      elif(operation=='face_del'):
         root = ET.parse('dface.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      elif(operation=='punt_del'):
         root = ET.parse('dpunt.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      elif(operation=='route_del'):
         root = ET.parse('droute.xml').getroot()
         session.send_rpc(ET.tostring(root, encoding='utf8').decode('utf8'))
      else:
         usage()

if __name__ == '__main__':
   if(len(sys.argv)<4):
      usage()
   else:
      test(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])


