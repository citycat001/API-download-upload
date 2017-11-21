import argparse
import hashlib 
import hmac 
import httplib 
import urllib 
import time
import json
import email
import sys
import urllib2
from httplib import BadStatusLine
import ssl
import base64

public_key = 
private_key = 
ip = 
port = 
user = 
passwd = 
proxy_enabled = "No"
proxy_ip = "#PROXY_IP#"
proxy_port = 

# Command Line Arguments Parsing 
parser = argparse.ArgumentParser(description='testconnection')
requiredNamed = parser.add_argument_group('required arguments')

requiredNamed.add_argument('-d',metavar='daysRequested', required=True,
					dest='daysRequested', action='store',
					help='# of days / InWs to obtain ie 1, 7, 30, 90.')

parser.add_argument('-o', action='store_true',
					help='write API response to file instead of sending to API')
args = parser.parse_args()

data = '' 
queryType = '/view/iocs?'	
format = 'json'

# days Requested Setup
timeVal = int(args.daysRequested) * 86400

query = { 
    'startDate' : 1474329600,#int(time.time()) - timeVal, 
    'endDate' : 1474761600#int(time.time()) 
} 
time_stamp = email.Utils.formatdate(localtime=True)

#Create Query 
enc_q = queryType + urllib.urlencode(query) + '&format=' + format

Host = "https://api.isightpartners.com"
combined_url = (Host + enc_q)

#Generate proper accept_header for requested indicator type
accept_header = 'application/json'

#Generate Hash for Auth
data = enc_q + '2.0' + accept_header + time_stamp
hashed = hmac.new(private_key, data, hashlib.sha256) 

#Get dataset
handler = urllib2.HTTPHandler()

if "yes" in proxy_enabled:
	print "Proxy Connection"
	proxy_ip_port = (proxy_ip + ":" + proxy_port)
	proxy_handler = urllib2.ProxyHandler({'https':proxy_ip_port})
	opener = urllib2.build_opener(proxy_handler)
else:
	print "Direct Connection"
	opener = urllib2.build_opener(handler)	

urllib2.install_opener(opener)
data = None

request = urllib2.Request(combined_url, data=data)
request.add_header('Accept', accept_header)
request.add_header('Accept-Version', '2.0')
request.add_header('X-Auth', public_key)
request.add_header('X-Auth-Hash', hashed.hexdigest())
request.add_header('X-App-Name', 'mysight-api')
request.add_header('Date', time_stamp)

request.get_method = lambda: 'GET'

try:
		response = urllib2.urlopen(request)
except urllib2.HTTPError as e:
		print e.read()
		exit()
except urllib2.URLError as e:
		print 'Failed to connect to API'
		print 'Reason: ', e.reason
		exit()
else:
		print 'Success connecting to API'

print "Response Code: " + str(response.code)
status = response.code
if status == 200 : 
	print ('\nAPI Authentication good!')
if status == 204 :
	sys.exit('\nAPI Error 204: search Result not found.')
	print '\n'
if status == 404 :
    sys.exit("\nAPI Error 404.")
if status == 401 :
	sys.exit("\nAPI Error 401: Check keys, auth-hash headers, or timezone of workstation.")
if status != 200 :
	print status 
	sys.exit("API Error. See API documentation.")

#Test for whether the user wanted file output or not
if args.o is False:

	print 'Reading Response...'
	start = time.time()
	r = json.loads(response.read())
	iocStatus = r['success']
	print 'Response on JSON extract: ' + str(iocStatus)
	
	print 'Starting API Authentication Code'

	start = time.time()
	upstring = base64.b64encode(user + ':' + passwd)

	handler = urllib2.HTTPHandler()
	opener = urllib2.build_opener(handler)
	urllib2.install_opener(opener)
	data = None

	request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/token', data=data)
	request.add_header('Accept', 'application/json')
	request.add_header('Authorization', 'Basic ' + upstring)
	request.get_method = lambda: 'GET'

	try:
			response2 = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
			print e.read()
			exit()
	except urllib2.URLError as e:
			print 'Failed to connect to API server.'
			print 'Reason: ', e.reason
			exit()
	else:
			print 'Success on API Authentication '
			token = (response2.info().getheader('X-Api-Token'))
			
			
	# Create Custom  Category (if it doesn't already exist)

	catname = ""
	data = """{"retention_policy":"auto","ui_edit_policy":"full"}"""

	request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicator_categories/' + catname, data=data)
	request.add_header('X-Api-Token', token)
	request.add_header('Accept', 'application/json')
	request.add_header('Content-Type', 'application/json')
	request.add_header('If-None-Match', '*')
	request.get_method = lambda: 'PUT'

	try:
			response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
			if e.code == 412:
				pass
			else:
				raise
	except urllib2.URLError as e:
			print 'Failed to connect to API server.'
			print 'Reason: ', e.reason
	else:
			print 'Success on  Category Creation'		
	
	track_total = len(r['message'])
	print 'Total Number of Messages is: ' + str(track_total)
	track_current = 0
	for each in r['message']:
		ioc_reportId =  each['reportId']
		track_current += 1
		print 'Processing ' + str(track_current) + ' of ' + str(track_total) + ' API messages. Updating reportID: ' + str(ioc_reportId) 
		ioc_ThreatScape_orig =  each['ThreatScape']
		ioc_ThreatScape = str(ioc_ThreatScape_orig.replace (" ", "_"))
		#print 'ThreatScape: ' + str(ioc_ThreatScape)
		ioc_md5 = each['md5']
		#print 'md5: ' + str(ioc_md5)
		ioc_userAgent = each['userAgent']

		ioc_domain = each['domain']
		#print 'domain: ' +str(ioc_domain)
		ioc_url = each['url']
		#print 'url: ' + str(ioc_url)
		ioc_ip = each['ip']
		#print 'ip: ' + str(ioc_ip)


		ioc_name = "" + '_' + str(ioc_ThreatScape) + '_(' + str(ioc_reportId) + ')'
		ioc_data = "{\"create_text\":\"" + user + "\",\"display_name\":\"" + ioc_name + "\"}"
		request = urllib2.Request('https://' + ip + ':' + port + '/api/v2/indicators/' + catname + '/' + ioc_name, data=ioc_data)
		request.add_header('X-Api-Token', token)
		request.add_header('Accept', 'application/json')
		request.add_header('Content-Type', 'application/json')
		request.add_header('If-None-Match', '*')
		request.get_method = lambda: 'PUT'

		try:
				response = urllib2.urlopen(request)
		except urllib2.HTTPError as e:
				if e.code == 412:
					pass
				else:
					raise
		except urllib2.URLError as e:
				print 'Failed to connect to API server.'
				print 'Reason: ', e.reason
		else:
				pass
				print 'Success Creating new  Report'

		# Add presence condition

		#print 'Processing MD5 Presence Conditons'
		pres_cond_build = ''

		if ioc_md5:
			if ioc_md5.lower() == "d41d8cd98f00b204e9800998ecf8427e":
				print "An Empty File Hash Detected: NOT Adding This Hash: " + ioc_md5
				pass
			else:
				#print 'Found md5 to add'
				md5_pres_cond = '{"token":"fileWriteEvent/md5","type":"md5","operator":"equal","value":"' + ioc_md5 + '"},'
				pres_cond_build = pres_cond_build + md5_pres_cond
				pres_cond = pres_cond_build.strip( ',' )
				#print 'Final stripped presence conditions'
				#print pres_cond

				pres_ioctype = "/conditions/presence"
				data = """{"tests":[""" + pres_cond + """]}"""
				data = data.replace('\\', '\\\\')	

				request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicators/' + catname + '/' + ioc_name + pres_ioctype, data=data)
				request.add_header('X-Api-Token', token)
				request.add_header('Accept', 'application/json')
				request.add_header('Content-Type', 'application/json')
				request.get_method = lambda: 'POST'

				try:
						response = urllib2.urlopen(request)
				except urllib2.HTTPError as e:
						print e.read()
				except urllib2.URLError as e:
						print 'Failed to connect to API server.'
						print 'Reason: ', e.reason
				else:
						res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
				#		print 'Success adding presence condition'
		else:
			pass
			#print 'No md5 to add'

		#print 'Processing File and Size Presence Conditons'
		pres_cond_build = ''

		#print 'Processing execution user agent Conditons'
		exec_cond_build = ''

		if ioc_userAgent:
		#	print 'Adding user Agent'
			userAgent_exec_cond = '{"token":"urlMonitorEvent/userAgent","type":"text","operator":"equal","value":"' + ioc_userAgent + '"},'
			exec_cond_build = exec_cond_build + userAgent_exec_cond
			exec_cond = exec_cond_build.strip( ',' )
			#print 'Final stripped execution conditions'
			#print exec_cond
		
			exec_ioctype = "/conditions/execution"
			data = """{"tests":[""" + exec_cond + """]}"""
			data = data.replace('\\', '\\\\')

			request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicators/' + catname + '/' + ioc_name + exec_ioctype, data=data)
			request.add_header('X-Api-Token', token)
			request.add_header('Accept', 'application/json')
			request.add_header('Content-Type', 'application/json')
			request.get_method = lambda: 'POST'

			try:
					response = urllib2.urlopen(request)
			except urllib2.HTTPError as e:
					print e.read()

			except urllib2.URLError as e:
					print 'Failed to connect to API server.'
					print 'Reason: ', e.reason

			else:
					res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		#			print 'Success adding execution condition'
		else:
			pass
		#	print 'Empty user Agent'

		#print 'Processing execution domain Conditons'
		exec_cond_build = ''

		if ioc_domain:
		#	print 'Adding domain'
			domain_exec_cond = '{"token":"dnsLookupEvent/hostname","type":"text","operator":"contains","value":"' + ioc_domain + '"},'
			exec_cond_build = exec_cond_build + domain_exec_cond
			exec_cond = exec_cond_build.strip( ',' )
			#print 'Final stripped execution conditions'
			#print exec_cond
		
			exec_ioctype = "/conditions/execution"
			data = """{"tests":[""" + exec_cond + """]}"""
			data = data.replace('\\', '\\\\')

			request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicators/' + catname + '/' + ioc_name + exec_ioctype, data=data)
			request.add_header('X-Api-Token', token)
			request.add_header('Accept', 'application/json')
			request.add_header('Content-Type', 'application/json')
			request.get_method = lambda: 'POST'

			try:
					response = urllib2.urlopen(request)
			except urllib2.HTTPError as e:
					print e.read()

			except urllib2.URLError as e:
					print 'Failed to connect to API server.'
					print 'Reason: ', e.reason

			else:
					res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		#			print 'Success adding execution condition'
		else:
			pass
		#	print 'Empty domain'

		#print 'Processing execution IP Conditons'
		exec_cond_build = ''

		if ioc_ip:
		#	print 'Adding IP'
			domain_exec_cond = '{"token":"ipv4NetworkEvent/remoteIP","type":"text","operator":"contains","value":"' + ioc_ip + '"},'
			exec_cond_build = exec_cond_build + domain_exec_cond
			exec_cond = exec_cond_build.strip( ',' )
			#print 'Final stripped execution conditions'
			#print exec_cond
		
			exec_ioctype = "/conditions/execution"
			data = """{"tests":[""" + exec_cond + """]}"""
			data = data.replace('\\', '\\\\')

			request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicators/' + catname + '/' + ioc_name + exec_ioctype, data=data)
			request.add_header('X-Api-Token', token)
			request.add_header('Accept', 'application/json')
			request.add_header('Content-Type', 'application/json')
			request.get_method = lambda: 'POST'

			try:
					response = urllib2.urlopen(request)
			except urllib2.HTTPError as e:
					print e.read()

			except urllib2.URLError as e:
					print 'Failed to connect to API server.'
					print 'Reason: ', e.reason

			else:
					res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		#			print 'Success adding execution condition'
		else:
			pass
		#	print 'Empty IP'

	

		#print 'Processing execution url Conditons'
		exec_cond_build = ''

		if ioc_url:
		#	print 'Adding url'
			url_exec_cond = '{"token":"urlMonitorEvent/hostname","type":"text","operator":"contains","value":"' + ioc_url + '"},'
			exec_cond_build = exec_cond_build + url_exec_cond
			exec_cond = exec_cond_build.strip( ',' )
			#print 'Final stripped execution conditions'
			#print exec_cond
		
			exec_ioctype = "/conditions/execution"
			data = """{"tests":[""" + exec_cond + """]}"""
			data = data.replace('\\', '\\\\')

			request = urllib2.Request('https://' + ip + ':' + port + '/api/v1/indicators/' + catname + '/' + ioc_name + exec_ioctype, data=data)
			request.add_header('X-Api-Token', token)
			request.add_header('Accept', 'application/json')
			request.add_header('Content-Type', 'application/json')
			request.get_method = lambda: 'POST'

			try:
					response = urllib2.urlopen(request)
			except urllib2.HTTPError as e:
					print e.read()

			except urllib2.URLError as e:
					print 'Failed to connect to API server.'
					print 'Reason: ', e.reason

			else:
					res = json.loads(response.read().decode(response.info().getparam('charset') or 'utf-8'))
		#			print 'Success adding execution condition'
		else:
			pass
		#	print 'Empty url'


	print 'API Query And Processing code took', time.time()-start, 'seconds.'
	print 'Starting Log out of API'	
	data = None
	
	request = urllib2.Request('https://' + ip + ':' + port + '/api/v2/token', data=data)
	request.add_header('X-Api-Token', token)
	request.add_header('Accept', 'application/json')
	request.add_header('Content-Type', 'application/json')
	request.get_method = lambda: 'DELETE'

	try:
			response = urllib2.urlopen(request)
	except urllib2.HTTPError as e:
			print e.read()

	except urllib2.URLError as e:
			print 'Failed to connect to API server.'
			print 'Reason: ', e.reason

	else:
			print 'Logged out of API'
	print 'Script was successful and is now completed'

	
else:
	filestatus = 'File output requested.\n'
	print filestatus
	data = response.read()
	try:
		with open(args.o, 'wb') as f:
			f.write(data)
			f.close()
			filewritten = args.o + ' written to disk.'
			print filewritten
	except:
			import traceback
			traceback.print_exc()
			sys.exit('File not written.')
