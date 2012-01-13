# -*- coding: utf-8 -*-

import SocketServer
import os, sys
import threading
import time
import cgi
from xml.sax.saxutils import escape

botglobal = None

class MyUDHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		global botglobal
		try:
			data = self.request[0].decode("utf-8")
		except:
			return

		botglobal.usersposts[data[5:17]] = data[19:]
		if data[5:17] in botglobal.blacklist:
			return

		botglobal.last_user_id = data[5:17]
		botglobal.send("radio@conference.qip.ru", "groupchat", data, "<html xmlns='http://jabber.org/protocol/xhtml-im'> <body xmlns='http://www.w3.org/1999/xhtml'> <span style='font-family: Comic Sans MS; font-weight: bold;'><br/>=== SITE MESSAGE ===<br/>%s<br/>=== CUT HERE ===<br/></span></body></html>" % cgi.escape(data))

class ThreadedUnixDatagramServer(SocketServer.ThreadingMixIn, SocketServer.UnixDatagramServer):
	pass

def info(bot):
	global botglobal
	botglobal = bot
	if not hasattr(botglobal, "usersposts"):
		botglobal.usersposts = {}
		botglobal.blacklist = []
		botglobal.last_user_id = None
	try:
		os.unlink("/tmp/botsock")
	except:
		pass
	if hasattr(bot, "server"):
		bot.server.shutdown()
		bot.server = None
		time.sleep(2)

	server = ThreadedUnixDatagramServer("/tmp/botsock", MyUDHandler)
	os.chmod("/tmp/botsock", 0777)
	bot.server = server
	server_thread = threading.Thread(target=server.serve_forever)
	server_thread.setDaemon(True)
	server_thread.start()
	return ((), 0, None)
