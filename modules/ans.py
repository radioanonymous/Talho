# -*- coding: utf-8 -*-

import urllib2
import socket
from BeautifulSoup import BeautifulSoup, Tag, NavigableString
from cgi import escape
from misc import _
from hashlib import md5
import datetime
import re

def main(bot, args):
	'''Ответить слушателю. Параметры: <user_id> <message>
Если в качестве user_id указать восклицательный знак, сообщение будет выглядеть как объявление.
Если в качестве user_id указать символ @ (или " в русской раскладке), будет использован идентификатор последнего поста. Использовать ОСТОРОЖНО!
? user_id — заблеклистить юзера user_id, его сообщения перестанут поступать в диджейку.
?? — показать блеклист.
?! — очистить блеклист.'''
	syl = { '0' : 'be', '1' : 'sa', '2' : 'ko', '3' : 'pa', '4' : 're', '5' : 'du', '6' : 'ma', '7' : 'ne', '8' : 'wa', '9' : 'si', 'a' : 'to', 'b' : 'za', 'c' : 'mi', 'd' : 'ka', 'e' : 'ga', 'f' : 'no' }
	salt = bot.settings["ans_salt"]
	message_limit = 250
	userpost = ""
	if len(args) == 1 and args[0] != "??" and args[0] != "?!" or not len(args):
		return
	blacklisting = False
	if args[0] != "!":
		if args[0] == "??":
			return _("blacklist:\n%s") % "\n".join(bot.blacklist)
		if args[0] == "?!":
			bot.blacklist = []
			return _("blacklist cleared.")
		if args[0] == "?":
			blacklisting = True
			del args[0]
		if args[0] == "@" or args[0] == '"':
			sender = bot.last_user_id
		else:
			sender = args[0]
		if len(sender) != 12:
			return _("incorrect name entered, should be 12 symbols.")
		check = md5()
		check.update(sender[:8].encode('utf-8') + salt)
		if check.hexdigest()[:4] != sender[8:12]:
			return _("incorrect name entered (checksum invalid).")
	
		if blacklisting:
			bot.blacklist.append(sender)
			return _("%s was added to blacklist.") % sender

		to = ">>" + sender
		if sender in bot.usersposts:
			userpost = "<span class=\"userpost\">&gt; " + escape(bot.usersposts[sender]) + "</span><br/>"
	else:
		to = "!"
        message = " ".join(args[1:])
	if len(message) > message_limit:
		return _("too long answer, should be less than %d symbols, you entered %d symbols.") % (message_limit, len(message))
        soup = BeautifulSoup(open(bot.settings["ans_file"], "r"))
	posts = soup.findAll('p')
	new_post = Tag(soup, 'p')
	user_id = Tag(soup, 'span', [('id', 'user_id')])
	if to != "!":
		user_id.insert(0, escape(to))
	else:
		user_id.insert(0, "<b>&gt;&gt;ОБЪЯВЛЕНИЕ&lt;&lt;</b>")
	new_post.insert(0, '<span class="timestamp">[' + datetime.datetime.strftime(datetime.datetime.now(), "%H:%M:%S") + ']</span>')
	new_post.insert(1, user_id)
	message = re.sub(r'\[([^]]*)\]', lambda x: '<a href="' + x.group(1).replace("&amp;", "&") + '" target="_blank">' + x.group(1) + '</a>', escape(message))
	message = re.sub(r'\{([^}]*)\}', lambda x: '<a href="' + x.group(1).replace("&amp;", "&") + '" target="_blank"><img style="max-width: 200px; max-height: 200px;display: inline;" src="' + x.group(1).replace("&amp;", "&") + '"/></a>', message)
	new_post.insert(2, userpost + message)
	if len(posts) > 0:
		posts[0].parent.insert(2, new_post)
	else:
		soup.find('h1').parent.insert(1, new_post)
	if len(posts) > 9:

		posts[len(posts) - 1].extract()

	f = open(bot.settings["ans_file"], "w")
	f.write(soup.prettify())
	f.close()
        
        return _("sent.")

def info(bot):
	return (("a", u"ф"), 9, main)
