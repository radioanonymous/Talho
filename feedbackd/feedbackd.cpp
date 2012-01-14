#include "libcaptcha.h"
#include <vector>
#include <string>
#include <map>
#include <evhttp.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <openssl/md5.h>

#ifndef FEEDBACK_LOCATION
#	define FEEDBACK_LOCATION		"/feedback"
#endif

#ifndef UID_SALT
#	define	UID_SALT			"anon.fm"
#endif

#ifndef DIGEST_SALT
#	define	DIGEST_SALT			"type_random_letters_here"
#endif

struct cdata {
	char			content[6];
	unsigned char	gif[GIFSIZE];
	time_t			ctime;
};

typedef std::map<std::string, std::string> param_t;

class Captcha {
public:
	void		show_html(struct evbuffer *buf, const char *tmpl, param_t &p);
	bool		show_gif(struct evbuffer *buf, unsigned id);
	bool		validate(unsigned id, const char *text);
private:
	unsigned generate();
	cdata *new_captcha(cdata *c);
	typedef std::map<unsigned, cdata*> ccache;

	ccache captchas;
};

cdata *Captcha::new_captcha(cdata *c)
{
	if (!c)
		c = new cdata;
	unsigned char im[70*200];

	captcha(im, (unsigned char*)c->content);
	makegif(im, c->gif);
	return c;
}

unsigned Captcha::generate()
{
	time_t now = time(NULL);
	if (captchas.size() > 1000) {
		Captcha::ccache::iterator i = captchas.begin(), min = i;
		time_t mt = min->second->ctime;
		while (++i != captchas.end())
			if (i->second->ctime < mt) {
				min = i;
				mt = min->second->ctime;
			}
		delete min->second;
		captchas.erase(min);
	}

	while (1) {
		unsigned r = random() % 900000 + 100000;

		Captcha::ccache::iterator c = captchas.find(r);
		if (c == captchas.end()) {
			Captcha::ccache::value_type cap(r,new_captcha(NULL));
			captchas.insert(cap);
			return r;
		} else if (c->second->ctime + 300 > now || captchas.size() > 1000) {
			c->second->ctime = now;
			new_captcha(c->second);
			return r;
		}
	}
}


static void templater(struct evbuffer *buf, const char *tmpl, param_t &args)
{
	static const char marker[] = "${";
	const char *begin = tmpl, *end;
	std::string name;
	while (*begin) {
		end = strstr(begin, marker);
		if (end) {
			evbuffer_add(buf, begin, end - begin);
			const char *n = strchr(end, '}');
			if (n) {
				name.assign(end + sizeof(marker) - 1, n);
				param_t::const_iterator v = args.find(name);
				if (v != args.end())
					evbuffer_add(buf, v->second.c_str(), v->second.size());
				begin = n + 1;
			} else {
				evbuffer_add(buf, end, sizeof(marker) - 1);
				begin = end + sizeof(marker) - 1;
			}
		} else {
			evbuffer_add(buf, begin, strlen(begin));
			break;
		}
	}
}

void Captcha::show_html(struct evbuffer *buf, const char *tmpl, param_t &args)
{
	char cap[32];
	sprintf(cap, "%u", generate());
	args["CAPTCHA"] = cap;
	args["GIF"] = args["PREFIX"] + "/" + cap + ".gif";
	templater(buf, tmpl, args);
}

bool Captcha::show_gif(struct evbuffer *buf, unsigned id)
{
	Captcha::ccache::const_iterator c = captchas.find(id);
	if (c != captchas.end()) {
		evbuffer_add(buf, c->second->gif, GIFSIZE);
		return true;
	}
	return false;
}

bool Captcha::validate(unsigned id, const char *text)
{
	Captcha::ccache::iterator c = captchas.find(id);
	if (c != captchas.end()) {
		bool match = strncasecmp(text, c->second->content, sizeof(c->second->content) - 1) == 0;
		captchas.erase(c);
		return match;
	}
	return false;
}

static Captcha cc;
static const char *html_tmpl;
static const char *html_tmpl_err;
static const char *html_tmpl_ok;
static const char *sockaddr = "/tmp/botsock";

static char xval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >='a' && c <='f')
		return c - 'a' + 10;
	if (c >='A' && c <='F')
		return c - 'A' + 10;
	return 0;
}

#if !defined(_EVENT_NUMERIC_VERSION) || _EVENT_NUMERIC_VERSION < 0x02000000
#	define	evhttp_request_get_command(req)			(req)->type
#	define	evhttp_request_get_input_buffer(req)	(req)->input_buffer
#	define	evhttp_request_get_input_headers(req)	(req)->input_headers
#	define	evhttp_request_get_connection(req)		(req)->evcon
#endif

static void say(const std::string &what)
{
	struct sockaddr_un name;
	int sock;
	size_t size;
	sock = socket(PF_LOCAL, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror ("socket");
		exit (EXIT_FAILURE);
	}

	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, sockaddr, sizeof (name.sun_path));
	name.sun_path[sizeof (name.sun_path) - 1] = '\0';

	size = (offsetof (struct sockaddr_un, sun_path)
			+ strlen (name.sun_path) + 1);

	if (connect(sock, (struct sockaddr*)&name, size) != -1) {
		write(sock, what.c_str(), what.size());
	}
	close(sock);
}

std::string generate_uid(struct evhttp_request *req)
{
	std::string result;
	static const char syl[] = "besakoparedumanewasitozamikagano"; // from ans.py
	static const char xdigit[] = "0123456789abcdef";
	unsigned char digest[16];
	MD5_CTX m5c;
	MD5_Init(&m5c);
	/* 1. Translate IPv4 into symbolic name */
	/* Look for X-Forwarded-For header */
	const char *fwd_ip = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Real-IP");
	if (!fwd_ip)
		fwd_ip = evhttp_find_header(evhttp_request_get_input_headers(req), "X-Forwarded-For");
	if (fwd_ip) {
		MD5_Update(&m5c, fwd_ip, strlen(fwd_ip));
	} else {
		char *peer = NULL;
		ev_uint16_t port = 0;
		evhttp_connection_get_peer(evhttp_request_get_connection(req), &peer, &port);
		if (peer) {
			MD5_Update(&m5c, peer, strlen(peer));
		} else {
			MD5_Update(&m5c, "0.0.0.0", sizeof("0.0.0.0") - 1);
		}
	}
	MD5_Update(&m5c, UID_SALT, sizeof(UID_SALT) - 1);
	MD5_Final(digest, &m5c);
	for (unsigned i = 0; i < 4; i++) {
		result += syl[digest[i] >> 4];
		result += syl[digest[i] & 0xf];
	}
	/* 2. Add 4-symbols digest */
	MD5_Init(&m5c);
	MD5_Update(&m5c, result.c_str(), result.size());
	MD5_Update(&m5c, DIGEST_SALT, sizeof(DIGEST_SALT) - 1);
	MD5_Final(digest, &m5c);
	for (unsigned i = 0; i < 2; i++) {
		result += xdigit[digest[i] >> 4];
		result += xdigit[digest[i] & 0xf];
	}
	return result;
}

static void process_request(struct evhttp_request *req, void *arg)
{
	static const std::string location = FEEDBACK_LOCATION;
	struct evbuffer *buf = evbuffer_new();
	if (!buf)
		return;
	generate_uid(req);
	const char *uri = evhttp_request_uri(req);
	if (memcmp(uri, location.c_str(), location.size()) == 0) {
		uri += location.size();
		if (*uri == '/')
			uri++;
		if (evhttp_request_get_command(req) == EVHTTP_REQ_GET && isdigit(*uri)) {
			unsigned id = strtoul(uri, NULL, 10);
			if (!cc.show_gif(buf, id))
				goto notfound;
			evhttp_add_header(req->output_headers, "Content-Type", "image/gif");
		} else {
			param_t p;
			static const std::string
				form_captcha = "cid",
				form_check = "check",
				form_msg = "msg";
			p["PREFIX"] = location;
			p["PCAPTCHA"] = form_captcha;
			p["PCHECK"] = form_check;
			p["PMSG"] = form_msg;
			evhttp_add_header(req->output_headers, "Content-Type", "text/html; charset=UTF-8");
			if (evhttp_request_get_command(req) == EVHTTP_REQ_POST) {
				const char *tmpl = html_tmpl_err;
				evbuffer *in = evhttp_request_get_input_buffer(req);
				char *data = (char*)EVBUFFER_DATA(in);
				while (*uri && !isdigit(*uri))
					uri++;
				if (data) {
#define FINZ(p) if (p) {char *end = strchr(p, '&'); if (end) *end = 0;}
					int len = EVBUFFER_LENGTH(in) + 1;
					std::vector<char> post;
					post.reserve(len);
					post.assign(data, data + len);
					data[len - 1] = 0;
					/* user entered captcha */
					std::string what = form_check + "=";
					char *text = strstr(&post[0], what.c_str());
					if (text)
						text += what.size();
					/* captcha id */
					what = form_captcha + "=";
					char *cid = strstr(&post[0], what.c_str());
					if (!cid)
						for (cid = (char*)uri; *cid && !isdigit(*cid); cid++);
					else
						cid += what.size();
					/* message text */
					what = form_msg + "=";
					char *msg = strstr(&post[0], what.c_str());
					std::string uid = generate_uid(req);
					std::string raw_message = "From " + uid + "  ";
					if (msg) {
						std::string message;
						for (msg = msg + what.size(); *msg && *msg != '&'; msg++) {
							char out = *msg;
							switch (out) {
							case '%':
								if (isxdigit(msg[1]) && isxdigit(msg[2])) {
									out = (xval(msg[1]) << 4) | xval(msg[2]);
									msg += 2;
								}
								break;
							case '+':
								out = 0x20;
							}
							switch (out) {
							case '<':
								message += "&lt;";
								break;
							case '>':
								message += "&gt;";
								break;
							case '&':
								message += "&amp;";
								break;
							default:
								message += out;
							}
							raw_message += out;
						}
						p["MSG"] = message;
					}
					FINZ(text);
					FINZ(cid);
#undef FINZ
					if (text && cid && cc.validate(strtoul(cid, NULL, 10), text)) {
						tmpl = html_tmpl_ok;
						p["UID"] = uid;
						say(raw_message);
					}
				}
				cc.show_html(buf, tmpl, p);
			} else {
				cc.show_html(buf, html_tmpl, p);
			}
		}
		evhttp_send_reply(req, HTTP_OK, "OK", buf);
		evbuffer_free(buf);
		return;
	}
notfound:
	evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
	evbuffer_add_printf(buf, "Not found");
	evhttp_send_reply(req, HTTP_NOTFOUND, "Not found", buf);
	evbuffer_free(buf);
}

static char *read_file(const char *fname, const char *default_contents)
{
	struct stat st;
	char *result = (char*)default_contents;
	if (stat(fname, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
		int fd = open(fname, O_RDONLY);
		if (fd != -1) {
			result = new char[st.st_size + 1];
			result[st.st_size] = 0;
			if (read(fd, result, st.st_size) != st.st_size) {
				delete []result;
				result = (char*)default_contents;
			}
			close(fd);
		}
	}
	return result;
}

extern char html_default_ask[], html_default_err[], html_default_ok[];

int main(int argc, char **argv)
{
	struct event_base *base = NULL;
	struct evhttp *httpd = NULL;
	base = event_init();
	if (!base) {
		fprintf(stderr, "Can't initialize libevent!\n");
		return 1;
	}
	httpd = evhttp_new(base);
	if (!httpd) {
		fprintf(stderr, "Can't initialize evhttp\n");
		return 1;
	}
	if (evhttp_bind_socket(httpd, "0.0.0.0", 9000) != 0) {
		fprintf(stderr, "Can't bind http socket!\n");
		return 1;
	}
	html_tmpl = read_file("feedback_ask.html", html_default_ask);
	html_tmpl_err = read_file("feedback_err.html", html_default_err);
	html_tmpl_ok = read_file("feedback_ok.html", html_default_ok);
	evhttp_set_gencb(httpd, process_request, NULL);
	event_base_dispatch(base);
	return 0;
}
