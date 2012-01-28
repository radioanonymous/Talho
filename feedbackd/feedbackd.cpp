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
#include "http_client.h"

#ifndef FEEDBACK_LOCATION
#	define FEEDBACK_LOCATION		"/feedback"
#endif

#ifndef UID_SALT
#	define	UID_SALT			"anon.fm"
#endif

#ifndef DIGEST_SALT
#	define	DIGEST_SALT			"type_random_letters_here"
#endif

#ifndef	SKYPE_PREFIX
#	define	SKYPE_PREFIX		"/skype"
#endif

#ifndef	SKYPE_CACHE_TIME
#	define	SKYPE_CACHE_TIME	15
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
static const char *html_tmpl_skype;
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

class skype_status {
	typedef std::map<std::string, std::pair<http_request*, skype_status*> > request_queue;
	typedef std::map<std::string, std::pair<time_t,int> > state_cache;
	typedef void (*callback_proc)(void *data, int state);
	static request_queue srq;
	static state_cache sch;
	/* Skype callback context */
	callback_proc cb;
	void *cb_data;
	skype_status *next;
	std::string login;
	skype_status(const std::string &login, callback_proc cb, void *data, skype_status *next)
		: cb(cb), cb_data(data), next(next), login(login) {}
	static void on_ready(void *ctx, http_request *req);
public:
	enum {ONLINE, DND, OFFLINE};
	static void fetch_state(event_base *base, const std::string &login, callback_proc callback, void *data); 
};

skype_status::request_queue skype_status::srq;
skype_status::state_cache skype_status::sch;

void skype_status::fetch_state(event_base *base, const std::string &login, callback_proc callback, void *data)
{
	const state_cache::const_iterator cached = sch.find(login);
	if (cached != sch.end() && cached->second.first + SKYPE_CACHE_TIME > time(NULL)) {
		callback(data, cached->second.second);
	} else {
		std::string url = "http://mystatus.skype.com/smallicon/" + login;
		request_queue::iterator rq = srq.find(login);
		if (rq == srq.end()) {
			skype_status *status = new skype_status(login, callback, data, NULL);
			http_request *req = new http_request(base, url.c_str(), EVHTTP_REQ_HEAD);
			srq.insert(request_queue::value_type(login,
						std::pair<http_request*, skype_status*>(req, status)));
			req->enqueue(on_ready, status);
		} else {
			rq->second.second = new skype_status(login, callback, data, rq->second.second);
		}
	}
}

void skype_status::on_ready(void *ctx, http_request *req)
{
	static const struct {int len, state;} status_map[] = {
		{502, ONLINE},		// chat
		{428, ONLINE},		// online
		{546, DND},			// away
		{490, DND},			// dnd
		{500, OFFLINE},		// na
		{376, OFFLINE}		// offline
	};
	int state = OFFLINE;
	const char *clen = evhttp_find_header(req->get_request()->input_headers, "Content-Length");
	if (clen) {
		int len = atoi(clen);
		for (unsigned i = 0; i < sizeof(status_map) / sizeof(*status_map); i++)
			if (len == status_map[i].len) {
				state = status_map[i].state;
				break;
			}
	}
	sch[((skype_status*)ctx)->login] = std::pair<time_t,int>(time(NULL), state);
	request_queue::iterator r = srq.find(((skype_status*)ctx)->login);
	if (r != srq.end()) {
		for (skype_status *s = r->second.second; s; ) {
			skype_status *next = s->next;
			s->cb(s->cb_data, state);
			delete s;
			s = next;
		}
		delete r->second.first;
		srq.erase(r);
	}
}

struct skype_ctx {
	struct evhttp_request *req;
	struct evbuffer *buf;
	std::string login;
	int mode;
	skype_ctx(struct evhttp_request *req, struct evbuffer *buf) : req(req), buf(buf), mode(0) {}
	~skype_ctx() {evbuffer_free(buf);}

	static void reply(void *ctx, int state);
};

void skype_ctx::reply(void *ctx, int state)
{
	skype_ctx *self = (skype_ctx*)ctx;
	if (self->mode) {
		evhttp_add_header(self->req->output_headers, "Content-Type", "application/x-javascript; charset=UTF-8");
		evbuffer_add_printf(self->buf, "{login: \"%s\", state: \"%d\"}", self->login.c_str(), state);
	} else {
		param_t args;
		evhttp_add_header(self->req->output_headers, "Content-Type", "text/html; charset=UTF-8");
		args["LOGIN"] = self->login;
		templater(self->buf, html_tmpl_skype, args);
	}
	evhttp_send_reply(self->req, HTTP_OK, "OK", self->buf);
	delete self;
}

static void process_request(struct evhttp_request *req, void *arg)
{
	struct event_base *base = (struct event_base*)arg;
	struct evbuffer *buf = evbuffer_new();
	if (!buf)
		return;
	generate_uid(req);
	const char *uri = evhttp_request_uri(req);
	if (memcmp(uri, FEEDBACK_LOCATION, sizeof(FEEDBACK_LOCATION) - 1) == 0) {
		uri += sizeof(FEEDBACK_LOCATION) - 1;
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
			p["PREFIX"] = FEEDBACK_LOCATION;
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
	/* Skype icon */
	} else if (memcmp(uri, SKYPE_PREFIX, sizeof(SKYPE_PREFIX) - 1) == 0) {
		struct skype_ctx *ctx = new skype_ctx(req, buf);
		uri += sizeof(SKYPE_PREFIX) - 1;
		int len = strlen(uri);
		if (len > 4 && memcmp(uri + len - 3, ".js", 3) == 0) {
			ctx->mode = 1;
			ctx->login.assign(uri + 1, uri + len - 3);
		} else {
			ctx->login = uri + 1;
		}
		skype_status::fetch_state(base, ctx->login, skype_ctx::reply, ctx);
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

extern char html_default_ask[], html_default_err[], html_default_ok[], html_default_skype[];

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
	html_tmpl_skype = read_file("skype_status.html", html_default_skype);
	evhttp_set_gencb(httpd, process_request, base);
	event_base_dispatch(base);
	evhttp_free(httpd);
	event_base_free(base);
	return 0;
}
