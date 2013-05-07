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
#include <ctemplate/template.h>
#include "http_client.h"
#include "meta-parser.h"

using ctemplate::TemplateDictionary;
using ctemplate::LoadTemplate;
using ctemplate::StringToTemplateCache;
using ctemplate::STRIP_WHITESPACE;
using ctemplate::TemplateString;
using ctemplate::ExpandTemplate;

static const TemplateString tmpl_ask("feedback_ask.html"), tmpl_ok("feedback_ok.html"), tmpl_skype("skype_status.html");

namespace id {
#include "tpl_ask.h"
#include "tpl_ok.h"
#include "tpl_skype.h"
};

#define	PRERENDER_GIFS


#ifndef FEEDBACK_LOCATION
#	define FEEDBACK_LOCATION		"/feedback"
#endif

#ifndef	FEEDBACK_MAX_LENGTH
#	define FEEDBACK_MAX_LENGTH		140
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

#ifndef	SONGDL_LOCATION
#	define	SONGDL_LOCATION			"/song/"
#endif

#ifndef	SONGDL_MPD_PID
#	define	SONGDL_MPD_PID			"/radio/mpd/pid"
#endif

#define	SONGDL_FD					3
#ifndef	SONGDL_MUSIC_PREFIX
#	define	SONGDL_MUSIC_PREFIX			"/radio/mpd/music/"
#endif

#ifndef	SONGDL_MUSIC_ACCEL
#	define	SONGDL_MUSIC_ACCEL			"/songdl"
#endif

static int utf8_strlen(const std::string &str)
{
	const unsigned char *ptr = (const unsigned char*)str.c_str();
	int len = 0;
	while (*ptr) {
		/* ASCII symbols */
		if (*ptr < 0x80) {
			ptr++;
		} else if ((*ptr & 0xe0) == 0xc0 && (ptr[1] & 0xc0) == 0x80) {
			/* 0x80 - 0x7FF */
			ptr += 2;
		} else if ((*ptr & 0xf0) == 0xe0 && (ptr[1] & 0xc0) == 0x80 && (ptr[2] & 0xc0) == 0x80) {
			/* 0x800 - 0xffff */
			ptr += 3;
		} else {
			ptr++;
			while ((*ptr & 0xc0) == 0x80) ptr++;
		}
		len++;
	}
	return len;
}

struct cdata {
	unsigned		id;
	char			content[6];
#ifdef	PRERENDER_GIFS
	unsigned char	gif[GIFSIZE];
#endif
	time_t			ctime;
	struct cdata	*prev, *next;
};

class Captcha {
public:
	Captcha() : m_head(NULL), m_tail(NULL) {}
	void		show_html(struct evbuffer *buf, const TemplateString &tmpl, TemplateDictionary &p);
	bool		show_gif(struct evbuffer *buf, unsigned id);
	bool		validate(unsigned id, const char *text);
private:
	unsigned generate();
	cdata *new_captcha(unsigned id, time_t now);
	typedef std::map<unsigned, cdata*> ccache;
	cdata		*m_head, *m_tail;

	ccache captchas;
};

cdata *Captcha::new_captcha(unsigned id, time_t now)
{
	cdata *c = new cdata;
	if (m_head)
		m_head->prev = c;
	c->next = m_head;
	m_head = c;
	if (!m_tail)
		m_tail = c;
	c->prev = NULL;

	c->id = id;
	c->ctime = now;
#ifdef	PRERENDER_GIFS
	unsigned char im[70*200];
	captcha(im, (unsigned char*)c->content);
	makegif(im, c->gif);
#else
	captcha_generate((unsigned char*)c->content);
#endif
	return c;
}

unsigned Captcha::generate()
{
	unsigned r = 0;
	time_t now = time(NULL);
	/* Remove all old captchas first */
	while (m_tail && (m_tail->ctime + 300 < now || captchas.size() > 5000)) { // don't allow number of captchas to grow above 5000 entries
		cdata *prev = m_tail->prev;
		r = m_tail->id;
		captchas.erase(m_tail->id);
		delete m_tail;
		m_tail = prev;
	}
	if (m_tail)
		m_tail->next = NULL;
	else
		m_head = NULL;

	if (!r) {
		/* Find free identificator for captcha */
		Captcha::ccache::iterator c;
		for (unsigned i = 0; i < 100; i++) {
			r = random() % 900000 + 100000;
			Captcha::ccache::iterator c = captchas.find(r);
			if (c == captchas.end()) {
				captchas.insert(Captcha::ccache::value_type(r, new_captcha(r, now)));
				return r;
			}
		}
		/* We haven't succeeded to find spare id in 100 hits, so make two users solve same captcha (updating it's ctime) */
		cdata *cap = c->second;
		if (cap->next)
			cap->next->prev = cap->prev;
		else
			m_tail = cap->prev;
		if (cap->prev) {
			cap->prev->next = cap->next;
			cap->next = m_head;
			if (m_head)
				m_head->prev = cap;
			m_head = cap;
		}
		cap->ctime = now;
	} else {
		/* Generate new captcha */
		captchas.insert(Captcha::ccache::value_type(r, new_captcha(r, now)));
	}

	return r;
}

class evbuffer_emitter : public ctemplate::ExpandEmitter {
	struct evbuffer *out;
public:
	evbuffer_emitter(struct evbuffer *out) : out(out) {}
	virtual void Emit(char c) { evbuffer_add(out, &c, 1); }
	virtual void Emit(const std::string& s) { evbuffer_add(out, s.c_str(), s.length()); }
	virtual void Emit(const char* s) { evbuffer_add(out, s, strlen(s)); }
	virtual void Emit(const char* s, size_t slen) { evbuffer_add(out, s, slen); }
};

static void templater(struct evbuffer *buf, const TemplateString &tmpl, TemplateDictionary &args)
{
	evbuffer_emitter out(buf);
	ExpandTemplate(tmpl, STRIP_WHITESPACE, &args, &out);
}

void Captcha::show_html(struct evbuffer *buf, const TemplateString &tmpl, TemplateDictionary &args)
{
	unsigned cap = generate();
	args.SetIntValue(id::kda_CAPTCHA, cap);
	args.SetFormattedValue(id::kda_GIF, "%s/%u.gif", FEEDBACK_LOCATION, cap);
	templater(buf, tmpl, args);
}

bool Captcha::show_gif(struct evbuffer *buf, unsigned id)
{
	Captcha::ccache::const_iterator c = captchas.find(id);
	if (c != captchas.end()) {
#ifdef	PRERENDER_GIFS
		evbuffer_add(buf, c->second->gif, GIFSIZE);
#else
		unsigned char im[70*200];
		unsigned char gif[GIFSIZE];
		captcha_render(im, (const unsigned char*)c->second->content);
		makegif(im, gif);
		evbuffer_add(buf, gif, GIFSIZE);
#endif
		return true;
	}
	return false;
}

bool Captcha::validate(unsigned id, const char *text)
{
	Captcha::ccache::iterator c = captchas.find(id);
	if (c != captchas.end()) {
		cdata *cap = c->second;
		bool match = strncasecmp(text, c->second->content, sizeof(c->second->content) - 1) == 0;

		/* Erase captcha */
		if (cap->prev)
			cap->prev->next = cap->next;
		else
			m_head = cap->next;
		if (cap->next)
			cap->next->prev = cap->prev;
		else
			m_tail = cap->prev;
		delete cap;
		captchas.erase(c);
	
		return match;
	}
	return false;
}

static Captcha cc;
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
		TemplateDictionary args("skype");
		evhttp_add_header(self->req->output_headers, "Content-Type", "text/html; charset=UTF-8");
		if (state == skype_status::ONLINE)
			args.SetValueAndShowSection(id::kds_LOGIN, self->login, id::kds_IF_ONLINE);
		templater(self->buf, tmpl_skype, args);
	}
	evhttp_send_reply(self->req, HTTP_OK, "OK", self->buf);
	delete self;
}

static bool get_songpath(char *buf, int bufsz)
{
	int pid;
	char path[1024];
	FILE *pf = fopen(SONGDL_MPD_PID, "r");
	if (!pf)
		return false;
	if (fscanf(pf, "%d", &pid) != 1) {
		fclose(pf);
		return false;
	}
	fclose(pf);

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, SONGDL_FD);
	pid = readlink(path, buf, bufsz);
	if (pid > 0 && pid < bufsz) {
		path[pid] = 0;
		return true;
	}
	return false;
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
			TemplateDictionary p("feedback");
			static const std::string
				form_captcha = "cid",
				form_check = "check",
				form_msg = "msg";
			p.SetValue(id::kda_PREFIX, FEEDBACK_LOCATION);
			p.SetValue(id::kda_PCAPTCHA, form_captcha);
			p.SetValue(id::kda_PCHECK, form_check);
			p.SetValue(id::kda_PMSG, form_msg);
			p.SetIntValue(id::kda_MAXLEN, FEEDBACK_MAX_LENGTH);
			evhttp_add_header(req->output_headers, "Content-Type", "text/html; charset=UTF-8");
			if (evhttp_request_get_command(req) == EVHTTP_REQ_POST) {
				const TemplateString *tmpl = &tmpl_ask;
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
					std::string message;
					if (msg) {
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
							message += out;
						}
						p.SetValue(id::kda_MSG, message);
					}
					FINZ(text);
					FINZ(cid);
#undef FINZ
					if (text && cid && cc.validate(strtoul(cid, NULL, 10), text)) {
						if (text && utf8_strlen(message) <= FEEDBACK_MAX_LENGTH) {
							std::string uid = generate_uid(req);
							std::string raw_message = "From " + uid + "  " + message;
							tmpl = &tmpl_ok;
							p.SetValue(id::kdo_UID, uid);
							say(raw_message);
						} else {
							p.ShowSection(id::kda_IF_MSG_TOO_LONG);
						}
					} else {
						p.ShowSection(id::kda_IF_BAD_CAPTCHA);
					}
				}
				cc.show_html(buf, *tmpl, p);
			} else {
				cc.show_html(buf, tmpl_ask, p);
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
	/* Song DL */
	} else if (memcmp(uri, SONGDL_LOCATION, sizeof(SONGDL_LOCATION) - 1) == 0) {
		char songpath[2048];
		char b[2048];
		if (!get_songpath(songpath, sizeof(songpath)))
			goto notfound;
		if (memcmp(songpath, SONGDL_MUSIC_PREFIX, sizeof(SONGDL_MUSIC_PREFIX) - 1) != 0)
			goto notfound;
		std::string ctt = "audio/mpeg", fn = meta_parse(songpath, &ctt);
		snprintf(b, sizeof(b), "attachment; filename=\"%s\"", fn.c_str());
		evhttp_add_header(req->output_headers, "Content-Disposition", b);
		snprintf(b, sizeof(b), "%s/%s", SONGDL_MUSIC_ACCEL, songpath + sizeof(SONGDL_MUSIC_PREFIX) - 1);
		evhttp_add_header(req->output_headers, "X-Accel-Redirect", b);
		evhttp_add_header(req->output_headers, "Content-Type", ctt.c_str());
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

extern char html_default_ask[], html_default_ok[], html_default_skype[];

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
	if (!LoadTemplate(tmpl_ask, STRIP_WHITESPACE))
		StringToTemplateCache(tmpl_ask, html_default_ask, STRIP_WHITESPACE);
	if (!LoadTemplate(tmpl_ok, STRIP_WHITESPACE))
		StringToTemplateCache(tmpl_ok, html_default_ok, STRIP_WHITESPACE);
	if (!LoadTemplate(tmpl_skype, STRIP_WHITESPACE))
		StringToTemplateCache(tmpl_skype, html_default_skype, STRIP_WHITESPACE);
	meta_init();
	evhttp_set_gencb(httpd, process_request, base);
	event_base_dispatch(base);
	evhttp_free(httpd);
	event_base_free(base);
	meta_cleanup();
	return 0;
}
