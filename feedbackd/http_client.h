#pragma once
#include <evhttp.h>
#include <string>

class http_request {
public:
	typedef void (*callback)(void *arg, http_request *req);
private:
	struct event_base *m_base;
	struct evhttp_connection *m_cn;
	struct evhttp_request *m_req;

	struct evbuffer *m_buffer;
	enum evhttp_cmd_type m_type;

	std::string m_query, m_host;
	int m_port;
	callback m_on_complete;
	void *m_user_data;

	void renew_request();
	static void download_callback(struct evhttp_request *req, void *arg);

public:
	http_request(struct event_base *base, const char *url, enum evhttp_cmd_type type = EVHTTP_REQ_GET);
	~http_request();

	void enqueue(callback on_complete, void *user_data);
	bool parse_uri(const char *uri);

	struct evhttp_request	*get_request() const { return m_req; }
	struct event_base		*get_event_base() const { return m_base; }
};

