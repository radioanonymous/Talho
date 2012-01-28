#include "http_client.h"
#include <event.h>
#include <evhttp.h>
#include <stdexcept>
#include <string.h>
#include <stdlib.h>

void http_request::enqueue(callback on_complete, void *user_data)
{
	m_on_complete = on_complete;
	m_user_data = user_data;
	renew_request();
}

void
http_request::download_callback(struct evhttp_request *req, void *arg)
{
	http_request *self = (http_request*)arg;
//	struct evhttp_uri *new_uri = NULL;
//	const char *new_location = NULL;

	/* response is ready */

	switch(req->response_code)
	{
		/*
	case HTTP_MOVEPERM:
	case HTTP_MOVETEMP:
		new_location = evhttp_find_header(req->input_headers, "Location");
		if (!new_location)
			return;

		new_uri = evhttp_uri_parse(new_location);
		if (!new_uri)
			return;

		evhttp_uri_free(self->m_uri);
		self->m_uri = new_uri;

		download_renew_request(ctx);
		return;
*/
	}

	self->m_on_complete(self->m_user_data, self);
}

bool http_request::parse_uri(const char *uri)
{
	const char *p;
	if (memcmp(uri, "http://", sizeof("http://") - 1) != 0)
		return false;
	m_host.clear();
	m_port = 80;
	/* 1. Extract host part */
	for (p = uri + sizeof("http://") - 1; *p && *p != ':' && *p != '/'; p++) ;
	m_host.assign(uri + sizeof("http://") - 1, p);
	if (*p == ':')
		m_port = strtol(p, (char**)&p, 10);
	if (*p == '/')
		m_query = p;
	else
		m_query = '/';
	return true;
}

http_request::http_request(struct event_base *base, const char *url, enum evhttp_cmd_type type)
	: m_base(base), m_type(type), m_cn(NULL), m_req(NULL), m_buffer(NULL)
{
#if 0
	struct evhttp_uri *uri = evhttp_uri_parse(url);
	if (!uri)
		throw std::runtime_error("Can't parse uri");
	m_host = evhttp_uri_get_host(uri);
	m_port = evhttp_uri_get_port(uri);
	if (m_port == -1)
		m_port = 80;
	if (evhttp_uri_get_query(uri))
		m_query = evhttp_uri_get_query(uri);
	else
		m_query = "/";
	printf("query: \"%s\"\n", evhttp_uri_get_query(uri));
	evhttp_uri_free(uri);
#else
	if (!parse_uri(url))
		throw std::runtime_error("Can't parse uri");
#endif

	m_buffer = evbuffer_new();

//	renew_request(ctx);
}

http_request::~http_request()
{

	if (m_cn)
		evhttp_connection_free(m_cn);

	if (m_buffer)
		evbuffer_free(m_buffer);

}

void 
http_request::renew_request()
{
	/* free connections & request */
	if (m_cn)
		evhttp_connection_free(m_cn);

#if !defined(_EVENT_NUMERIC_VERSION) || _EVENT_NUMERIC_VERSION < 0x02000000
	m_cn = evhttp_connection_new(m_host.c_str(), m_port);
	evhttp_connection_set_base(m_cn, m_base);
#else
	m_cn = evhttp_connection_base_new(
		m_base, NULL, 
		m_host.c_str(),
		m_port);
#endif

	m_req = evhttp_request_new(http_request::download_callback, this);

	evhttp_make_request(m_cn, m_req, m_type, m_query.c_str());

	evhttp_add_header(m_req->output_headers,
                            "Host", m_host.c_str());
}

