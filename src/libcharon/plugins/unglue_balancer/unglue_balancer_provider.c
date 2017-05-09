#include "unglue_balancer_provider.h"

#include <time.h>

#include <daemon.h>
#include <utils/debug.h>
#include <utils/identification.h>


typedef struct private_balancer_provider_t private_balancer_provider_t;
typedef struct attribute_entry_t attribute_entry_t;

struct private_balancer_provider_t {
	unglue_balancer_provider_t public;
	char *url_template;
	int timeout;
};

METHOD(redirect_provider_t, redirect_on_init, bool,
	private_balancer_provider_t *this,
	ike_sa_t *ike_sa, identification_t **gateway)
{
    host_t *client_host;
    char url[512] = {0};
	bool result = FALSE;

	if (!this->url_template || !strstr(this->url_template, "%H"))
	{
		DBG1(DBG_LIB, "unglue-balancer URL template is empty or invalid, redirect disabled");
		return FALSE;
	}

	client_host = ike_sa->get_other_host(ike_sa);
	DBG2(DBG_LIB, "unglue-balancer client IP address: %H", client_host);

	snprintf(url, sizeof(url), this->url_template, client_host);

	status_t status;
	int code = 0;
	chunk_t response = chunk_empty;

	status = lib->fetcher->fetch(lib->fetcher, url, &response,
				FETCH_TIMEOUT, this->timeout,
				FETCH_RESPONSE_CODE, &code,
				FETCH_END);

	if (status == SUCCESS)
	{
		if (response.ptr)
		{
			if (code == 200)
			{
				DBG2(DBG_LIB, "unglue-balancer API call OK (status=%d, code=%d, resp %B)", status, code, &response);

				u_char *nl = NULL;
				chunk_t ip = chunk_empty;

				nl = memchr(response.ptr, '\r', response.len);
				if (!nl)
					nl = memchr(response.ptr, '\n', response.len);
				if (nl)
				{
					ip = chunk_create(response.ptr, nl - response.ptr);
					DBG2(DBG_LIB, "unglue-balancer IP %B", &ip);
					*gateway = identification_create_from_data(ip);
					if (*gateway)
					{
						DBG2(DBG_LIB, "unglue-balancer gateway identification is valid, redirecting...");
						result = TRUE;
					}
					else
					{
						DBG1(DBG_LIB, "unglue-balancer is unable to create gateway identification");
					}
				}
				else
				{
					DBG1(DBG_LIB, "unglue-balancer API response body is invalid, resp %B", &response);
				}
			}
			else
			{
				DBG1(DBG_IMV, "unglue-balancer API call failed, code=%d", code);
			}
			chunk_clear(&response);
		}
		else
		{
			DBG1(DBG_IMV, "unglue-balancer API call failed, resp %B", code);
		}
	}
	else
	{
		DBG1(DBG_LIB, "unglue-balancer API call failed, status=%d", status);
	}

	return result;
}

METHOD(redirect_provider_t, redirect_on_auth, bool,
	private_balancer_provider_t *this,
	ike_sa_t *ike_sa, identification_t **gateway)
{
    DBG3(DBG_CFG, "skipping AUTH redirect");
    return FALSE;
}

METHOD(unglue_balancer_provider_t, destroy, void,
	private_balancer_provider_t *this)
{
	free(this);
}

METHOD(unglue_balancer_provider_t, reload, void,
	private_balancer_provider_t *this)
{
	this->url_template = lib->settings->get_str(lib->settings, "%s.plugins.unglue-balancer.url", NULL, lib->ns);
	this->timeout = lib->settings->get_int(lib->settings, "%s.plugins.unglue-balancer.timeout", 3, lib->ns);
	DBG1(DBG_CFG, "unglue-balancer re-loaded: URL=%s, timeout=%d", this->url_template, this->timeout);
}

unglue_balancer_provider_t *unglue_balancer_provider_create(database_t *db)
{
	private_balancer_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.redirect_on_init = _redirect_on_init,
				.redirect_on_auth = _redirect_on_auth,
			},
			.reload = _reload,
			.destroy = _destroy,
		}
	);

	this->url_template = lib->settings->get_str(lib->settings, "%s.plugins.unglue-balancer.url", NULL, lib->ns);
	this->timeout = lib->settings->get_int(lib->settings, "%s.plugins.unglue-balancer.timeout", 3, lib->ns);
	DBG1(DBG_CFG, "unglue-balancer loaded: URL=%s, timeout=%d", this->url_template, this->timeout);

	return &this->public;
}
