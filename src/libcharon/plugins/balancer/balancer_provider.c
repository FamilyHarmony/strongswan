#include "balancer_provider.h"

#include <time.h>

#include <daemon.h>
#include <utils/debug.h>
#include <utils/identification.h>


typedef struct private_balancer_provider_t private_balancer_provider_t;
typedef struct attribute_entry_t attribute_entry_t;

struct private_balancer_provider_t {
	balancer_provider_t public;
	char *command;
};

METHOD(redirect_provider_t, redirect_on_init, bool,
	private_balancer_provider_t *this,
	ike_sa_t *ike_sa, identification_t **gateway)
{
    FILE *fp;
    char gw[1024];

    fp = popen(this->command, "r");
    if (fp == NULL) {
        DBG1(DBG_CFG, "unable to execute command: '%s'", this->command);
    } else {
        DBG3(DBG_CFG, "balancer command succeeded");
        if (fgets(gw, sizeof(gw)-1, fp) != NULL) {
            DBG2(DBG_CFG, "got balancer command response: '%s'", gw);
            *gateway = identification_create_from_string(gw);
            if (*gateway != NULL) {
                DBG3(DBG_CFG, "gateway is valid, redirecting...");
                return TRUE;
            }
        }
    }
    return FALSE;
}

METHOD(redirect_provider_t, redirect_on_auth, bool,
	private_balancer_provider_t *this,
	ike_sa_t *ike_sa, identification_t **gateway)
{
    DBG3(DBG_CFG, "skipping AUTH redirect");
    return FALSE;
}

METHOD(balancer_provider_t, destroy, void,
	private_balancer_provider_t *this)
{
	free(this);
}

METHOD(balancer_provider_t, reload, void,
	private_balancer_provider_t *this)
{
	this->command = lib->settings->get_str(lib->settings, "%s.plugins.balancer.command", NULL, lib->ns);
	DBG1(DBG_CFG, "reloaded balancer plugin command: %s", this->command);
}

balancer_provider_t *balancer_provider_create(database_t *db)
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

	this->command = lib->settings->get_str(lib->settings, "%s.plugins.balancer.command", NULL, lib->ns);
	DBG1(DBG_CFG, "loaded balancer plugin command: %s", this->command);

	return &this->public;
}
