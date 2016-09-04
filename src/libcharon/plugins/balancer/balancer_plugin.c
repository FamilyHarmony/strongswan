#include "balancer_plugin.h"
#include "balancer_provider.h"

#include <daemon.h>

typedef struct private_balancer_plugin_t private_balancer_plugin_t;

struct private_balancer_plugin_t {
	balancer_plugin_t public;
	balancer_provider_t *provider;
};

METHOD(plugin_t, get_name, char*,
	private_balancer_plugin_t *this)
{
	return "balancer";
}

static bool plugin_cb(private_balancer_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->redirect->add_provider(charon->redirect,
									   &this->provider->provider);
	}
	else
	{
		charon->redirect->remove_provider(charon->redirect,
									      &this->provider->provider);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_balancer_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "redirect"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_balancer_plugin_t *this)
{
	this->provider->reload(this->provider);
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_balancer_plugin_t *this)
{
	this->provider->destroy(this->provider);
	free(this);
}

plugin_t *balancer_plugin_create()
{
	private_balancer_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.provider = balancer_provider_create(),
	);

	return &this->public.plugin;
}
