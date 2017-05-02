#include "unglue_cred_plugin.h"

#include <library.h>

#include <unistd.h>
#include <utils/debug.h>
#include <credentials/sets/callback_cred.h>

typedef struct private_unglue_cred_plugin_t private_unglue_cred_plugin_t;

struct private_unglue_cred_plugin_t {
	unglue_cred_plugin_t public;
	callback_cred_t      *cb;
};

METHOD(plugin_t, get_name, char*,
	private_unglue_cred_plugin_t *this)
{
	return "unglue_cred";
}

static shared_key_t* callback_shared(private_unglue_cred_plugin_t *this,
								shared_key_type_t type,
								identification_t *me, identification_t *other,
								id_match_t *match_me, id_match_t *match_other)
{
	shared_key_t *shared;
	char id[512] = {0};
	char pw[512] = {0};
	char *dev, *acc;
	
	DBG2(DBG_CFG, "unglue cred for id: '%Y' (type: %d)", other, type);
	
	switch (type)
	{
		case SHARED_EAP:
			//label = str_from_chunk(other->get_encoding(other));
			DBG3(DBG_CFG, "type is SHARED_EAP", other);
			break;
		default:
			DBG3(DBG_CFG, "unsupported type: %d", type);
			return NULL;
	}
	
	if (match_me)
	{
		*match_me = ID_MATCH_PERFECT;
	}
	if (match_other)
	{
		*match_other = ID_MATCH_PERFECT;
	}
	
	snprintf(id, sizeof(id), "%Y", other);
	if (sscanf(id, "%m[0-9]@%m[0-9].device", &dev, &acc) != 2)
	{
		DBG1(DBG_CFG, "unable to parse the id");
		return NULL;
	}
	
	snprintf(pw, sizeof(pw), "%s.%s@unglue", acc, dev);
	free(dev);
	free(acc);
	
	DBG2(DBG_CFG, "secret: %s", pw);
	shared = shared_key_create(type, chunk_clone(chunk_from_str(pw)));
	
	return shared->get_ref(shared);
}

static bool plugin_cb(private_unglue_cred_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		
		lib->credmgr->add_set(lib->credmgr, &this->cb->set);
	}
	else
	{
		lib->credmgr->remove_set(lib->credmgr, &this->cb->set);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_unglue_cred_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "unglue"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_unglue_cred_plugin_t *this)
{
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_unglue_cred_plugin_t *this)
{
	this->cb->destroy(this->cb);
	free(this);
}

plugin_t *unglue_cred_plugin_create()
{
	private_unglue_cred_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.cb = callback_cred_create_shared((void*)callback_shared, this),
	);

	return &this->public.plugin;
}
