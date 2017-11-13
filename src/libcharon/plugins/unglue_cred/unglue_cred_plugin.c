#include "unglue_cred_plugin.h"

#include <library.h>

#include <unistd.h>
#include <utils/debug.h>
#include <credentials/sets/callback_cred.h>

#define UG_MAX_KEYS 10

typedef struct private_unglue_cred_plugin_t private_unglue_cred_plugin_t;

struct private_unglue_cred_plugin_t {
	unglue_cred_plugin_t public;
	callback_cred_t      *cb;
	char*                keys[UG_MAX_KEYS];
	bool                 enable_hmac;
	bool                 enable_plain;
};

METHOD(plugin_t, get_name, char*, private_unglue_cred_plugin_t *this)
{
	return "unglue-cred";
}

static shared_key_t* callback_shared(private_unglue_cred_plugin_t *this,
								shared_key_type_t type,
								identification_t *me, identification_t *other,
								id_match_t *match_me, id_match_t *match_other)
{
	shared_key_t *shared;
	char id[512] = {0};
	char pw[512] = {0};
	uint dev, acc;
	uint key_no;
	
	DBG2(DBG_IKE, "unglue cred: for id '%Y' (type: %d)", other, type);
	
	switch (type)
	{
		case SHARED_EAP:
			//label = str_from_chunk(other->get_encoding(other));
			DBG2(DBG_IKE, "type is SHARED_EAP", other);
			break;
		default:
			DBG2(DBG_IKE, "unsupported type: %d", type);
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

	if (this->enable_hmac && sscanf(id, "%u@%u.hmac-S%u", &dev, &acc, &key_no) == 3)
	{
		DBG1(DBG_IKE, "unglue-cred: type = hmac");

		snprintf(pw, sizeof(pw), "%u.%u", acc, dev);
		DBG1(DBG_IKE, "unglue-cred: secret hmac pw: %s, key#: %u", pw, key_no);

		if (key_no >= UG_MAX_KEYS)
		{
			DBG1(DBG_IKE, "warning: requested key #%u is invalid (# > 10), unable to sign", key_no);
			return NULL;
		}

		if (this->keys[key_no] == NULL)
		{
			DBG1(DBG_IKE, "warning: requested key #%u is NULL, unable to sign", key_no);
			return NULL;
		}

		DBG2(DBG_IKE, "key #%u is %s", key_no, this->keys[key_no]);

		char sig_hex[41] = {0};
		uint8_t sig[20] = {0};

		signer_t *signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_160);
		if (!signer)
		{
			DBG0(DBG_LIB, "error: unable to create AUTH_HMAC_SHA1_160 signer");
			return NULL;
		}
		if (!signer->set_key(signer, chunk_from_str(this->keys[key_no])))
		{
			DBG0(DBG_IKE, "error: unable to set key #%u", key_no);
			return NULL;
		}
		if (!signer->get_signature(signer, chunk_from_str(pw), sig))
		{
			DBG0(DBG_IKE, "error: unable to get signature with key #%u and pw: %s", key_no, pw);
			return NULL;
		}
		signer->destroy(signer);

		chunk_to_hex(chunk_from_thing(sig), sig_hex, FALSE);
		DBG1(DBG_IKE, "secret hmac: %s", sig_hex);

		shared = shared_key_create(type, chunk_clone(chunk_from_str(sig_hex)));
		return shared->get_ref(shared);
	}

	if (this->enable_plain && sscanf(id, "%d@%d.device", &dev, &acc) == 2)
	{
		DBG1(DBG_IKE, "unglue-cred: type = plain");

		snprintf(pw, sizeof(pw), "%u.%u@unglue", acc, dev);
		DBG1(DBG_IKE, "unglue-cred: secret plain pw: %s", pw);

		shared = shared_key_create(type, chunk_clone(chunk_from_str(pw)));
		return shared->get_ref(shared);
	}

	DBG1(DBG_IKE, "warning: unable to parse the id, unknown or disabled secret type");
	return NULL;
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
			PLUGIN_PROVIDE(CUSTOM, "unglue-cred"),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(SIGNER, AUTH_HMAC_SHA1_160),
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

	this->enable_hmac = lib->settings->get_bool(lib->settings, "%s.plugins.unglue-cred.hmac", TRUE, lib->ns);
	this->enable_plain = lib->settings->get_bool(lib->settings, "%s.plugins.unglue-cred.plain", FALSE, lib->ns);

	DBG0(DBG_CFG, "unglue-cred: hmac=%s, plain=%s", this->enable_hmac ? "yes" : "no", this->enable_plain ? "yes" : "no");

	this->keys[0] = lib->settings->get_str(lib->settings, "%s.plugins.unglue-cred.key0", NULL, lib->ns);
	this->keys[1] = lib->settings->get_str(lib->settings, "%s.plugins.unglue-cred.key1", NULL, lib->ns);
	this->keys[2] = lib->settings->get_str(lib->settings, "%s.plugins.unglue-cred.key2", NULL, lib->ns);
	this->keys[3] = lib->settings->get_str(lib->settings, "%s.plugins.unglue-cred.key3", NULL, lib->ns);
	for (uint i = 0; i < UG_MAX_KEYS; i++) {
		if (this->keys[i] != NULL) DBG0(DBG_CFG, "unglue-cred: loaded key #%u", i);
	}

	return &this->public.plugin;
}
