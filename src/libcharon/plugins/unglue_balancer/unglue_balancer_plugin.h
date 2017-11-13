/**
 * @defgroup attr attr
 * @ingroup cplugins
 *
 * @defgroup attr_plugin attr_plugin
 * @{ @ingroup attr
 */

#ifndef UNGLUE_BALANCER_PLUGIN_H_
#define UNGLUE_BALANCER_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct unglue_balancer_plugin_t unglue_balancer_plugin_t;

/**
 * Plugin providing configuration attribute through strongswan.conf.
 */
struct unglue_balancer_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** UNGLUE_BALANCER_PLUGIN_H_ @}*/