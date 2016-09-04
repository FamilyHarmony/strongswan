/**
 * @defgroup attr attr
 * @ingroup cplugins
 *
 * @defgroup attr_plugin attr_plugin
 * @{ @ingroup attr
 */

#ifndef BALANCER_PLUGIN_H_
#define BALANCER_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct balancer_plugin_t balancer_plugin_t;

/**
 * Plugin providing configuration attribute through strongswan.conf.
 */
struct balancer_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** BALANCER_PLUGIN_H_ @}*/
