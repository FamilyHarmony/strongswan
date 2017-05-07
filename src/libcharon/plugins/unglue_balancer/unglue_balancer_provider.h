/**
 * @defgroup balancer_provider balancer_provider
 * @{ @ingroup redirect
 */

#ifndef UNGLUE_BALANCER_PROVIDER_H_
#define UNGLUE_BALANCER_PROVIDER_H_

#include <sa/redirect_provider.h>

typedef struct unglue_balancer_provider_t unglue_balancer_provider_t;

/**
 * Provide balancer.
 */
struct unglue_balancer_provider_t {

	/**
	 * Implements redirect provider interface
	 */
	redirect_provider_t provider;

	/**
	 * Reload configuration from strongswan.conf.
	 */
	void (*reload)(unglue_balancer_provider_t *this);

	/**
	 * Destroy a balancer_provider instance.
	 */
	void (*destroy)(unglue_balancer_provider_t *this);
};

/**
 * Create a balancer_provider instance.
 */
unglue_balancer_provider_t *unglue_balancer_provider_create();

#endif /** UNGLUE_BALANCER_PROVIDER @}*/
