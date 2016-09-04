/**
 * @defgroup balancer_provider balancer_provider
 * @{ @ingroup redirect
 */

#ifndef BALANCER_PROVIDER_H_
#define BALANCER_PROVIDER_H_

#include <sa/redirect_provider.h>

typedef struct balancer_provider_t balancer_provider_t;

/**
 * Provide balancer.
 */
struct balancer_provider_t {

	/**
	 * Implements redirect provider interface
	 */
	redirect_provider_t provider;

	/**
	 * Reload configuration from strongswan.conf.
	 */
	void (*reload)(balancer_provider_t *this);

	/**
	 * Destroy a balancer_provider instance.
	 */
	void (*destroy)(balancer_provider_t *this);
};

/**
 * Create a balancer_provider instance.
 */
balancer_provider_t *balancer_provider_create();

#endif /** BALANCER_PROVIDER @}*/
