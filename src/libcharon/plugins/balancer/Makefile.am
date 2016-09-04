AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-balancer.la
else
plugin_LTLIBRARIES = libstrongswan-balancer.la
endif

libstrongswan_balancer_la_SOURCES = \
	balancer_plugin.h balancer_plugin.c \
	balancer_provider.h balancer_provider.c

libstrongswan_balancer_la_LDFLAGS = -module -avoid-version
