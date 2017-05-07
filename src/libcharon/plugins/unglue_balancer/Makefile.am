AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-unglue-balancer.la
else
plugin_LTLIBRARIES = libstrongswan-unglue-balancer.la
endif

libstrongswan_unglue_balancer_la_SOURCES = \
	unglue_balancer_plugin.h unglue_balancer_plugin.c \
	unglue_balancer_provider.h unglue_balancer_provider.c

libstrongswan_unglue_balancer_la_LDFLAGS = -module -avoid-version
