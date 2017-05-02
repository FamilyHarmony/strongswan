AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-unglue-cred.la
else
plugin_LTLIBRARIES = libstrongswan-unglue-cred.la
endif

libstrongswan_unglue_cred_la_SOURCES = \
	unglue_cred_plugin.h unglue_cred_plugin.c

libstrongswan_unglue_cred_la_LDFLAGS = -module -avoid-version
