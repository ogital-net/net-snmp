/*
 * module to include the modules
 */

#if defined(HAVE_VPP_DATAPLANE)
config_require(etherlike-mib/data_access/dot3stats_vpp);
#elif defined(linux)
config_require(etherlike-mib/data_access/dot3stats_linux);
#endif
