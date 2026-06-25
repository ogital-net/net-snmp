/*
 * module to include the modules
 */

#if defined(HAVE_VPP_DATAPLANE)
config_require(rmon-mib/data_access/etherstats_vpp);
#elif defined(linux)
config_require(rmon-mib/data_access/etherstats_linux);
#endif
