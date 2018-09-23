#
# This is loaded unconditionally at Bro startup. Include scripts here that should
# always be loaded.
#
# Normally, that will be only code that initializes built-in elements. Load
# your standard scripts in
# scripts/<plugin-namespace>/<plugin-name>/__load__.bro instead.
#

@load ./init.bro
@load ./s7_setup_comm.bro
@load ./s7_read.bro
@load ./s7_write.bro
@load ./s7_upload.bro
@load ./s7_download.bro
@load ./s7_plc_func.bro
@load ./s7_userdata.bro
@load ./s7p_all.bro
# @load ./testanlage_druck.bro
# @load ./testanlage_sensoren.bro
# @load ./testanlage_put_standard.bro
# @load ./testanlage_put_actors.bro
# @load s7_dfa.bro