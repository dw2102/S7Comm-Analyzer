#
# This is loaded unconditionally at zeek startup. Include scripts here that should
# always be loaded.
#
# Normally, that will be only code that initializes built-in elements. Load
# your standard scripts in
# scripts/<plugin-namespace>/<plugin-name>/__load__.zeek instead.
#

@load ./init.zeek
@load ./s7_setup_comm.zeek
@load ./s7_read.zeek
@load ./s7_write.zeek
@load ./s7_upload.zeek
@load ./s7_download.zeek
@load ./s7_plc_func.zeek
@load ./s7_userdata.zeek
@load ./s7p_all.zeek