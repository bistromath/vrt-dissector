#include "config.h"

#include <epan/packet.h>

#define VRT_PORT 1234

static int proto_vrt = -1;

void
proto_register_foo(void)
{
    proto_vrt = proto_register_protocol (
        "VITA 49 radio transport protocol", /* name       */
        "VITA 49",      /* short name */
        "VRT"       /* abbrev     */
        );
}

void
proto_reg_handoff_vrt(void)
{
    static dissector_handle_t vrt_handle;

    vrt_handle = create_dissector_handle(dissect_vrt, proto_vrt);
    dissector_add_uint("udp.port", VRT_PORT, vrt_handle);
}

static void dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VRT");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
}
