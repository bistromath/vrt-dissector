#include "config.h"
#include <epan/packet.h>

#define VRT_PORT 1234

static int proto_vrt = -1;

//fields
static int hf_vrt_header = -1; //32-bit header
static int hf_vrt_type = -1; //4-bit pkt type
static int hf_vrt_cidflag = -1; //1-bit class ID flag
static int hf_vrt_tflag = -1; //1-bit trailer flag
static int hf_vrt_tsi = -1; //2-bit timestamp type
static int hf_vrt_tsf = -1; //2-bit fractional timestamp type
static int hf_vrt_seq = -1; //4-bit sequence number
static int hf_vrt_len = -1; //16-bit length
static int hf_vrt_sid = -1; //32-bit stream ID (opt.)
static int hf_vrt_cid = -1; //64-bit class ID (opt.)
static int hf_vrt_ts_int = -1; //32-bit integer timestamp (opt.)
static int hf_vrt_ts_frac = -1; //64-bit fractional timestamp (opt.)
static int hf_vrt_data = -1; //data
static int hf_vrt_trailer = -1; //32-bit trailer (opt.)

//subtree state variables
static gint ett_vrt = -1;

static void dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "vrt");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    int offset = 0;

    if(tree) { //we're being asked for details
        proto_item *ti;
        proto_item *vrt_tree;
        ti = proto_tree_add_item(tree, proto_vrt, tvb, 0, -1, ENC_NA);
        vrt_tree = proto_item_add_subtree(ti, ett_vrt);
        proto_tree_add_item(vrt_tree, hf_vrt_header, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else { //we're being asked for a summary

    }
}

void
proto_register_vrt(void)
{
    static hf_register_info hf[] = {
        { &hf_vrt_header,
            { "VRT header", "vrt.hdr",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = { &ett_vrt };

    proto_vrt = proto_register_protocol (
        "VITA 49 radio transport protocol", /* name       */
        "vrt",      /* short name */
        "vrt"       /* abbrev     */
        );

    proto_register_field_array(proto_vrt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vrt(void)
{
    static dissector_handle_t vrt_handle;

    vrt_handle = create_dissector_handle(dissect_vrt, proto_vrt);
    dissector_add_uint("udp.port", VRT_PORT, vrt_handle);
}


