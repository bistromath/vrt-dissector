#include "config.h"
#include <epan/packet.h>

#define VRT_PORT 49156

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
static int hf_vrt_ts_frac_picosecond = -1; //64-bit fractional timestamp (opt.)
static int hf_vrt_ts_frac_sample = -1; //64-bit fractional timestamp (opt.)
static int hf_vrt_data = -1; //data
static int hf_vrt_trailer = -1; //32-bit trailer (opt.)

//subtree state variables
static gint ett_vrt = -1;
static gint ett_header = -1;

static const value_string packet_types[] = {
    {0x00, "IF data packet without stream ID"},
    {0x01, "IF data packet with stream ID"},
    {0x02, "Extension data packet without stream ID"},
    {0x03, "Extension data packet with stream ID"},
    {0x04, "IF context packet"},
    {0x05, "Extension context packet"},
    {0, NULL}
};

static const value_string tsi_types[] = {
    {0x00, "No integer-seconds timestamp field included"},
    {0x01, "Coordinated Universal Time (UTC)"},
    {0x02, "GPS time"},
    {0x03, "Other"},
    {0, NULL}
};

static const value_string tsf_types[] = {
    {0x00, "No fractional-seconds timestamp field included"},
    {0x01, "Sample count timestamp"},
    {0x02, "Real time (picoseconds) timestamp"},
    {0x03, "Free running count timestamp"},
    {0, NULL}
};

static void dissect_vrt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *hdr_tree, *vrt_tree;
    proto_item *ti, *hdr_item;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VITA 49");
    col_clear(pinfo->cinfo,COL_INFO);

    //get packet type
    guint8 type = tvb_get_guint8(tvb, 0) >> 4;
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(type, packet_types, "Reserved packet type (0x%02x)"));

    //get SID, CID, T, TSI, and TSF flags
    guint8 sidflag = type & 1;
    guint8 cidflag = (tvb_get_guint8(tvb, 0) >> 3) & 0x01;
    guint8 tflag = (tvb_get_guint8(tvb, 0) >> 2) & 0x01;
    guint8 tsiflag = (tvb_get_guint8(tvb, 1) >> 6) & 0x03;
    guint8 tsfflag = (tvb_get_guint8(tvb, 1) >> 4) & 0x03;
    guint16 len = tvb_get_ntohs(tvb, 2);
    guint16 nsamps = len - 1 - sidflag - cidflag*2 - tsiflag - tsfflag*2 - tflag;

    int offset = 0;

    if(tree) { //we're being asked for details
        ti = proto_tree_add_item(tree, proto_vrt, tvb, 0, -1, ENC_NA);
        vrt_tree = proto_item_add_subtree(ti, ett_vrt);

        hdr_item = proto_tree_add_item(vrt_tree, hf_vrt_header, tvb, offset, 4, ENC_BIG_ENDIAN);
        
        hdr_tree = proto_item_add_subtree(hdr_item, ett_header);
        proto_tree_add_item(hdr_tree, hf_vrt_type, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hdr_tree, hf_vrt_cidflag, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hdr_tree, hf_vrt_tflag, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(hdr_tree, hf_vrt_tsi, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hdr_tree, hf_vrt_tsf, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(hdr_tree, hf_vrt_seq, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(hdr_tree, hf_vrt_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        //header's done! if SID (last bit of type), put the stream ID here
        if(sidflag) {
            proto_tree_add_item(hdr_tree, hf_vrt_sid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }

        //if there's a class ID (cidflag), put the class ID here
        if(cidflag) {
            proto_tree_add_item(hdr_tree, hf_vrt_cid, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
        }

        //if TSI and/or TSF, populate those here
        if(tsiflag != 0) {
            proto_tree_add_item(hdr_tree, hf_vrt_ts_int, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if(tsfflag != 0) {
            if(tsfflag == 1 || tsfflag == 3) {
                proto_tree_add_item(hdr_tree, hf_vrt_ts_frac_sample, tvb, offset, 8, ENC_BIG_ENDIAN);
            } else if(tsfflag == 2) {
                proto_tree_add_item(hdr_tree, hf_vrt_ts_frac_picosecond, tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            offset += 8;
        }

        //now we're into the data
        //TODO assert we've got enough len left
        proto_tree_add_item(hdr_tree, hf_vrt_data, tvb, offset, nsamps*4, ENC_NA);
        offset += nsamps*4;

        if(tflag) {
            proto_tree_add_item(hdr_tree, hf_vrt_trailer, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        
        

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
        },
        { &hf_vrt_type,
            { "Packet type", "vrt.type",
            FT_UINT8, 4,
            VALS(packet_types), 0xF0,
            NULL, HFILL }
        },
        { &hf_vrt_cidflag,
            { "Class ID included", "vrt.cidflag",
            FT_BOOLEAN, 1,
            NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_vrt_tflag,
            { "Trailer included", "vrt.tflag",
            FT_BOOLEAN, 1,
            NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_vrt_tsi,
            { "Integer timestamp type", "vrt.tsi",
            FT_UINT8, 2,
            VALS(tsi_types), 0xC0,
            NULL, HFILL }
        },
        { &hf_vrt_tsf,
            { "Fractional timestamp type", "vrt.tsf",
            FT_UINT8, 2,
            VALS(tsf_types), 0x30,
            NULL, HFILL }
        },
        { &hf_vrt_seq,
            { "Sequence number", "vrt.seq",
            FT_UINT8, 4,
            NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_vrt_len,
            { "Length", "vrt.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_int,
            { "Integer timestamp", "vrt.ts_int",
            FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_sample,
            { "Fractional timestamp (samples)", "vrt.ts_frac",
            FT_UINT64, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_ts_frac_picosecond,
            { "Fractional timestamp (picoseconds)", "vrt.ts_frac",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_sid,
            { "Stream ID", "vrt.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_cid,
            { "Class ID", "vrt.cid",
            FT_UINT64, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_data,
            { "Data", "vrt.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_vrt_trailer,
            { "Trailer", "vrt.trailer",
            FT_UINT32, BASE_HEX,
            NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_vrt,
        &ett_header
     };

    proto_vrt = proto_register_protocol (
        "VITA 49 radio transport protocol", /* name       */
        "VITA 49",      /* short name */
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


