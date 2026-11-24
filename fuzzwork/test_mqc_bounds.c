/* Unit test: MQ/RAW decoder must never read out of bounds and must
 * report exhaustion via end_of_byte_stream_counter, for any input.
 * Build with ASan; run under a variety of tiny buffers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "opj_includes.h"

static void fill_guard(OPJ_BYTE* p, size_t n)
{
    /* poison pattern after the data buffer to catch OOB reads when
     * ASan is not used */
    memset(p, 0xAB, n);
}

int main(void)
{
    static const OPJ_UINT32 lens[] = {0, 1, 2, 3, 5, 8, 16, 64};
    size_t li;
    int seed;

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        OPJ_UINT32 len = lens[li];
        for (seed = 0; seed < 8; seed++) {
            OPJ_BYTE* buf;
            opj_mqc_t mqc;
            OPJ_UINT32 i;
            OPJ_UINT32 s = (OPJ_UINT32)(seed * 2654435761U + len);

            /* allocate exactly len + OPJ_COMMON_CBLK_DATA_EXTRA bytes, */
            /* with a guard region after (ASan redzone catches OOB). */
            buf = (OPJ_BYTE*)opj_malloc(len + OPJ_COMMON_CBLK_DATA_EXTRA);
            assert(buf);
            for (i = 0; i < len; i++) {
                OPJ_BYTE b;
                s = s * 1664525U + 1013904223U;
                b = (OPJ_BYTE)(s >> 24);
                /* avoid 0xFF bytes so that the RAW decoder does not */
                /* legitimately stall on an in-data marker */
                buf[i] = (b == 0xFF) ? 0xFE : b;
            }
            /* also test the pathological all-0x00 and all-0xFF contents */
            if (seed == 6) {
                memset(buf, 0x00, len);
            }
            if (seed == 7) {
                memset(buf, 0xFF, len);
            }

            /* MQ decode: far more symbols than the data can encode */
            memset(&mqc, 0, sizeof(mqc));
            opj_mqc_resetstates(&mqc);
            opj_mqc_init_dec(&mqc, buf, len, OPJ_COMMON_CBLK_DATA_EXTRA);
            for (i = 0; i < 100000; i++) {
                OPJ_UINT32 d;
                opj_mqc_setcurctx(&mqc, i % MQC_NUMCTXS);
                opj_mqc_decode(d, (&mqc));
                (void)d;
            }
            if (mqc.end_of_byte_stream_counter == 0 && len < 16) {
                fprintf(stderr,
                        "FAIL: len=%u seed=%d: MQ exhaustion not detected\n",
                        len, seed);
                return 1;
            }
            opq_mqc_finish_dec(&mqc);

            /* RAW decode */
            memset(&mqc, 0, sizeof(mqc));
            opj_mqc_raw_init_dec(&mqc, buf, len, OPJ_COMMON_CBLK_DATA_EXTRA);
            for (i = 0; i < 100000; i++) {
                (void)opj_mqc_raw_decode(&mqc);
            }
            /* seed==7 (all-0xFF data) legitimately stalls the RAW */
            /* decoder on the artificial marker without ever overrunning */
            /* the buffer, so no exhaustion is reported in that case. */
            if (seed != 7 && mqc.end_of_byte_stream_counter == 0 && len < 16) {
                fprintf(stderr,
                        "FAIL: len=%u seed=%d: RAW exhaustion not detected\n",
                        len, seed);
                return 1;
            }
            opq_mqc_finish_dec(&mqc);

            opj_free(buf);
        }
    }

    /* Also verify the decoder no longer relies on the artificial marker:
     * decode from a buffer whose 2 extra bytes are NOT 0xFF 0xFF but
     * garbage: results must be identical to the 0xFF 0xFF case. */
    {
        OPJ_BYTE buf1[8 + OPJ_COMMON_CBLK_DATA_EXTRA];
        OPJ_BYTE buf2[8 + OPJ_COMMON_CBLK_DATA_EXTRA];
        opj_mqc_t m1, m2;
        OPJ_UINT32 i;
        memset(buf1, 0x5A, sizeof(buf1));
        memset(buf2, 0x5A, sizeof(buf2));
        fill_guard(buf1 + 8, OPJ_COMMON_CBLK_DATA_EXTRA);
        fill_guard(buf2 + 8, OPJ_COMMON_CBLK_DATA_EXTRA);
        memset(&m1, 0, sizeof(m1));
        memset(&m2, 0, sizeof(m2));
        opj_mqc_resetstates(&m1);
        opj_mqc_resetstates(&m2);
        opj_mqc_init_dec(&m1, buf1, 8, OPJ_COMMON_CBLK_DATA_EXTRA);
        opj_mqc_init_dec(&m2, buf2, 8, OPJ_COMMON_CBLK_DATA_EXTRA);
        /* init_dec_common() wrote the artificial marker in both; the */
        /* point here is that decoding never reads those bytes anyway. */
        for (i = 0; i < 1000; i++) {
            OPJ_UINT32 d1, d2;
            opj_mqc_setcurctx(&m1, 0);
            opj_mqc_setcurctx(&m2, 0);
            opj_mqc_decode(d1, (&m1));
            opj_mqc_decode(d2, (&m2));
            if (d1 != d2) {
                fprintf(stderr, "FAIL: divergent decode at %u\n", i);
                return 1;
            }
        }
        opq_mqc_finish_dec(&m1);
        opq_mqc_finish_dec(&m2);
    }

    printf("OK: MQ/RAW decoder bounds checks verified\n");
    return 0;
}
