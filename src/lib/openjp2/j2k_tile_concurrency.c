/*
 * The copyright in this software is being made available under the 2-clauses
 * BSD License, included below. This software may be subject to other third
 * party and contributor rights, including patent rights, and no such rights
 * are granted under this license.
 *
 * Copyright (c) 2024, OpenJPEG contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS `AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
@file j2k_tile_concurrency.c
@brief Tile-level concurrency for random-access tile decoding.

The historical OpenJPEG decoder keeps all mutable decoding state (state
machine, tile codec workspace, procedure lists, tile coding parameters,
codestream index, output image, ...) inside the single opj_j2k_t handle and
its opj_stream_private_t. Consequently, two threads could not call
opj_get_decoded_tile() on the same codec: every structure involved was shared
and modified without synchronization, leading to state-machine
desynchronization and heap corruption.

This module makes distinct tile indices decodable concurrently by giving every
in-flight decode its own child opj_j2k_t whose mutable state is a deep copy of
the parent state as it stands right after the main header was read.

Synchronization:
 - one mutex per tile index serializes concurrent requests for the SAME tile,
   while different tiles run in parallel;
 - a registry mutex protects the worker pool (lazily forked child codecs) and
   the stream-owner table;
 - concurrent calls sharing the SAME opj_stream_t are serialized because a
   stream carries its own seek/read cursor. Different streams on the same
   resource (the recommended server setup, one open file per thread) run in
   parallel.

The inverse DWT is strictly tile-local in OpenJPEG, so no cross-tile
post-processing stage is needed.
*/

#include "opj_includes.h"

/* ----------------------------------------------------------------------- */
/* Forward references to j2k.c entry point                                 */
/* ----------------------------------------------------------------------- */

OPJ_BOOL opj_j2k_get_tile(opj_j2k_t *p_j2k,
                          opj_stream_private_t *p_stream,
                          opj_image_t* p_image,
                          opj_event_mgr_t * p_manager,
                          OPJ_UINT32 tile_index);

/* ----------------------------------------------------------------------- */
/* Per-worker / registry structures                                        */
/* ----------------------------------------------------------------------- */

struct opj_tile_worker {
    /** Child decoder with its own full mutable state. */
    opj_j2k_t *j2k;
    /** 1 while a thread is using this worker. */
    OPJ_BOOL busy;
};

struct opj_stream_lock {
    opj_stream_private_t *stream;
    OPJ_BOOL held;
    struct opj_stream_lock *next;
};

struct opj_tile_concurrency {
    /** Parent decoder (immutable header owner). */
    opj_j2k_t *parent;
    /** Number of tiles = cp->tw * cp->th, size of tile_mutex. */
    OPJ_UINT32 num_tiles;
    /** One lock per tile index: same-tile requests serialize, distinct tiles
     *  run in parallel. */
    opj_mutex_t **tile_mutex;
    /** Guards every field below plus the worker/stream tables. */
    opj_mutex_t *registry_mutex;
    /** Pool of forked child decoders, lazily grown. Entries are separately
     *  allocated so that their addresses stay valid when the pool grows. */
    opj_tile_worker_t **workers;
    OPJ_UINT32 num_workers;
    OPJ_UINT32 workers_capacity;
    /** Signaled when a stream lock is released. */
    opj_cond_t *stream_cond;
    /** Locks for streams currently in use. */
    struct opj_stream_lock *stream_locks;
};

/* ----------------------------------------------------------------------- */
/* Small helpers                                                           */
/* ----------------------------------------------------------------------- */

/* Duplicate a buffer. NULL input yields NULL output. */
static void *opj_tc_dup(const void *src, OPJ_SIZE_T size)
{
    void *out;
    if (src == NULL || size == 0U) {
        return NULL;
    }
    out = opj_malloc(size);
    if (out) {
        memcpy(out, src, size);
    }
    return out;
}

/* ----------------------------------------------------------------------- */
/* Deep copy of one tile coding parameter set                              */
/* ----------------------------------------------------------------------- */

static OPJ_BOOL opj_tc_tcp_copy(const opj_j2k_t *parent,
                                const opj_tcp_t *src, opj_tcp_t *dst,
                                OPJ_UINT32 numcomps)
{
    OPJ_UINT32 i;
    OPJ_UINT32 mct_matrix_size;

    /* Flat fields (rates, distoratio, pocs, flags, counters, ...). */
    *dst = *src;
    /* The pointer members are re-established below with private copies. */
    dst->ppt_markers = NULL;
    dst->ppt_data = NULL;
    dst->ppt_buffer = NULL;
    dst->tccps = NULL;
    dst->mct_norms = NULL;
    dst->m_mct_decoding_matrix = NULL;
    dst->m_mct_coding_matrix = NULL;
    dst->m_mct_records = NULL;
    dst->m_mcc_records = NULL;
    dst->m_data = NULL;

    /* PPT markers. */
    if (src->ppt_markers && src->ppt_markers_count) {
        dst->ppt_markers = (opj_ppx*) opj_calloc(src->ppt_markers_count,
                            sizeof(opj_ppx));
        if (!dst->ppt_markers) {
            return OPJ_FALSE;
        }
        for (i = 0; i < src->ppt_markers_count; ++i) {
            dst->ppt_markers[i].m_data_size = src->ppt_markers[i].m_data_size;
            dst->ppt_markers[i].m_data = (OPJ_BYTE*)opj_tc_dup(
                                             src->ppt_markers[i].m_data,
                                             src->ppt_markers[i].m_data_size);
            if (src->ppt_markers[i].m_data && !dst->ppt_markers[i].m_data) {
                return OPJ_FALSE;
            }
        }
    }

    /* ppt_data / ppt_len point inside ppt_buffer; duplicate the backing
     * buffer and recompute the inner pointers with the same offsets. */
    if (src->ppt_buffer) {
        dst->ppt_buffer = (OPJ_BYTE*)opj_tc_dup(src->ppt_buffer, src->ppt_len);
        if (!dst->ppt_buffer) {
            return OPJ_FALSE;
        }
        if (src->ppt_data) {
            dst->ppt_data = dst->ppt_buffer +
                            (src->ppt_data - src->ppt_buffer);
        }
    }

    /* Tile-component coding parameters: pure value types. */
    dst->tccps = (opj_tccp_t*) opj_calloc(numcomps, sizeof(opj_tccp_t));
    if (!dst->tccps) {
        return OPJ_FALSE;
    }
    memcpy(dst->tccps, src->tccps, numcomps * sizeof(opj_tccp_t));

    dst->mct_norms = (OPJ_FLOAT64*)opj_tc_dup(src->mct_norms,
                      numcomps * sizeof(OPJ_FLOAT64));
    if (src->mct_norms && !dst->mct_norms) {
        return OPJ_FALSE;
    }

    mct_matrix_size = numcomps * numcomps * (OPJ_UINT32)sizeof(OPJ_FLOAT32);
    dst->m_mct_coding_matrix = (OPJ_FLOAT32*)opj_tc_dup(src->m_mct_coding_matrix,
                                mct_matrix_size);
    if (src->m_mct_coding_matrix && !dst->m_mct_coding_matrix) {
        return OPJ_FALSE;
    }
    dst->m_mct_decoding_matrix = (OPJ_FLOAT32*)opj_tc_dup(
                                     src->m_mct_decoding_matrix,
                                     mct_matrix_size);
    if (src->m_mct_decoding_matrix && !dst->m_mct_decoding_matrix) {
        return OPJ_FALSE;
    }

    /* MCT records (array + per-record data). */
    if (src->m_mct_records && src->m_nb_max_mct_records) {
        dst->m_mct_records = (opj_mct_data_t*) opj_calloc(
                                 src->m_nb_max_mct_records,
                                 sizeof(opj_mct_data_t));
        if (!dst->m_mct_records) {
            return OPJ_FALSE;
        }
        memcpy(dst->m_mct_records, src->m_mct_records,
               src->m_nb_max_mct_records * sizeof(opj_mct_data_t));
        for (i = 0; i < src->m_nb_max_mct_records; ++i) {
            dst->m_mct_records[i].m_data = (OPJ_BYTE*)opj_tc_dup(
                                               src->m_mct_records[i].m_data,
                                               src->m_mct_records[i].m_data_size);
            if (src->m_mct_records[i].m_data && !dst->m_mct_records[i].m_data) {
                return OPJ_FALSE;
            }
        }
    }

    /* MCC records (array; inner pointers are re-based onto the local MCT
     * record array, mirroring opj_j2k_copy_default_tcp_and_create_tcd). */
    if (src->m_mcc_records && src->m_nb_max_mcc_records) {
        dst->m_mcc_records = (opj_simple_mcc_decorrelation_data_t*) opj_calloc(
                                 src->m_nb_max_mcc_records,
                                 sizeof(opj_simple_mcc_decorrelation_data_t));
        if (!dst->m_mcc_records) {
            return OPJ_FALSE;
        }
        memcpy(dst->m_mcc_records, src->m_mcc_records,
               src->m_nb_max_mcc_records *
               sizeof(opj_simple_mcc_decorrelation_data_t));
        for (i = 0; i < src->m_nb_max_mcc_records; ++i) {
            if (src->m_mcc_records[i].m_decorrelation_array) {
                OPJ_UINT32 offset = (OPJ_UINT32)(
                                        src->m_mcc_records[i].m_decorrelation_array -
                                        src->m_mct_records);
                dst->m_mcc_records[i].m_decorrelation_array =
                    dst->m_mct_records + offset;
            }
            if (src->m_mcc_records[i].m_offset_array) {
                OPJ_UINT32 offset = (OPJ_UINT32)(
                                        src->m_mcc_records[i].m_offset_array -
                                        src->m_mct_records);
                dst->m_mcc_records[i].m_offset_array =
                    dst->m_mct_records + offset;
            }
        }
    }

    (void)parent;
    return OPJ_TRUE;
}

/* ----------------------------------------------------------------------- */
/* Deep copy of the global coding parameters                               */
/* ----------------------------------------------------------------------- */

static OPJ_BOOL opj_tc_cp_copy(const opj_cp_t *src, opj_cp_t *dst,
                               OPJ_UINT32 numcomps)
{
    OPJ_UINT32 i;

    *dst = *src;
    dst->comment = NULL;
    dst->ppm_markers = NULL;
    dst->ppm_data = NULL;
    dst->ppm_data_current = NULL;
    dst->ppm_buffer = NULL;
    dst->ppm_data_first = NULL;
    dst->tcps = NULL;

    dst->comment = (OPJ_CHAR*)opj_tc_dup(src->comment,
                                         src->comment ? strlen(src->comment) + 1U : 0U);
    if (src->comment && !dst->comment) {
        return OPJ_FALSE;
    }

    /* PPM markers (main-header packet headers). */
    if (src->ppm_markers && src->ppm_markers_count) {
        dst->ppm_markers = (opj_ppx*) opj_calloc(src->ppm_markers_count,
                            sizeof(opj_ppx));
        if (!dst->ppm_markers) {
            return OPJ_FALSE;
        }
        for (i = 0; i < src->ppm_markers_count; ++i) {
            dst->ppm_markers[i].m_data_size = src->ppm_markers[i].m_data_size;
            dst->ppm_markers[i].m_data = (OPJ_BYTE*)opj_tc_dup(
                                             src->ppm_markers[i].m_data,
                                             src->ppm_markers[i].m_data_size);
            if (src->ppm_markers[i].m_data && !dst->ppm_markers[i].m_data) {
                return OPJ_FALSE;
            }
        }
    }
    if (src->ppm_buffer) {
        dst->ppm_buffer = (OPJ_BYTE*)opj_tc_dup(src->ppm_buffer,
                                                src->ppm_data_size);
        if (!dst->ppm_buffer) {
            return OPJ_FALSE;
        }
        if (src->ppm_data_first) {
            dst->ppm_data_first = dst->ppm_buffer +
                                  (src->ppm_data_first - src->ppm_buffer);
        }
        if (src->ppm_data) {
            dst->ppm_data = dst->ppm_buffer +
                            (src->ppm_data - src->ppm_buffer);
        }
        if (src->ppm_data_current) {
            dst->ppm_data_current = dst->ppm_buffer +
                                    (src->ppm_data_current - src->ppm_buffer);
        }
    }

    /* Tile coding parameters. */
    if (src->tcps && (src->tw * src->th) != 0U) {
        OPJ_UINT32 nb_tiles = src->tw * src->th;
        dst->tcps = (opj_tcp_t*) opj_calloc(nb_tiles, sizeof(opj_tcp_t));
        if (!dst->tcps) {
            return OPJ_FALSE;
        }
        for (i = 0; i < nb_tiles; ++i) {
            if (!opj_tc_tcp_copy(NULL, &src->tcps[i], &dst->tcps[i],
                                 numcomps)) {
                return OPJ_FALSE;
            }
        }
    }

    return OPJ_TRUE;
}

/* ----------------------------------------------------------------------- */
/* Deep copy of the codestream index (SOT/tile-part offsets)               */
/* ----------------------------------------------------------------------- */

static OPJ_BOOL opj_tc_cstr_index_copy(const opj_codestream_index_t *src,
                                       opj_codestream_index_t *dst)
{
    OPJ_UINT32 i;

    *dst = *src;
    dst->marker = NULL;
    dst->tile_index = NULL;

    if (src->marker && src->maxmarknum) {
        dst->marker = (opj_marker_info_t*) opj_calloc(src->maxmarknum,
                       sizeof(opj_marker_info_t));
        if (!dst->marker) {
            return OPJ_FALSE;
        }
        memcpy(dst->marker, src->marker,
               src->maxmarknum * sizeof(opj_marker_info_t));
    }

    if (src->tile_index && src->nb_of_tiles) {
        dst->tile_index = (opj_tile_index_t*) opj_calloc(src->nb_of_tiles,
                          sizeof(opj_tile_index_t));
        if (!dst->tile_index) {
            return OPJ_FALSE;
        }
        for (i = 0; i < src->nb_of_tiles; ++i) {
            const opj_tile_index_t *sti = &src->tile_index[i];
            opj_tile_index_t *dti = &dst->tile_index[i];
            *dti = *sti;
            dti->tp_index = NULL;
            dti->marker = NULL;
            dti->packet_index = NULL;
            if (sti->tp_index && sti->current_nb_tps) {
                dti->tp_index = (opj_tp_index_t*) opj_calloc(
                                    sti->current_nb_tps,
                                    sizeof(opj_tp_index_t));
                if (!dti->tp_index) {
                    return OPJ_FALSE;
                }
                memcpy(dti->tp_index, sti->tp_index,
                       sti->current_nb_tps * sizeof(opj_tp_index_t));
            }
            if (sti->marker && sti->maxmarknum) {
                dti->marker = (opj_marker_info_t*) opj_calloc(sti->maxmarknum,
                               sizeof(opj_marker_info_t));
                if (!dti->marker) {
                    return OPJ_FALSE;
                }
                memcpy(dti->marker, sti->marker,
                       sti->maxmarknum * sizeof(opj_marker_info_t));
            }
            if (sti->packet_index && sti->nb_packet) {
                dti->packet_index = (opj_packet_info_t*) opj_calloc(
                                        sti->nb_packet,
                                        sizeof(opj_packet_info_t));
                if (!dti->packet_index) {
                    return OPJ_FALSE;
                }
                memcpy(dti->packet_index, sti->packet_index,
                       sti->nb_packet * sizeof(opj_packet_info_t));
            }
        }
    }
    return OPJ_TRUE;
}

/* ----------------------------------------------------------------------- */
/* Header-only copy of the private image (component geometry, no pixels)   */
/* ----------------------------------------------------------------------- */

static opj_image_t *opj_tc_private_image_copy(const opj_image_t *src)
{
    opj_image_t *dst = (opj_image_t*) opj_calloc(1, sizeof(opj_image_t));
    OPJ_UINT32 c;
    if (!dst) {
        return NULL;
    }
    dst->x0 = src->x0;
    dst->y0 = src->y0;
    dst->x1 = src->x1;
    dst->y1 = src->y1;
    dst->color_space = src->color_space;
    dst->numcomps = src->numcomps;
    dst->icc_profile_len = 0;
    dst->icc_profile_buf = NULL;
    dst->comps = (opj_image_comp_t*) opj_calloc(src->numcomps,
                   sizeof(opj_image_comp_t));
    if (!dst->comps) {
        opj_free(dst);
        return NULL;
    }
    for (c = 0; c < src->numcomps; ++c) {
        dst->comps[c] = src->comps[c];
        dst->comps[c].data = NULL; /* pixels are allocated per tile decode */
    }
    if (src->icc_profile_len && src->icc_profile_buf) {
        dst->icc_profile_buf = (OPJ_BYTE*)opj_tc_dup(src->icc_profile_buf,
                                  src->icc_profile_len);
        if (!dst->icc_profile_buf) {
            opj_image_destroy(dst);
            return NULL;
        }
        dst->icc_profile_len = src->icc_profile_len;
    }
    return dst;
}

/* ----------------------------------------------------------------------- */
/* Child decoder fork                                                      */
/* ----------------------------------------------------------------------- */

/* Number of worker threads used by a codec's internal pool. */
static int opj_tc_get_pool_thread_count(const opj_j2k_t *j2k)
{
    return opj_thread_pool_get_thread_count(j2k->m_tp);
}

/* Build a child decoder whose mutable state is an independent copy of the
 * parent decoder state right after main-header reading. */
static opj_j2k_t *opj_tc_fork_child(const opj_j2k_t *parent,
                                    opj_event_mgr_t *p_manager)
{
    opj_j2k_t *child;
    const opj_j2k_dec_t *pdec = &parent->m_specific_param.m_decoder;
    opj_j2k_dec_t *cdec;
    OPJ_UINT32 numcomps;

    if (!parent->m_private_image || !parent->cstr_index) {
        opj_event_msg(p_manager, EVT_ERROR,
                      "Concurrent tile decode requires opj_read_header() to "
                      "have succeeded first.\n");
        return NULL;
    }
    numcomps = parent->m_private_image->numcomps;

    child = opj_j2k_create_decompress();
    if (!child) {
        return NULL;
    }

    /* Match the parent's internal worker pool before the child tcd binds
     * itself to this thread pool. */
    {
        int parent_threads = opj_tc_get_pool_thread_count(parent);
        if (parent_threads > 0) {
            opj_j2k_set_threads(child, (OPJ_UINT32)parent_threads);
        }
    }

    /* ---- coding parameters (deep copy) ---- */
    if (!opj_tc_cp_copy(&parent->m_cp, &child->m_cp, numcomps)) {
        opj_event_msg(p_manager, EVT_ERROR,
                      "Failed to clone coding parameters for tile worker.\n");
        opj_j2k_destroy(child);
        return NULL;
    }

    /* ---- private image (header only; pixel buffers are per tile) ---- */
    child->m_private_image = opj_tc_private_image_copy(parent->m_private_image);
    if (!child->m_private_image) {
        opj_j2k_destroy(child);
        return NULL;
    }

    /* ---- codestream index (tile-part offsets, ...). The freshly created
     * child already owns a default index; release it before overwriting the
     * pointer so its backing allocations do not leak. ---- */
    j2k_destroy_cstr_index(child->cstr_index);
    child->cstr_index = (opj_codestream_index_t*) opj_calloc(1,
                        sizeof(opj_codestream_index_t));
    if (!child->cstr_index) {
        opj_j2k_destroy(child);
        return NULL;
    }
    if (!opj_tc_cstr_index_copy(parent->cstr_index, child->cstr_index)) {
        opj_j2k_destroy(child);
        return NULL;
    }

    /* ---- decoder state machine ---- */
    cdec = &child->m_specific_param.m_decoder;
    cdec->m_state = J2K_STATE_TPHSOT; /* same state as parent after header */
    cdec->m_tile_ind_to_dec = -1;
    cdec->m_can_decode = 0;
    cdec->m_skip_data = 0;
    cdec->m_discard_tiles = 0;
    cdec->m_last_sot_read_pos = 0;
    cdec->m_sot_length = 0;
    cdec->m_last_tile_part = pdec->m_last_tile_part;
    cdec->m_start_tile_x = pdec->m_start_tile_x;
    cdec->m_start_tile_y = pdec->m_start_tile_y;
    cdec->m_end_tile_x = pdec->m_end_tile_x;
    cdec->m_end_tile_y = pdec->m_end_tile_y;
    cdec->m_numcomps_to_decode = pdec->m_numcomps_to_decode;
    cdec->m_nb_tile_parts_correction_checked =
        pdec->m_nb_tile_parts_correction_checked;
    cdec->m_nb_tile_parts_correction = pdec->m_nb_tile_parts_correction;

    if (pdec->m_numcomps_to_decode && pdec->m_comps_indices_to_decode) {
        cdec->m_comps_indices_to_decode = (OPJ_UINT32*)opj_tc_dup(
            pdec->m_comps_indices_to_decode,
            pdec->m_numcomps_to_decode * sizeof(OPJ_UINT32));
        if (!cdec->m_comps_indices_to_decode) {
            opj_j2k_destroy(child);
            return NULL;
        }
    }

    /* TLM table (used to seek to tile parts when decode area is restricted). */
    if (pdec->m_tlm.m_tile_part_infos && pdec->m_tlm.m_entries_count) {
        cdec->m_tlm.m_entries_count = pdec->m_tlm.m_entries_count;
        cdec->m_tlm.m_is_invalid = pdec->m_tlm.m_is_invalid;
        cdec->m_tlm.m_tile_part_infos =
            (opj_j2k_tlm_tile_part_info_t*)opj_tc_dup(
                pdec->m_tlm.m_tile_part_infos,
                pdec->m_tlm.m_entries_count *
                sizeof(opj_j2k_tlm_tile_part_info_t));
        if (!cdec->m_tlm.m_tile_part_infos) {
            opj_j2k_destroy(child);
            return NULL;
        }
    }

    /* Intersecting tile-part offsets (decode area). */
    if (pdec->m_intersecting_tile_parts_offset &&
        pdec->m_num_intersecting_tile_parts) {
        cdec->m_num_intersecting_tile_parts =
            pdec->m_num_intersecting_tile_parts;
        cdec->m_intersecting_tile_parts_offset = (OPJ_OFF_T*)opj_tc_dup(
            pdec->m_intersecting_tile_parts_offset,
            pdec->m_num_intersecting_tile_parts * sizeof(OPJ_OFF_T));
        if (!cdec->m_intersecting_tile_parts_offset) {
            opj_j2k_destroy(child);
            return NULL;
        }
    }

    /* ---- tile codec, bound to the child's own cp/image ---- */
    child->m_tcd = opj_tcd_create(OPJ_TRUE);
    if (!child->m_tcd) {
        opj_j2k_destroy(child);
        return NULL;
    }
    if (!opj_tcd_init(child->m_tcd, child->m_private_image, &child->m_cp,
                      child->m_tp)) {
        opj_j2k_destroy(child);
        return NULL;
    }

    child->ihdr_w = parent->ihdr_w;
    child->ihdr_h = parent->ihdr_h;
    child->dump_state = parent->dump_state;
    child->m_is_tile_worker = OPJ_TRUE;

    return child;
}

static void opj_tc_worker_free(opj_tile_worker_t *w)
{
    if (w->j2k) {
        opj_j2k_destroy(w->j2k);
        w->j2k = NULL;
    }
}

/* ----------------------------------------------------------------------- */
/* Registry lifecycle                                                      */
/* ----------------------------------------------------------------------- */

static void opj_tc_stream_unlock(opj_tile_concurrency_t *tc,
                                 opj_stream_private_t *stream);

opj_tile_concurrency_t *opj_tc_create(opj_j2k_t *parent)
{
    opj_tile_concurrency_t *tc;
    OPJ_UINT32 i, num_tiles;

    if (!parent || !parent->m_is_decoder || !parent->m_cp.tcps) {
        return NULL;
    }
    num_tiles = parent->m_cp.tw * parent->m_cp.th;
    if (num_tiles == 0U) {
        return NULL;
    }

    tc = (opj_tile_concurrency_t*) opj_calloc(1,
         sizeof(opj_tile_concurrency_t));
    if (!tc) {
        return NULL;
    }
    tc->parent = parent;
    tc->num_tiles = num_tiles;
    tc->registry_mutex = opj_mutex_create();
    if (!tc->registry_mutex) {
        opj_free(tc);
        return NULL;
    }
    tc->stream_cond = opj_cond_create();
    if (!tc->stream_cond) {
        for (i = 0; i < num_tiles; ++i) {
            opj_mutex_destroy(tc->tile_mutex[i]);
        }
        opj_free(tc->tile_mutex);
        opj_mutex_destroy(tc->registry_mutex);
        opj_free(tc);
        return NULL;
    }
    tc->tile_mutex = (opj_mutex_t**) opj_calloc(num_tiles,
                      sizeof(opj_mutex_t*));
    if (!tc->tile_mutex) {
        opj_cond_destroy(tc->stream_cond);
        opj_mutex_destroy(tc->registry_mutex);
        opj_free(tc);
        return NULL;
    }
    for (i = 0; i < num_tiles; ++i) {
        tc->tile_mutex[i] = opj_mutex_create();
        if (!tc->tile_mutex[i]) {
            OPJ_UINT32 j;
            for (j = 0; j < i; ++j) {
                opj_mutex_destroy(tc->tile_mutex[j]);
            }
            opj_free(tc->tile_mutex);
            opj_cond_destroy(tc->stream_cond);
            opj_mutex_destroy(tc->registry_mutex);
            opj_free(tc);
            return NULL;
        }
    }
    return tc;
}

void opj_tc_destroy(opj_tile_concurrency_t *tc)
{
    OPJ_UINT32 i;
    struct opj_stream_lock *sl, *sl_next;
    if (!tc) {
        return;
    }
    for (i = 0; i < tc->num_workers; ++i) {
        if (tc->workers[i]) {
            opj_tc_worker_free(tc->workers[i]);
            opj_free(tc->workers[i]);
        }
    }
    opj_free(tc->workers);
    for (i = 0; i < tc->num_tiles; ++i) {
        opj_mutex_destroy(tc->tile_mutex[i]);
    }
    opj_free(tc->tile_mutex);
    sl = tc->stream_locks;
    while (sl) {
        sl_next = sl->next;
        opj_free(sl);
        sl = sl_next;
    }
    opj_mutex_destroy(tc->registry_mutex);
    opj_cond_destroy(tc->stream_cond);
    opj_free(tc);
}

/* Acquire an idle worker, forking a new child codec when the pool is full.
 * registry_mutex must be held by the caller. The returned worker is a stable,
 * separately allocated object: it remains valid across later pool growth. */
static opj_tile_worker_t *opj_tc_acquire_worker_locked(
    opj_tile_concurrency_t *tc, opj_event_mgr_t *p_manager)
{
    opj_tile_worker_t *w = NULL;
    OPJ_UINT32 i;

    for (i = 0; i < tc->num_workers; ++i) {
        if (!tc->workers[i]->busy && tc->workers[i]->j2k) {
            w = tc->workers[i];
            break;
        }
    }

    if (!w) {
        OPJ_UINT32 slot = tc->num_workers;

        /* Prefer re-forking into a slot whose previous worker was retired
         * after a failed decode (j2k == NULL, not busy). */
        for (i = 0; i < tc->num_workers; ++i) {
            if (!tc->workers[i]->busy && !tc->workers[i]->j2k) {
                slot = i;
                break;
            }
        }

        if (slot == tc->num_workers &&
                tc->num_workers == tc->workers_capacity) {
            OPJ_UINT32 new_cap = tc->workers_capacity ?
                                 tc->workers_capacity * 2U : 4U;
            opj_tile_worker_t **grown = (opj_tile_worker_t**) opj_realloc(
                                            tc->workers,
                                            new_cap * sizeof(opj_tile_worker_t*));
            if (!grown) {
                return NULL;
            }
            memset(grown + tc->num_workers, 0,
                   (new_cap - tc->num_workers) *
                   sizeof(opj_tile_worker_t*));
            tc->workers = grown;
            tc->workers_capacity = new_cap;
        }

        if (!tc->workers[slot]) {
            w = (opj_tile_worker_t*) opj_calloc(1, sizeof(opj_tile_worker_t));
            if (!w) {
                return NULL;
            }
            tc->workers[slot] = w;
            if (slot == tc->num_workers) {
                tc->num_workers++;
            }
        } else {
            w = tc->workers[slot];
        }
        w->j2k = opj_tc_fork_child(tc->parent, p_manager);
        if (!w->j2k) {
            opj_free(w);
            tc->workers[slot] = NULL;
            return NULL;
        }
    }

    w->busy = OPJ_TRUE;
    return w;
}

/* registry_mutex must be held by the caller. */
static void opj_tc_release_worker_locked(opj_tile_worker_t *w)
{
    w->busy = OPJ_FALSE;
}

/* Wait until no worker holds the given stream, then mark it held.
 * registry_mutex must be held by the caller. Returns FALSE only on allocation
 * failure; the caller must then abort instead of breaking stream ownership. */
static OPJ_BOOL opj_tc_stream_lock_locked(opj_tile_concurrency_t *tc,
        opj_stream_private_t *stream)
{
    struct opj_stream_lock *sl;
    for (;;) {
        for (sl = tc->stream_locks; sl; sl = sl->next) {
            if (sl->stream == stream) {
                break;
            }
        }
        if (!sl) {
            sl = (struct opj_stream_lock*) opj_calloc(1,
                 sizeof(struct opj_stream_lock));
            if (!sl) {
                return OPJ_FALSE;
            }
            sl->stream = stream;
            sl->next = tc->stream_locks;
            tc->stream_locks = sl;
        }
        if (!sl->held) {
            sl->held = OPJ_TRUE;
            return OPJ_TRUE;
        }
        /* Another in-flight decode uses this exact stream: wait for it. */
        opj_cond_wait(tc->stream_cond, tc->registry_mutex);
    }
}

static void opj_tc_stream_unlock(opj_tile_concurrency_t *tc,
                                 opj_stream_private_t *stream)
{
    struct opj_stream_lock *sl;
    opj_mutex_lock(tc->registry_mutex);
    for (sl = tc->stream_locks; sl; sl = sl->next) {
        if (sl->stream == stream) {
            sl->held = OPJ_FALSE;
            opj_cond_signal(tc->stream_cond);
            break;
        }
    }
    opj_mutex_unlock(tc->registry_mutex);
}

/* ----------------------------------------------------------------------- */
/* Public entry                                                            */
/* ----------------------------------------------------------------------- */

OPJ_BOOL opj_tc_get_decoded_tile(opj_tile_concurrency_t *tc,
                                 opj_stream_private_t *p_stream,
                                 opj_image_t *p_image,
                                 opj_event_mgr_t *p_manager,
                                 OPJ_UINT32 tile_index)
{
    opj_tile_worker_t *w;
    OPJ_BOOL ok;

    if (!tc || tile_index >= tc->num_tiles) {
        return OPJ_FALSE;
    }

    /* Same tile index: serialize (its per-tile tcps entry and output region
     * are shared). Different tiles proceed in parallel below. */
    opj_mutex_lock(tc->tile_mutex[tile_index]);

    /* Same stream instance: serialize (the stream has a single seek/read
     * cursor). Distinct streams over the same file stay fully parallel. */
    opj_mutex_lock(tc->registry_mutex);
    if (!opj_tc_stream_lock_locked(tc, p_stream)) {
        opj_mutex_unlock(tc->registry_mutex);
        opj_mutex_unlock(tc->tile_mutex[tile_index]);
        opj_event_msg(p_manager, EVT_ERROR,
                      "Out of memory while locking the stream.\n");
        return OPJ_FALSE;
    }
    w = opj_tc_acquire_worker_locked(tc, p_manager);
    opj_mutex_unlock(tc->registry_mutex);

    if (!w) {
        opj_tc_stream_unlock(tc, p_stream);
        opj_mutex_unlock(tc->tile_mutex[tile_index]);
        opj_event_msg(p_manager, EVT_ERROR,
                      "No tile worker available (resource exhaustion).\n");
        return OPJ_FALSE;
    }

    /* The actual decode runs entirely on the child's private state. */

    /* A stream opened independently on the same file still sits at its
     * initial position, whereas the regular API contract expects the stream
     * to have been advanced past the main header by opj_read_header(): that
     * function consumes the SOT marker ID (2 bytes) before returning, leaving
     * the cursor right after it. main_head_end points AT the SOT marker, so
     * seek two bytes further. Streams that do not support seeking fail the
     * following tile read with the usual "Problem with seek function"
     * diagnostic. */
    if (w->j2k->cstr_index &&
            opj_stream_tell(p_stream) <= w->j2k->cstr_index->main_head_end) {
        if (!opj_stream_read_seek(p_stream,
                                  w->j2k->cstr_index->main_head_end + 2,
                                  p_manager)) {
            opj_event_msg(p_manager, EVT_ERROR,
                          "Cannot seek the stream to the first tile part.\n");
            ok = OPJ_FALSE;
        } else {
            ok = opj_j2k_get_tile(w->j2k, p_stream, p_image, p_manager,
                                  tile_index);
        }
    } else {
        ok = opj_j2k_get_tile(w->j2k, p_stream, p_image, p_manager,
                              tile_index);
    }

    opj_mutex_lock(tc->registry_mutex);
    if (!ok) {
        /* A failed decode may have left the child in an unrecoverable state
         * (e.g. its private image was destroyed). Retire it; the slot is
         * re-forked lazily on the next acquisition. */
        opj_tc_worker_free(w);
    }
    opj_tc_release_worker_locked(w);
    opj_mutex_unlock(tc->registry_mutex);
    opj_tc_stream_unlock(tc, p_stream);
    opj_mutex_unlock(tc->tile_mutex[tile_index]);

    return ok;
}
