// blz.h — tiny self-contained LZ77 byte-stream compressor (bit-packed tokens).
//
// Why hand-rolled instead of zlib: the binder is the smallest possible stub and
// links only shell32. Adding zlib would grow the stub by ~40 KB, and that stub is
// re-embedded into every build. This codec is dependency-free and, with
// bit-packed tokens, reaches most of the compression a general library would.
//
// Format:
//   header: magic 'B' 'L' 'Z' '2', u32 originalSize, u32 compressedSize
//   body:   a bitstream of tokens, MSB-first within each byte:
//             bit 1 -> literal run
//                       4-bit length code  (0..14 => 1..15 bytes, 15 => read u8 ext)
//                       then `len` raw bytes
//             bit 0 -> match
//                       2-bit distance code, then offset bytes:
//                         0 => dist 1..256     (1 byte: dist-1)
//                         1 => dist 257..65536 (2 bytes: dist-257, LE)
//                         2 => dist 65537..16777216 (3 bytes: dist-65537, LE)
//                       4-bit length code as above, but value+4 (so min match = 5)
#pragma once
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BLZ_MAGIC 0x325A4C42u /* "BLZ2" little-endian */
#define BLZ_MIN_MATCH 5

#pragma pack(push, 1)
struct BlzHeader {
    uint32_t magic;
    uint32_t originalSize;
    uint32_t compressedSize;
};
#pragma pack(pop)

static inline size_t blzBound(size_t n) { return n + n / 2 + sizeof(BlzHeader) + 256; }

// ---- bit writer ----
struct BlzBitWriter {
    uint8_t* buf;
    size_t cap;
    size_t pos;      // byte position
    int bit;         // 0..7, next bit index within buf[pos]
};

static inline void bwInit(BlzBitWriter* w, uint8_t* buf, size_t cap) {
    w->buf = buf; w->cap = cap; w->pos = 0; w->bit = 0;
}
// write `n` bits (n <= 24) MSB-first
static inline bool bwWrite(BlzBitWriter* w, uint32_t value, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (w->pos >= w->cap) return false;
        if (w->bit == 0) w->buf[w->pos] = 0;
        if (value & (1u << i)) w->buf[w->pos] |= (uint8_t)(1 << (7 - w->bit));
        w->bit++;
        if (w->bit == 8) { w->bit = 0; w->pos++; }
    }
    return true;
}
static inline size_t bwFinish(BlzBitWriter* w) {
    if (w->bit != 0) { w->pos++; w->bit = 0; }
    return w->pos;
}

// ---- bit reader ----
struct BlzBitReader {
    const uint8_t* buf;
    size_t size;
    size_t pos;
    int bit;
};

static inline void brInit(BlzBitReader* r, const uint8_t* buf, size_t size) {
    r->buf = buf; r->size = size; r->pos = 0; r->bit = 0;
}
static inline bool brRead(BlzBitReader* r, int n, uint32_t* out) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) {
        if (r->pos >= r->size) return false;
        uint32_t b = (r->buf[r->pos] >> (7 - r->bit)) & 1u;
        v = (v << 1) | b;
        r->bit++;
        if (r->bit == 8) { r->bit = 0; r->pos++; }
    }
    *out = v;
    return true;
}
// read `n` whole bytes (must be byte-aligned)
static inline bool brReadBytes(BlzBitReader* r, uint8_t* dst, size_t n) {
    if (r->bit != 0) return false;
    if (r->pos + n > r->size) return false;
    memcpy(dst, r->buf + r->pos, n);
    r->pos += n;
    return true;
}

// ---- length coding (shared by both sides) ----
// 4-bit code: 0..14 => len = code + base ; 15 => len = 15 + base + nextByte
static inline void bwWriteLen(BlzBitWriter* w, size_t len, size_t base, bool* ok) {
    size_t v = len - base;
    if (v < 15) {
        if (!bwWrite(w, (uint32_t)v, 4)) *ok = false;
    } else {
        if (!bwWrite(w, 15, 4)) { *ok = false; return; }
        size_t ext = v - 15;
        if (ext > 255) ext = 255;   // matches are capped at 255 anyway
        // 8-bit extension, MSB-first
        if (!bwWrite(w, (uint32_t)ext, 8)) { *ok = false; return; }
    }
}
static inline size_t brReadLen(BlzBitReader* r, size_t base, bool* ok) {
    uint32_t code = 0;
    if (!brRead(r, 4, &code)) { *ok = false; return 0; }
    if (code < 15) return base + code;
    uint32_t ext = 0;
    if (!brRead(r, 8, &ext)) { *ok = false; return 0; }
    return base + 15 + ext;
}

// ---- distance coding ----
static inline void bwWriteDist(BlzBitWriter* w, size_t dist, bool* ok) {
    // dist is 1-based
    size_t d = dist - 1;
    if (d < 256) {
        if (!bwWrite(w, 0, 2)) { *ok = false; return; }
        if (!bwWrite(w, (uint32_t)d, 8)) { *ok = false; return; }
    } else if (d < 65536) {
        if (!bwWrite(w, 1, 2)) { *ok = false; return; }
        if (!bwWrite(w, (uint32_t)(d - 256), 16)) { *ok = false; return; }
    } else {
        if (!bwWrite(w, 2, 2)) { *ok = false; return; }
        if (!bwWrite(w, (uint32_t)(d - 65536), 24)) { *ok = false; return; }
    }
}
static inline size_t brReadDist(BlzBitReader* r, bool* ok) {
    uint32_t code = 0;
    if (!brRead(r, 2, &code)) { *ok = false; return 0; }
    uint32_t v = 0;
    if (code == 0) {
        if (!brRead(r, 8, &v)) { *ok = false; return 0; }
        return (size_t)v + 1;
    } else if (code == 1) {
        if (!brRead(r, 16, &v)) { *ok = false; return 0; }
        return (size_t)v + 256 + 1;
    } else {
        if (!brRead(r, 24, &v)) { *ok = false; return 0; }
        return (size_t)v + 65536 + 1;
    }
}

// Compress `src` into a freshly malloc'd buffer. Caller frees.
static inline uint8_t* blzCompress(const uint8_t* src, size_t srcLen, size_t* outLen) {
    size_t cap = blzBound(srcLen);
    uint8_t* out = (uint8_t*)malloc(cap);
    if (!out) return nullptr;

    BlzHeader hdr;
    hdr.magic = BLZ_MAGIC;
    hdr.originalSize = (uint32_t)srcLen;
    hdr.compressedSize = 0;
    memcpy(out, &hdr, sizeof(hdr));

    const size_t MAX_MATCH = 255;
    const size_t WINDOW = 1 << 20;   // 1 MiB reach; distance coding supports it
    const size_t HASH_BITS = 16;
    const size_t HASH_SIZE = (size_t)1 << HASH_BITS;
    const int MAX_CHAIN = 64;

    int32_t* head = (int32_t*)malloc(HASH_SIZE * sizeof(int32_t));
    int32_t* prev = (int32_t*)malloc((srcLen ? srcLen : 1) * sizeof(int32_t));
    if (!head || !prev) { free(out); free(head); free(prev); return nullptr; }
    memset(head, 0xFF, HASH_SIZE * sizeof(int32_t));

    auto hash4 = [&](size_t p) -> size_t {
        uint32_t v;
        memcpy(&v, src + p, 4);
        return (size_t)((v * 2654435761u) >> (32 - HASH_BITS)) & (HASH_SIZE - 1);
    };

    BlzBitWriter w;
    bwInit(&w, out + sizeof(BlzHeader), cap - sizeof(BlzHeader));
    bool ok = true;

    auto insertPos = [&](size_t p) {
        if (p + 4 > srcLen) return;
        size_t h = hash4(p);
        prev[p] = head[h];
        head[h] = (int32_t)p;
    };

    size_t litStart = 0;
    auto flushLits = [&](size_t end) {
        while (ok && litStart < end) {
            size_t n = end - litStart;
            if (n > 255) n = 255;
            bwWrite(&w, 1, 1);                       // token: literal run
            bwWriteLen(&w, n, 1, &ok);               // len coded with base 1
            for (size_t k = 0; k < n && ok; k++)
                bwWrite(&w, src[litStart + k], 8);
            litStart += n;
        }
    };

    for (size_t pos = 0; pos < srcLen && ok; ) {
        size_t matchLen = 0, matchDist = 0;
        if (pos + BLZ_MIN_MATCH <= srcLen) {
            size_t hi = hash4(pos);
            int32_t cand = head[hi];
            size_t bestLen = 0, bestDist = 0;
            int chain = 0;
            size_t maxL = srcLen - pos;
            if (maxL > MAX_MATCH) maxL = MAX_MATCH;
            size_t minAccept = BLZ_MIN_MATCH;
            while (cand >= 0 && chain++ < MAX_CHAIN) {
                size_t cpos = (size_t)cand;
                size_t d = pos - cpos;
                if (d == 0 || d > WINDOW) break;
                if (bestLen < maxL && src[cpos + bestLen] == src[pos + bestLen]) {
                    size_t l = 0;
                    while (l < maxL && src[cpos + l] == src[pos + l]) l++;
                    if (l > bestLen) {
                        bestLen = l;
                        bestDist = d;
                        if (l >= maxL) break;
                    }
                }
                cand = prev[cpos];
            }
            // A match is only worth it if the distance code doesn't cost more
            // than the literals it replaces. Minimum match already accounts for
            // that (5 bytes vs ~2 bytes of token overhead + dist).
            if (bestLen >= minAccept) {
                matchLen = bestLen;
                matchDist = bestDist;
            }
        }

        if (matchLen) {
            flushLits(pos);
            bwWrite(&w, 0, 1);                        // token: match
            bwWriteDist(&w, matchDist, &ok);
            bwWriteLen(&w, matchLen, BLZ_MIN_MATCH, &ok);
            for (size_t k = pos; k < pos + matchLen; k++) insertPos(k);
            pos += matchLen;
            litStart = pos;
        } else {
            insertPos(pos);
            pos++;
        }
    }
    if (ok) flushLits(srcLen);

    size_t bodyLen = bwFinish(&w);
    free(head);
    free(prev);

    if (!ok) { free(out); return nullptr; }
    ((BlzHeader*)out)->compressedSize = (uint32_t)(sizeof(BlzHeader) + bodyLen);
    *outLen = sizeof(BlzHeader) + bodyLen;
    return out;
}

// Decompress a BLZ2 stream into `dst` (at least originalSize bytes).
static inline bool blzDecompress(const uint8_t* src, size_t srcLen,
    uint8_t* dst, size_t dstLen) {
    if (!src || srcLen < sizeof(BlzHeader)) return false;
    BlzHeader hdr;
    memcpy(&hdr, src, sizeof(hdr));
    if (hdr.magic != BLZ_MAGIC) return false;
    if (hdr.originalSize > dstLen) return false;

    BlzBitReader r;
    brInit(&r, src + sizeof(BlzHeader), srcLen - sizeof(BlzHeader));
    bool ok = true;
    size_t o = 0;

    while (o < hdr.originalSize && ok) {
        uint32_t tok = 0;
        if (!brRead(&r, 1, &tok)) { ok = false; break; }
        if (tok) {
            size_t n = brReadLen(&r, 1, &ok);
            if (!ok) break;
            if (o + n > hdr.originalSize) { ok = false; break; }
            // byte-aligned? literals are written as 8-bit groups but may straddle
            // byte boundaries, so read them bit-wise.
            for (size_t k = 0; k < n && ok; k++) {
                uint32_t b = 0;
                if (!brRead(&r, 8, &b)) { ok = false; break; }
                dst[o++] = (uint8_t)b;
            }
        } else {
            size_t dist = brReadDist(&r, &ok);
            if (!ok) break;
            size_t len = brReadLen(&r, BLZ_MIN_MATCH, &ok);
            if (!ok) break;
            if (dist == 0 || dist > o) { ok = false; break; }
            if (o + len > hdr.originalSize) { ok = false; break; }
            for (size_t k = 0; k < len; k++) {
                dst[o] = dst[o - dist];
                o++;
            }
        }
    }
    return ok && o == hdr.originalSize;
}

static inline bool blzIsCompressed(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(BlzHeader)) return false;
    BlzHeader hdr;
    memcpy(&hdr, data, sizeof(hdr));
    return hdr.magic == BLZ_MAGIC;
}
