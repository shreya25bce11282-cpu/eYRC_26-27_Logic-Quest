#!/usr/bin/env python3
# apply_task3a.py - puts the Task 3A solution into your Path_Planner_Dec.c
# Usage (from code/c_programs):   python3 apply_task3a.py Path_Planner_Dec.c
# It only replaces what is between the two "Add your code here" markers
# (first: the custom functions, second: the code inside main).
# A backup of your file is saved as Path_Planner_Dec.c.bak first.
import sys, shutil

START = "// ############# Add your code here #############"
END   = "// ##############################################"

BLOCK_A = r"""
// PRESENT-80 decryption and shortest-path planning (Bellman-Ford, tiny RAM)

// ---------- PRESENT-80 decryption, no big tables, no 64-bit math ----------
// S-box and its inverse are packed 4 bits per entry into constants
// (these live inside instructions, not in data memory).
#define SBOX_LO  0xDA09B65Cu   // S[0..7]
#define SBOX_HI  0x21748FE3u   // S[8..15]
#define ISBOX_LO 0xD21C8FE5u   // Sinv[0..7]
#define ISBOX_HI 0xA970364Bu   // Sinv[8..15]

static uint8_t nib(uint32_t lo, uint32_t hi, uint8_t x) {
    uint32_t w = (x & 8) ? hi : lo;
    return (uint8_t)((w >> ((x & 7) << 2)) & 0xF);
}

// 80-bit key register held as five 16-bit words: k[4] = bits 79..64 ... k[0] = bits 15..0
static void rotr16(uint16_t *k) {            // rotate right by 16 bits
    uint16_t t = k[0];
    k[0] = k[1]; k[1] = k[2]; k[2] = k[3]; k[3] = k[4]; k[4] = t;
}
static void rotr1(uint16_t *k) {             // rotate right by 1 bit
    uint16_t low = k[0] & 1;
    k[0] = (k[0] >> 1) | (k[1] << 15);
    k[1] = (k[1] >> 1) | (k[2] << 15);
    k[2] = (k[2] >> 1) | (k[3] << 15);
    k[3] = (k[3] >> 1) | (k[4] << 15);
    k[4] = (k[4] >> 1) | (low << 15);
}
static void rotl1(uint16_t *k) {             // rotate left by 1 bit
    uint16_t top = k[4] >> 15;
    k[4] = (k[4] << 1) | (k[3] >> 15);
    k[3] = (k[3] << 1) | (k[2] >> 15);
    k[2] = (k[2] << 1) | (k[1] >> 15);
    k[1] = (k[1] << 1) | (k[0] >> 15);
    k[0] = (k[0] << 1) | top;
}
// rotate left 61 = rotate right 19 = rotr16 then rotr1 three times
static void rotl61(uint16_t *k) { rotr16(k); rotr1(k); rotr1(k); rotr1(k); }
// rotate right 61 = rotate left 19 = rotl1 nineteen times (rotl16 is rotr64: 4 x rotr16)
static void rotr61(uint16_t *k) {
    uint8_t i;
    for (i = 0; i < 4; i++) rotr16(k);       // left 16 == right 64 (mod 80)
    rotl1(k); rotl1(k); rotl1(k);
}

static void top_nibble_sub(uint16_t *k, uint8_t inverse) {
    uint8_t n = (uint8_t)(k[4] >> 12);
    n = inverse ? nib(ISBOX_LO, ISBOX_HI, n) : nib(SBOX_LO, SBOX_HI, n);
    k[4] = (uint16_t)((k[4] & 0x0FFF) | ((uint16_t)n << 12));
}
static void xor_counter(uint16_t *k, uint8_t i) {   // bits 19..15 ^= i (5 bits)
    k[1] ^= (uint16_t)(i >> 1);                      // bits 19..16
    k[0] ^= (uint16_t)((i & 1) << 15);               // bit 15
}

// Inverse permutation: bit j of the input goes back to position (4*j) mod 63
static void inv_perm(uint32_t *hi, uint32_t *lo) {
    uint32_t nh = 0, nl = 0;
    uint8_t j, p = 0;
    for (j = 0; j < 63; j++) {
        uint32_t b = (j < 32) ? ((*lo >> j) & 1u) : ((*hi >> (j - 32)) & 1u);
        if (b) { if (p < 32) nl |= (1u << p); else nh |= (1u << (p - 32)); }
        p += 4; if (p >= 63) p -= 63;               // p = 4*j mod 63, no multiply
    }
    if (*hi >> 31) nh |= 0x80000000u;               // bit 63 stays put
    *hi = nh; *lo = nl;
}
static void inv_sbox_layer(uint32_t *hi, uint32_t *lo) {
    uint8_t i; uint32_t h = 0, l = 0;
    for (i = 0; i < 8; i++) {
        l |= (uint32_t)nib(ISBOX_LO, ISBOX_HI, (uint8_t)((*lo >> (i << 2)) & 0xF)) << (i << 2);
        h |= (uint32_t)nib(ISBOX_LO, ISBOX_HI, (uint8_t)((*hi >> (i << 2)) & 0xF)) << (i << 2);
    }
    *hi = h; *lo = l;
}

// Decrypts the 64-bit block (hi:lo) in place, using the PRESENT_KEY_* macros
static void present_decrypt(uint32_t *hi, uint32_t *lo) {
    uint16_t k[5];
    uint8_t i;
    k[4] = (uint16_t)(PRESENT_KEY_HI >> 16);  k[3] = (uint16_t)(PRESENT_KEY_HI & 0xFFFF);
    k[2] = (uint16_t)(PRESENT_KEY_MID >> 16); k[1] = (uint16_t)(PRESENT_KEY_MID & 0xFFFF);
    k[0] = (uint16_t)PRESENT_KEY_LO;
    // run the key schedule forward to get the register that holds K32
    for (i = 1; i <= 31; i++) { rotl61(k); top_nibble_sub(k, 0); xor_counter(k, i); }
    *hi ^= ((uint32_t)k[4] << 16) | k[3];            // add K32
    *lo ^= ((uint32_t)k[2] << 16) | k[1];
    for (i = 31; i >= 1; i--) {
        inv_perm(hi, lo);
        inv_sbox_layer(hi, lo);
        // step the key register back one round to get K_i
        xor_counter(k, i); top_nibble_sub(k, 1); rotr61(k);
        *hi ^= ((uint32_t)k[4] << 16) | k[3];
        *lo ^= ((uint32_t)k[2] << 16) | k[1];
    }
}

// ---------- Path planning: shortest path on the arena, tiny RAM ----------
// The arena's 37 lines are written as function calls (they live in the program,
// not in data memory). We use "Bellman-Ford": sweep over all lines again and
// again, improving distances, until a full sweep changes nothing.
// dist[] holds the distance from the END node, so later we can walk forward
// from the start node, always stepping to a neighbour that is closer.

typedef struct {
    uint8_t *dist;   // dist[1..36]
    uint8_t  mode;   // 0 = improve distances, 1 = find next step
    uint8_t  changed;
    uint8_t  v;      // node we are standing on (mode 1)
    uint8_t  nxt;    // chosen next node (mode 1), 0 = none yet
} PlanCtx;

// One line of the arena, between nodes a and b, of weight w
static void ed(PlanCtx *c, uint8_t a, uint8_t b, uint8_t w) {
    uint8_t *d = c->dist;
    if (c->mode == 0) {
        if ((uint16_t)d[a] + w < d[b]) { d[b] = (uint8_t)(d[a] + w); c->changed = 1; }
        if ((uint16_t)d[b] + w < d[a]) { d[a] = (uint8_t)(d[b] + w); c->changed = 1; }
    } else if (c->nxt == 0) {
        if (a == c->v && (uint16_t)d[b] + w == d[a]) c->nxt = b;
        else if (b == c->v && (uint16_t)d[a] + w == d[b]) c->nxt = a;
    }
}

// Figure 1: every line of the arena (node, node, weight)
static void arena(PlanCtx *c) {
    ed(c, 1, 4, 15);  ed(c, 1, 6, 15);  ed(c, 1, 5, 5);   ed(c, 1, 36, 100);
    ed(c, 2, 4, 5);   ed(c, 3, 6, 5);   ed(c, 4, 14, 15);
    ed(c, 5, 7, 11);  ed(c, 5, 8, 11);  ed(c, 7, 10, 5);  ed(c, 7, 15, 11);
    ed(c, 8, 11, 5);  ed(c, 8, 20, 11); ed(c, 9, 11, 7);  ed(c, 9, 12, 5);
    ed(c, 11, 19, 7); ed(c, 13, 14, 5); ed(c, 14, 15, 5); ed(c, 13, 30, 19);
    ed(c, 16, 17, 5); ed(c, 16, 23, 7); ed(c, 18, 19, 5); ed(c, 20, 21, 5);
    ed(c, 20, 27, 11); ed(c, 22, 25, 5); ed(c, 23, 25, 7); ed(c, 23, 26, 5);
    ed(c, 24, 27, 5); ed(c, 26, 29, 11); ed(c, 27, 29, 11); ed(c, 28, 31, 5);
    ed(c, 28, 32, 15); ed(c, 29, 32, 5); ed(c, 30, 33, 5); ed(c, 30, 35, 19);
    ed(c, 31, 34, 5); ed(c, 31, 35, 19);
}

// Writes the nodes from 'from' to 'to' into out[] (first node = from).
// dist must have 37 bytes of room. Returns how many nodes were written.
static uint8_t plan_path(uint8_t from, uint8_t to, uint8_t *dist, uint8_t *out) {
    PlanCtx c;
    uint8_t i, n = 0, v = from;
    if (from < 1 || from > 36 || to < 1 || to > 36) return 0;   // not an arena node
    for (i = 0; i < 37; i++) dist[i] = 255;
    dist[to] = 0;
    c.dist = dist; c.mode = 0;
    do { c.changed = 0; arena(&c); } while (c.changed);
    c.mode = 1;
    out[n++] = v;
    while (v != to) {
        c.v = v; c.nxt = 0;
        arena(&c);
        if (c.nxt == 0) break;          // cannot happen on this arena
        v = c.nxt;
        out[n++] = v;
    }
    return n;
}
"""

BLOCK_B = r"""
    // the working array lives at a fixed address on the CPU (working memory)
    #ifdef __linux__
        uint8_t dist[40];
    #else
        uint8_t *dist = (uint8_t *) 0x02000020;      // working memory starts at 0x02000020
    #endif

    if (is_encrypted == 0) {
        // plain node number: go from current_node to next_node
        end_point = NEXT_NODE;
    }
    else {
        // work on copies: the encrypted block in data memory must not be written
        uint32_t hi = ENCRYPTED_HI;
        uint32_t lo = ENCRYPTED_LO;
        present_decrypt(&hi, &lo);

        // decrypted block: byte 0 done, bytes 1..5 message, byte 6 next pick-up, byte 7 drop
        message[0] = (uint8_t)((hi >> 16) & 0xFF);
        message[1] = (uint8_t)((hi >> 8) & 0xFF);
        message[2] = (uint8_t)(hi & 0xFF);
        message[3] = (uint8_t)((lo >> 24) & 0xFF);
        message[4] = (uint8_t)((lo >> 16) & 0xFF);
        end_point  = (uint8_t)(lo & 0xFF);            // drop node

        if ((hi >> 24) == 0) {                        // done flag 0: set up the next move
            IS_ENCRYPTED = 0;
            NEXT_NODE    = (uint8_t)((lo >> 8) & 0xFF);   // next pick-up node
            CURRENT_NODE = end_point;                      // the bot will be at the drop node
        }
    }

    idx = plan_path(start_point, end_point, dist, path_planned);
"""

path = sys.argv[1] if len(sys.argv) > 1 else "Path_Planner_Dec.c"
text = open(path, newline="").read()
nl = "\r\n" if "\r\n" in text else "\n"
fix = lambda b: b.strip("\n").replace("\n", nl)

pos, out = 0, ""
for block in (BLOCK_A, BLOCK_B):
    a = text.find(START, pos)
    if a < 0:
        sys.exit("could not find the 'Add your code here' marker - is this the boilerplate file?")
    a_end = a + len(START)
    e = text.find(END, a_end)
    if e < 0:
        sys.exit("could not find the closing marker line")
    while e > a_end and text[e - 1] in " \t":      # keep the marker's own indentation
        e -= 1
    out += text[pos:a_end] + nl + fix(block) + nl + nl
    pos = e
out += text[pos:]
if out.count(START) != 2:
    sys.exit("expected exactly two 'Add your code here' markers, found %d" % out.count(START))
shutil.copyfile(path, path + ".bak")
open(path, "w", newline="").write(out)
print("done: patched " + path + " (backup: " + path + ".bak)")
