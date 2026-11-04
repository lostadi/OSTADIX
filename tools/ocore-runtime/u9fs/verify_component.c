/* Test carrier only. Production implementations come from the pinned sources. */
#include <plan9.h>
#include <fcall.h>

extern uint ref_convM2S(uchar *, uint, Fcall *);
extern uint ref_convS2M(Fcall *, uchar *, uint);
extern int ref_statcheck(uchar *, uint);
extern uint ref_convM2D(uchar *, uint, Dir *, char *);
extern uint ref_convD2M(Dir *, uchar *, uint);
extern uint ref_sizeD2M(Dir *);
extern void *ref_memmove(void *, const void *, size_t);
extern void *ref_memcpy(void *, const void *, size_t);
extern size_t ref_strlen(const char *);
extern void test_write(const char *, size_t);

_Static_assert(sizeof(Fcall) == 712, "original Fcall LP64 ABI changed");
_Static_assert(_Alignof(Fcall) == 8, "original Fcall alignment changed");
_Static_assert(sizeof(Qid) == 24, "original Qid LP64 ABI changed");
static unsigned checks;

static void fill(void *memory, unsigned count, unsigned value)
{
    volatile unsigned char *p = memory;
    while (count--) *p++ = (unsigned char)value;
}

static int equal(const void *left, const void *right, unsigned count)
{
    const unsigned char *a = left, *b = right;
    while (count--) if (*a++ != *b++) return 0;
    return 1;
}

static int same_text(const char *left, const char *right)
{
    unsigned n = ref_strlen(left);
    return n == ref_strlen(right) && equal(left, right, n);
}

static void number(unsigned value)
{
    char digits[16]; unsigned n = 0;
    do { digits[n++] = '0' + value % 10; value /= 10; } while (value);
    while (n) test_write(&digits[--n], 1);
    test_write("\n", 1);
}

#define CHECK(expression) do { checks++; if (!(expression)) { \
    test_write("FAIL line ", 10); number(__LINE__); return 1; } } while (0)

int main(void)
{
    unsigned char wire[16384], reference[16384], a[16384], b[16384];
    unsigned char encoded[16384], encoded_ref[16384], data[257], stat[1024];
    unsigned char left[1024], right[1024], input[1024];
    Dir d, da, db; char sa[2048], sb[2048];
    fill(&d, sizeof(d), 0); fill(&da, sizeof(da), 0); fill(&db, sizeof(db), 0);
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = (unsigned char)(i * 73);
    for (unsigned i = 0; i < sizeof(input); i++) input[i] = (unsigned char)(i * 37 + 13);
    for (unsigned alignment = 0; alignment < 32; alignment++) {
        for (unsigned n = 0; n < 257; n++) {
            fill(left, sizeof(left), 0xa5); fill(right, sizeof(right), 0xa5);
            CHECK(memcpy(left + alignment, input + 31 - alignment, n) == left + alignment);
            CHECK(ref_memcpy(right + alignment, input + 31 - alignment, n) == right + alignment);
            CHECK(equal(left, right, sizeof(left)));
            CHECK(memmove(left + alignment + 3, left + alignment, n) == left + alignment + 3);
            CHECK(ref_memmove(right + alignment + 3, right + alignment, n) == right + alignment + 3);
            CHECK(equal(left, right, sizeof(left)));
            CHECK(memmove(left + alignment, left + alignment + 3, n) == left + alignment);
            CHECK(ref_memmove(right + alignment, right + alignment + 3, n) == right + alignment);
            CHECK(equal(left, right, sizeof(left)));
            fill(left, sizeof(left), 'a'); left[alignment + n] = 0;
            CHECK(strlen((char *)left + alignment) == ref_strlen((char *)left + alignment));
            CHECK(strlen((char *)left + alignment) == n);
        }
    }
    d.type = 0x1234; d.dev = 0xfedcba98; d.qid.type = 0x80;
    d.qid.vers = 0xabcdef89; d.qid.path = 0x123456789abcdef0ULL;
    d.mode = 0x800001ff; d.atime = 123456; d.mtime = 654321;
    d.length = 0x1122334455667788ULL; d.name = "native-wire-file";
    d.uid = "original-user"; d.gid = "original-group"; d.muid = "";
    CHECK(sizeD2M(&d) == ref_sizeD2M(&d));
    unsigned ns = convD2M(&d, stat, sizeof(stat));
    unsigned nr = ref_convD2M(&d, reference, sizeof(reference));
    CHECK(ns > 0 && ns == nr); CHECK(equal(stat, reference, ns));
    CHECK(statcheck(stat, ns) == 0 && ref_statcheck(reference, ns) == 0);
    CHECK(convM2D(stat, ns, &da, sa) == ref_convM2D(reference, ns, &db, sb));
    CHECK(da.type == db.type && da.dev == db.dev && da.qid.path == db.qid.path &&
          da.qid.vers == db.qid.vers && da.qid.type == db.qid.type);
    CHECK(da.mode == db.mode && da.atime == db.atime && da.mtime == db.mtime && da.length == db.length);
    CHECK(same_text(da.name, db.name) && same_text(da.uid, db.uid) &&
          same_text(da.gid, db.gid) && same_text(da.muid, db.muid));
    for (unsigned n = 0; n < ns; n++) {
        CHECK(convD2M(&d, a, n) == ref_convD2M(&d, b, n));
        CHECK(statcheck(stat, n) == ref_statcheck(reference, n));
    }
    for (unsigned variant = 0; variant < 17; variant++) {
        Fcall f; fill(&f, sizeof(f), 0);
        f.fid = 0xfedcba98; f.tag = 0xabcd; f.msize = 8192; f.version = VERSION9P;
        f.oldtag = 0x1234; f.ename = "original-error"; f.qid = d.qid; f.iounit = 4096;
        f.uname = "original-user"; f.aname = "/work"; f.perm = 0666;
        f.name = "native-file"; f.mode = 2; f.newfid = 0xabcdef01;
        f.nwname = variant; f.nwqid = variant;
        for (unsigned i = 0; i < MAXWELEM; i++) {
            f.wname[i] = i % 2 ? "" : "component"; f.wqid[i] = d.qid; f.wqid[i].path += i;
        }
        f.offset = 0x123456789abcdef0LL; f.count = variant ? 257 : 0;
        f.data = (char *)data; f.nstat = ns; f.stat = stat; f.afid = NOFID; f.aqid = d.qid;
        for (unsigned type = Tversion; type < Tmax; type++) {
            if (type == Terror) continue;
            f.type = type;
            unsigned n = convS2M(&f, wire, sizeof(wire));
            unsigned rn = ref_convS2M(&f, reference, sizeof(reference));
            CHECK(n > 0 && n == rn); CHECK(equal(wire, reference, n));
            CHECK(convS2M(&f, a, n - 1) == ref_convS2M(&f, b, n - 1));
            Fcall fa, fb; fill(&fa, sizeof(fa), 0); fill(&fb, sizeof(fb), 0);
            ref_memcpy(a, wire, n); ref_memcpy(b, reference, n);
            unsigned an = convM2S(a, n, &fa), bn = ref_convM2S(b, n, &fb);
            CHECK(an == bn);
            if (bn) {
                unsigned en = convS2M(&fa, encoded, sizeof(encoded));
                unsigned ern = ref_convS2M(&fb, encoded_ref, sizeof(encoded_ref));
                CHECK(en == n && ern == n && equal(encoded, encoded_ref, n) && equal(encoded, wire, n));
            } else { CHECK(type == Rauth); } /* Exact upstream behavior. */
            for (unsigned cut = 0; cut < n; cut++) {
                fill(&fa, sizeof(fa), 0); fill(&fb, sizeof(fb), 0);
                ref_memcpy(a, wire, n); ref_memcpy(b, reference, n);
                CHECK(convM2S(a, cut, &fa) == ref_convM2S(b, cut, &fb));
            }
        }
    }
    static const char success[] = "Original u9fs and musl via O-core: PASS; checks=";
    test_write(success, sizeof(success) - 1);
    number(checks);
    return 0;
}
