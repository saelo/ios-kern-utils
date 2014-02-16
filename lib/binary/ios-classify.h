// the spec macro chooses between alternatives depending on the "class"
// possible "classes": armv6 pre 4.3, armv7 pre 4.3, 4.3.x, 5.0.x

static unsigned int _armv6 = 0;
static unsigned int _armv7 = 1;
static unsigned int _43 = 2;
static unsigned int _50 = 3;

#define spec_(c1, v1, c2, v2, c3, v3, c4, v4, ...) \
    (class >= (c1) ? (v1) : \
     class >= (c2) ? (v2) : \
     class >= (c3) ? (v3) : \
     class >= (c4) ? (v4) : \
     (die("no valid alternative"), (typeof(v1+0)) 0))
#define spec(args...) spec_(args, 10, 0, 10, 0, 10, 0)

#define is_armv7(binary) (binary->cpusubtype == 9)

static unsigned int classify(const struct binary *binary) {
    if(!is_armv7(binary)) return _armv6;
    else if(b_sym(binary, "_mach_gss_hold_cred", 0)) return _50;
    else if(b_sym(binary, "_vfs_getattr", 0)) return _43;
    else return _armv7;
}
