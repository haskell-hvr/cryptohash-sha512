## 0.11.101.0

 - Add Eq instance for Ctx
 - add start and startlazy producing Ctx
 - Remove ineffective RULES

## 0.11.100.1

 - First public release

## 0.11.100.0 *(unreleased)*

 - new `hmac` and `hmaclazy` functions providing HMAC-SHA-512
   computation conforming to RFC2104 and RFC4231
 - fix unaligned memory-accesses
 - switch to 'safe' FFI for calls where overhead becomes neglible
 - removed inline assembly in favour of portable C constructs
 - fix 32bit length overflow bug in `hash` function
 - fix inaccurate context-size
 - add context-size verification to incremental API operations

## 0.11.7.1 *(unreleased)*

 - first version forked off `cryptohash-0.11.7` release
