#ifndef _TD_LOADKEY_H_
#define _TD_LOADKEY_H_ 1

#define TD_KEYLEN_BYTES	(32)
#define	TD_IDLEN_BYTES	(16)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int td_load_station_key(const char *fname,
                        uint8_t stationkey[TD_KEYLEN_BYTES],
                        uint8_t pubkey[TD_KEYLEN_BYTES]);

void td_print_key(const uint8_t key[TD_KEYLEN_BYTES]);

char *td_key2str(const uint8_t key[TD_KEYLEN_BYTES]);

#ifdef __cplusplus
};
#endif // __cplusplus

#endif // _TD_LOADKEY_H_
