#ifndef _INCLGUARD_CLONERING_RUST_INTERFACE_H_
#define _INCLGUARD_CLONERING_RUST_INTERFACE_H_

struct RustGlobalsStruct
{
    void* global;
    void* cli_conf;
    void* fail_map;
};

struct RustGlobalsStruct rust_init(int cur_lcore_id, uint8_t* station_key);
uint8_t rust_update_cli_conf(void* conf_ptr);
uint8_t rust_process_packet(void* rust_global, void* c_raw_ethframe,
                            size_t c_frame_len);
uint8_t rust_event_loop_tick(void* rust_global);
uint8_t rust_update_overloaded_decoys(void* rust_global);
uint8_t rust_periodic_report(void* rust_global);
uint8_t rust_periodic_cleanup(void* rust_global);

#endif //_INCLGUARD_CLONERING_RUST_INTERFACE_H_
