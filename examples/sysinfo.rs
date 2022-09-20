fn main() {
    match statgrab::init(true) {
        Ok(h) => {
            println!("{:?}", h.get_host_info(None));
            println!("{:?}", h.get_cpu_stats(None));
            println!("{:?}", h.get_mem_stats(None));
            println!("{:?}", h.get_load_stats(None));
            println!("{:?}", h.get_user_stats(None));
            println!("{:?}", h.get_swap_stats(Some(3)));
            println!("{:?}", h.get_fs_stats(None));
            println!("{:?}", h.get_disk_io_stats(None));
            println!("{:?}", h.get_network_io_stats(None));
            println!("{:?}", h.get_network_iface_stats(None));
            println!("{:?}", h.get_page_stats(None));
            println!("{:?}", h.get_process_stats(None));
            println!("{:?}", h.get_process_count_of(statgrab::ProcessCountSource::Entire));
        }
        Err(e) => panic!("{:?}", e),
    }
}
