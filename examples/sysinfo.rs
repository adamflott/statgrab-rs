fn main() {
    match statgrab::init(true) {
        Ok(h) => {
            println!("{:?}", h.get_host_info());
            println!("{:?}", h.get_cpu_stats());
            println!("{:?}", h.get_mem_stats());
            println!("{:?}", h.get_load_stats());
            println!("{:?}", h.get_user_stats());
            println!("{:?}", h.get_swap_stats());
            println!("{:?}", h.get_fs_stats());
            println!("{:?}", h.get_disk_io_stats());
            println!("{:?}", h.get_network_io_stats());
            println!("{:?}", h.get_network_iface_stats());
            println!("{:?}", h.get_page_stats());
            println!("{:?}", h.get_process_stats());
            println!("{:?}", h.get_process_count_of(statgrab::ProcessCountSource::Entire));
        }
        Err(e) => panic!("{:?}", e),
    }
}
