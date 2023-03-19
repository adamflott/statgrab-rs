use chrono::Duration;

pub struct SGHandle {}

#[derive(Debug, Clone)]
pub enum SGError {
    None,
    InvalidArgument,
    Asprintf,
    Sprintf,
    Devices,
    DevStatGetDevs,
    DevStatSelectDevs,
    DiskInfo,
    ENOENT,
    GetIFAddrs,
    GetMntInfo,
    GetPageSize,
    Host,
    KstatDataLookup,
    KstatLookup,
    KstatOpen,
    KstatRead,
    KVMGetSwapInfo,
    KVMOpenFiles,
    Malloc,
    MemStatus,
    Open,
    OpenDir,
    ReadDir,
    Parse,
    PDHADD,
    PDHCOLLECT,
    PDHOPEN,
    PDHREAD,
    Permission,
    Pstat,
    SetEgid,
    SetEuid,
    SetMntEnt,
    Socket,
    SwapCtl,
    SysConf,
    Sysctl,
    SysCtlByName,
    SysCtlNameToMib,
    SysInfo,
    MachCall,
    IOKit,
    Uname,
    Unsupported,
    XSWVerMismatch,
    GetMsg,
    PutMsg,
    Initialisation,
    MutexLock,
    MutexUnlock,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum HostState {
    UnknownConfiguration,
    PhysicalHost,
    VirtualMachine,
    ParavirtualMachine,
    HardwareVirtualized,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub os_name: String,
    pub os_release: String,
    pub os_version: String,
    pub platform: String,
    pub hostname: String,
    pub bitwidth: u32,
    pub host_state: HostState,
    pub ncpus: u32,
    pub maxcpus: u32,
    pub uptime: Duration,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct CPUStats {
    pub user: u64,
    pub kernel: u64,
    pub idle: u64,
    pub iowait: u64,
    pub swap: u64,
    pub nice: u64,
    pub total: u64,
    pub context_switches: u64,
    pub voluntary_context_switches: u64,
    pub involuntary_context_switches: u64,
    pub syscalls: u64,
    pub interrupts: u64,
    pub soft_interrupts: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub enum CPUPercentSource {
    EntireCPUPercent,
    LastDiffCPUPercent,
    NewDiffCPUPercent,
}

#[derive(Debug, Clone)]
pub struct CPUPercents {
    pub user: f64,
    pub kernel: f64,
    pub idle: f64,
    pub iowait: f64,
    pub swap: f64,
    pub nice: f64,
    pub time_taken: Duration,
}

#[derive(Debug, Clone)]
pub struct MemStats {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub cache: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct LoadStats {
    pub min1: f64,
    pub min5: f64,
    pub min15: f64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct UserStats {
    pub login_name: String,
    pub record_id: String,
    pub record_id_size: usize,
    pub device: String,
    pub hostname: String,
    pub pid: i32, // TODO check if there is some appropriate for pid_t,
    pub login_time: Duration,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct SwapStats {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub enum FilesystemDeviceType {
    Unknown,
    Regular,
    Special,
    Loopback,
    Remote,
    Local,
    AllTypes,
}

#[derive(Debug, Clone)]
pub struct FilesystemStats {
    pub device_name: String,
    pub device_canonical: String,
    pub fs_type: String,
    pub mnt_point: String,
    pub device_type: FilesystemDeviceType,
    pub size: u64,
    pub used: u64,
    pub free: u64,
    pub avail: u64,
    pub total_inodes: u64,
    pub used_inodes: u64,
    pub free_inodes: u64,
    pub avail_inodes: u64,
    pub io_size: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub used_blocks: u64,
    pub avail_blocks: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct DiskIOStats {
    pub disk_name: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct NetworkIOStats {
    pub interface_name: String,
    pub tx: u64,
    pub rx: u64,
    pub ipackets: u64,
    pub opackets: u64,
    pub ierrors: u64,
    pub oerrors: u64,
    pub collisions: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub enum IfaceDuplexType {
    Full,
    Half,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum IfaceUpdownType {
    Down,
    Up,
}

#[derive(Debug, Clone)]
pub struct NetworkIfaceStats {
    pub interface_name: String,
    pub speed: u64,
    pub factor: u64,
    pub duplex: IfaceDuplexType,
    pub up: IfaceUpdownType,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub struct PageStats {
    pub pages_pagein: u64,
    pub pages_pageout: u64,
    pub systime: Duration,
}

#[derive(Debug, Clone)]
pub enum ProcessState {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProcessStats {
    pub process_name: String,
    pub proctitle: String,
    pub pid: i32,
    pub parent: i32,
    pub pgid: i32,
    pub sessid: i32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub context_switches: u64,
    pub voluntary_context_switches: u64,
    pub involuntary_context_switches: u64,
    pub proc_size: u64,
    pub proc_resident: u64,
    pub start_time: Duration,
    pub time_spent: Duration,
    pub cpu_percent: f64,
    pub nice: i32,
    pub state: ProcessState,
    pub systime: Duration,
}

pub enum ProcessCountSource {
    Entire,
    Last,
}

#[derive(Debug, Clone)]
pub struct ProcessCount {
    pub total: u64,
    pub running: u64,
    pub sleeping: u64,
    pub stopped: u64,
    pub zombie: u64,
    pub unknown: u64,
    pub systime: Duration,
}

fn convert_lsg_error(err: libstatgrab_sys::sg_error) -> Option<SGError> {
    match err {
        libstatgrab_sys::sg_error_SG_ERROR_NONE => None,
        libstatgrab_sys::sg_error_SG_ERROR_INVALID_ARGUMENT => Some(SGError::InvalidArgument),
        libstatgrab_sys::sg_error_SG_ERROR_ASPRINTF => Some(SGError::Asprintf),
        libstatgrab_sys::sg_error_SG_ERROR_SPRINTF => Some(SGError::Sprintf),
        libstatgrab_sys::sg_error_SG_ERROR_DEVICES => Some(SGError::Devices),
        libstatgrab_sys::sg_error_SG_ERROR_DEVSTAT_GETDEVS => Some(SGError::DevStatGetDevs),
        libstatgrab_sys::sg_error_SG_ERROR_DEVSTAT_SELECTDEVS => Some(SGError::DevStatSelectDevs),
        libstatgrab_sys::sg_error_SG_ERROR_DISKINFO => Some(SGError::DiskInfo),
        libstatgrab_sys::sg_error_SG_ERROR_ENOENT => Some(SGError::ENOENT),
        libstatgrab_sys::sg_error_SG_ERROR_GETIFADDRS => Some(SGError::GetIFAddrs),
        libstatgrab_sys::sg_error_SG_ERROR_GETMNTINFO => Some(SGError::GetMntInfo),
        libstatgrab_sys::sg_error_SG_ERROR_GETPAGESIZE => Some(SGError::GetPageSize),
        libstatgrab_sys::sg_error_SG_ERROR_HOST => Some(SGError::Host),
        libstatgrab_sys::sg_error_SG_ERROR_KSTAT_DATA_LOOKUP => Some(SGError::KstatDataLookup),
        libstatgrab_sys::sg_error_SG_ERROR_KSTAT_LOOKUP => Some(SGError::KstatLookup),
        libstatgrab_sys::sg_error_SG_ERROR_KSTAT_OPEN => Some(SGError::KstatOpen),
        libstatgrab_sys::sg_error_SG_ERROR_KSTAT_READ => Some(SGError::KstatRead),
        libstatgrab_sys::sg_error_SG_ERROR_KVM_GETSWAPINFO => Some(SGError::KVMGetSwapInfo),
        libstatgrab_sys::sg_error_SG_ERROR_KVM_OPENFILES => Some(SGError::KVMOpenFiles),
        libstatgrab_sys::sg_error_SG_ERROR_MALLOC => Some(SGError::Malloc),
        libstatgrab_sys::sg_error_SG_ERROR_MEMSTATUS => Some(SGError::MemStatus),
        libstatgrab_sys::sg_error_SG_ERROR_OPEN => Some(SGError::Open),
        libstatgrab_sys::sg_error_SG_ERROR_OPENDIR => Some(SGError::OpenDir),
        libstatgrab_sys::sg_error_SG_ERROR_READDIR => Some(SGError::ReadDir),
        libstatgrab_sys::sg_error_SG_ERROR_PARSE => Some(SGError::Parse),
        libstatgrab_sys::sg_error_SG_ERROR_PDHADD => Some(SGError::PDHADD),
        libstatgrab_sys::sg_error_SG_ERROR_PDHCOLLECT => Some(SGError::PDHCOLLECT),
        libstatgrab_sys::sg_error_SG_ERROR_PDHOPEN => Some(SGError::PDHOPEN),
        libstatgrab_sys::sg_error_SG_ERROR_PDHREAD => Some(SGError::PDHREAD),
        libstatgrab_sys::sg_error_SG_ERROR_PERMISSION => Some(SGError::Permission),
        libstatgrab_sys::sg_error_SG_ERROR_PSTAT => Some(SGError::Pstat),
        libstatgrab_sys::sg_error_SG_ERROR_SETEGID => Some(SGError::SetEgid),
        libstatgrab_sys::sg_error_SG_ERROR_SETEUID => Some(SGError::SetEuid),
        libstatgrab_sys::sg_error_SG_ERROR_SETMNTENT => Some(SGError::SetMntEnt),
        libstatgrab_sys::sg_error_SG_ERROR_SOCKET => Some(SGError::Socket),
        libstatgrab_sys::sg_error_SG_ERROR_SWAPCTL => Some(SGError::SwapCtl),
        libstatgrab_sys::sg_error_SG_ERROR_SYSCONF => Some(SGError::SysConf),
        libstatgrab_sys::sg_error_SG_ERROR_SYSCTL => Some(SGError::Sysctl),
        libstatgrab_sys::sg_error_SG_ERROR_SYSCTLBYNAME => Some(SGError::SysCtlByName),
        libstatgrab_sys::sg_error_SG_ERROR_SYSCTLNAMETOMIB => Some(SGError::SysCtlNameToMib),
        libstatgrab_sys::sg_error_SG_ERROR_SYSINFO => Some(SGError::SysInfo),
        libstatgrab_sys::sg_error_SG_ERROR_MACHCALL => Some(SGError::MachCall),
        libstatgrab_sys::sg_error_SG_ERROR_IOKIT => Some(SGError::IOKit),
        libstatgrab_sys::sg_error_SG_ERROR_UNAME => Some(SGError::Uname),
        libstatgrab_sys::sg_error_SG_ERROR_UNSUPPORTED => Some(SGError::Unsupported),
        libstatgrab_sys::sg_error_SG_ERROR_XSW_VER_MISMATCH => Some(SGError::XSWVerMismatch),
        libstatgrab_sys::sg_error_SG_ERROR_GETMSG => Some(SGError::GetMsg),
        libstatgrab_sys::sg_error_SG_ERROR_PUTMSG => Some(SGError::PutMsg),
        libstatgrab_sys::sg_error_SG_ERROR_INITIALISATION => Some(SGError::Initialisation),
        libstatgrab_sys::sg_error_SG_ERROR_MUTEX_LOCK => Some(SGError::MutexLock),
        libstatgrab_sys::sg_error_SG_ERROR_MUTEX_UNLOCK => Some(SGError::MutexUnlock),
        _ => Some(SGError::Unknown),
    }
}

pub fn init(ignore_init_errors: bool) -> Result<SGHandle, SGError> {
    unsafe {
        if ignore_init_errors {
            libstatgrab_sys::sg_init(1);
            Ok(SGHandle {})
        } else {
            let err = libstatgrab_sys::sg_init(0);

            match convert_lsg_error(err) {
                None => Err(SGError::Unknown),
                Some(err) => Err(err),
            }
        }
    }
}

fn to_c_entries(maybe_entries: Option<usize>) -> usize {
    maybe_entries.map_or(0, |v| v)
}

impl Drop for SGHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl SGHandle {
    pub fn shutdown(&self) -> Option<SGError> {
        let err = unsafe { libstatgrab_sys::sg_shutdown() };
        convert_lsg_error(err)
    }

    pub fn drop_privileges() -> Option<SGError> {
        let err = unsafe { libstatgrab_sys::sg_drop_privileges() };
        convert_lsg_error(err)
    }

    pub fn get_host_info(&self) -> HostInfo {
        let mut sz: usize = 0;
        unsafe {
            let general_stats = libstatgrab_sys::sg_get_host_info_r(&mut sz);
            let host_state = match (*general_stats).host_state {
                libstatgrab_sys::sg_host_state_sg_physical_host => HostState::PhysicalHost,
                libstatgrab_sys::sg_host_state_sg_virtual_machine => HostState::VirtualMachine,
                libstatgrab_sys::sg_host_state_sg_paravirtual_machine => HostState::ParavirtualMachine,
                libstatgrab_sys::sg_host_state_sg_hardware_virtualized => HostState::VirtualMachine,
                _ => HostState::UnknownConfiguration,
            };
            HostInfo {
                os_name: std::ffi::CStr::from_ptr((*general_stats).os_name).to_string_lossy().into_owned(),
                os_release: std::ffi::CStr::from_ptr((*general_stats).os_release).to_string_lossy().into_owned(),
                os_version: std::ffi::CStr::from_ptr((*general_stats).os_version).to_string_lossy().into_owned(),
                platform: std::ffi::CStr::from_ptr((*general_stats).platform).to_string_lossy().into_owned(),
                hostname: std::ffi::CStr::from_ptr((*general_stats).hostname).to_string_lossy().into_owned(),
                bitwidth: (*general_stats).bitwidth,
                host_state,
                ncpus: (*general_stats).ncpus,
                maxcpus: (*general_stats).maxcpus,
                uptime: chrono::Duration::seconds((*general_stats).uptime),
                systime: chrono::Duration::seconds((*general_stats).systime),
            }
        }
    }

    pub fn get_cpu_stats(&self) -> CPUStats {
        let mut sz: usize = 0;
        unsafe {
            let cpu_stats = libstatgrab_sys::sg_get_cpu_stats(&mut sz);
            CPUStats {
                user: (*cpu_stats).user,
                kernel: (*cpu_stats).kernel,
                idle: (*cpu_stats).idle,
                iowait: (*cpu_stats).iowait,
                swap: (*cpu_stats).swap,
                nice: (*cpu_stats).nice,
                total: (*cpu_stats).total,
                context_switches: (*cpu_stats).context_switches,
                voluntary_context_switches: (*cpu_stats).voluntary_context_switches,
                involuntary_context_switches: (*cpu_stats).involuntary_context_switches,
                syscalls: (*cpu_stats).syscalls,
                interrupts: (*cpu_stats).interrupts,
                soft_interrupts: (*cpu_stats).soft_interrupts,
                systime: chrono::Duration::seconds((*cpu_stats).systime),
            }
        }
    }

    pub fn get_cpu_stats_diff(&self, maybe_entries: Option<usize>) -> CPUStats {
        let mut c_entries = to_c_entries(maybe_entries);
        unsafe {
            let cpu_stats = libstatgrab_sys::sg_get_cpu_stats_diff(&mut c_entries);
            CPUStats {
                user: (*cpu_stats).user,
                kernel: (*cpu_stats).kernel,
                idle: (*cpu_stats).idle,
                iowait: (*cpu_stats).iowait,
                swap: (*cpu_stats).swap,
                nice: (*cpu_stats).nice,
                total: (*cpu_stats).total,
                context_switches: (*cpu_stats).context_switches,
                voluntary_context_switches: (*cpu_stats).voluntary_context_switches,
                involuntary_context_switches: (*cpu_stats).involuntary_context_switches,
                syscalls: (*cpu_stats).syscalls,
                interrupts: (*cpu_stats).interrupts,
                soft_interrupts: (*cpu_stats).soft_interrupts,
                systime: chrono::Duration::seconds((*cpu_stats).systime),
            }
        }
    }

    pub fn get_cpu_percents_of(&self, cps: CPUPercentSource, maybe_entries: Option<usize>) -> CPUPercents {
        let mut c_entries = to_c_entries(maybe_entries);
        unsafe {
            let c_cps = match cps {
                CPUPercentSource::EntireCPUPercent => libstatgrab_sys::sg_cpu_percent_source_sg_entire_cpu_percent,
                CPUPercentSource::LastDiffCPUPercent => libstatgrab_sys::sg_cpu_percent_source_sg_last_diff_cpu_percent,
                CPUPercentSource::NewDiffCPUPercent => libstatgrab_sys::sg_cpu_percent_source_sg_new_diff_cpu_percent,
            };
            let cpu_percents = libstatgrab_sys::sg_get_cpu_percents_of(c_cps, &mut c_entries);
            CPUPercents {
                user: (*cpu_percents).user,
                kernel: (*cpu_percents).kernel,
                idle: (*cpu_percents).idle,
                iowait: (*cpu_percents).iowait,
                swap: (*cpu_percents).swap,
                nice: (*cpu_percents).nice,
                time_taken: chrono::Duration::seconds((*cpu_percents).time_taken),
            }
        }
    }

    pub fn get_mem_stats(&self) -> MemStats {
        let mut sz: usize = 0;
        unsafe {
            let ms = libstatgrab_sys::sg_get_mem_stats_r(&mut sz);
            MemStats {
                total: (*ms).total,
                free: (*ms).free,
                used: (*ms).used,
                cache: (*ms).cache,
                systime: chrono::Duration::seconds((*ms).systime),
            }
        }
    }

    pub fn get_load_stats(&self) -> LoadStats {
        let mut sz: usize = 0;
        unsafe {
            let ms = libstatgrab_sys::sg_get_load_stats_r(&mut sz);
            LoadStats {
                min1: (*ms).min1,
                min5: (*ms).min5,
                min15: (*ms).min15,
                systime: chrono::Duration::seconds((*ms).systime),
            }
        }
    }

    pub fn get_user_stats(&self) -> UserStats {
        let mut sz: usize = 0;
        unsafe {
            let us = libstatgrab_sys::sg_get_user_stats_r(&mut sz);
            UserStats {
                login_name: std::ffi::CStr::from_ptr((*us).login_name).to_string_lossy().into_owned(),
                record_id: std::ffi::CStr::from_ptr((*us).record_id).to_string_lossy().into_owned(),
                record_id_size: (*us).record_id_size,
                device: std::ffi::CStr::from_ptr((*us).device).to_string_lossy().into_owned(),
                hostname: std::ffi::CStr::from_ptr((*us).hostname).to_string_lossy().into_owned(),
                pid: (*us).pid,
                login_time: chrono::Duration::seconds((*us).login_time),
                systime: chrono::Duration::seconds((*us).systime),
            }
        }
    }

    pub fn get_swap_stats(&self) -> SwapStats {
        let mut sz: usize = 0;
        unsafe {
            let ss = libstatgrab_sys::sg_get_swap_stats_r(&mut sz);
            SwapStats {
                total: (*ss).total,
                used: (*ss).used,
                free: (*ss).free,
                systime: chrono::Duration::seconds((*ss).systime),
            }
        }
    }

    pub fn get_fs_stats(&self) -> Vec<FilesystemStats> {
        let mut sz: usize = 0;
        let mut r = vec![];
        unsafe {
            let fs_ptr = libstatgrab_sys::sg_get_fs_stats_r(&mut sz);
            let fss = std::slice::from_raw_parts(fs_ptr, sz);

            for fs in fss {
                let device_type = match (fs).device_type {
                    libstatgrab_sys::sg_fs_device_type_sg_fs_unknown => FilesystemDeviceType::Unknown,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_regular => FilesystemDeviceType::Regular,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_special => FilesystemDeviceType::Special,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_loopback => FilesystemDeviceType::Loopback,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_remote => FilesystemDeviceType::Remote,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_local => FilesystemDeviceType::Local,
                    libstatgrab_sys::sg_fs_device_type_sg_fs_alltypes => FilesystemDeviceType::AllTypes,
                    _ => FilesystemDeviceType::Unknown,
                };

                r.push(FilesystemStats {
                    device_name: std::ffi::CStr::from_ptr((fs).device_name).to_string_lossy().into_owned(),
                    device_canonical: std::ffi::CStr::from_ptr((fs).device_canonical).to_string_lossy().into_owned(),
                    fs_type: std::ffi::CStr::from_ptr((fs).fs_type).to_string_lossy().into_owned(),
                    mnt_point: std::ffi::CStr::from_ptr((fs).mnt_point).to_string_lossy().into_owned(),
                    device_type,
                    size: (fs).size,
                    used: (fs).used,
                    free: (fs).free,
                    avail: (fs).avail,
                    total_inodes: (fs).total_inodes,
                    used_inodes: (fs).used_inodes,
                    free_inodes: (fs).free_inodes,
                    avail_inodes: (fs).avail_inodes,
                    io_size: (fs).io_size,
                    block_size: (fs).block_size,
                    total_blocks: (fs).total_blocks,
                    free_blocks: (fs).free_blocks,
                    used_blocks: (fs).used_blocks,
                    avail_blocks: (fs).avail_blocks,
                    systime: chrono::Duration::seconds((fs).systime),
                });
            }
        }
        r
    }

    pub fn get_disk_io_stats(&self) -> Vec<DiskIOStats> {
        let mut sz: usize = 0;
        let mut r = vec![];
        unsafe {
            let ds_ptr = libstatgrab_sys::sg_get_disk_io_stats_r(&mut sz);
            let dss = std::slice::from_raw_parts(ds_ptr, sz);

            for ds in dss {
                r.push(DiskIOStats {
                    disk_name: std::ffi::CStr::from_ptr((ds).disk_name).to_string_lossy().into_owned(),
                    read_bytes: (ds).read_bytes,
                    write_bytes: (ds).write_bytes,
                    systime: chrono::Duration::seconds((ds).systime),
                });
            }
        }
        r
    }

    pub fn get_network_io_stats(&self) -> Vec<NetworkIOStats> {
        let mut sz: usize = 0;
        let mut r = vec![];
        unsafe {
            let ns_ptr = libstatgrab_sys::sg_get_network_io_stats_r(&mut sz);
            let nss = std::slice::from_raw_parts(ns_ptr, sz);

            for ns in nss {
                r.push(NetworkIOStats {
                    interface_name: std::ffi::CStr::from_ptr((ns).interface_name).to_string_lossy().into_owned(),
                    tx: (ns).tx,
                    rx: (ns).rx,
                    ipackets: (ns).ipackets,
                    opackets: (ns).opackets,
                    ierrors: (ns).ierrors,
                    oerrors: (ns).oerrors,
                    collisions: (ns).collisions,
                    systime: chrono::Duration::seconds((ns).systime),
                });
            }
        }
        r
    }

    pub fn get_network_iface_stats(&self) -> Vec<NetworkIfaceStats> {
        let mut sz: usize = 0;
        let mut r = vec![];
        unsafe {
            let ns_ptr = libstatgrab_sys::sg_get_network_iface_stats_r(&mut sz);
            let nss = std::slice::from_raw_parts(ns_ptr, sz);

            for ns in nss {
                let duplex = match (ns).duplex {
                    libstatgrab_sys::sg_iface_duplex_SG_IFACE_DUPLEX_FULL => IfaceDuplexType::Full,
                    libstatgrab_sys::sg_iface_duplex_SG_IFACE_DUPLEX_HALF => IfaceDuplexType::Half,
                    _ => IfaceDuplexType::Unknown,
                };
                let up = match (ns).up {
                    libstatgrab_sys::sg_iface_updown_SG_IFACE_DOWN => IfaceUpdownType::Down,
                    libstatgrab_sys::sg_iface_updown_SG_IFACE_UP => IfaceUpdownType::Up,
                    _ => IfaceUpdownType::Down,
                };

                r.push(NetworkIfaceStats {
                    interface_name: std::ffi::CStr::from_ptr((ns).interface_name).to_string_lossy().into_owned(),
                    speed: (ns).speed,
                    factor: (ns).factor,
                    duplex,
                    up,
                    systime: chrono::Duration::seconds((ns).systime),
                });
            }
        }
        r
    }

    pub fn get_page_stats(&self) -> PageStats {
        let mut sz: usize = 0;
        unsafe {
            let ps = libstatgrab_sys::sg_get_page_stats_r(&mut sz);
            PageStats {
                pages_pagein: (*ps).pages_pagein,
                pages_pageout: (*ps).pages_pageout,
                systime: chrono::Duration::seconds((*ps).systime),
            }
        }
    }

    pub fn get_process_stats(&self) -> Vec<ProcessStats> {
        let mut sz: usize = 0;
        let mut r = vec![];
        unsafe {
            let ps_ptr = libstatgrab_sys::sg_get_process_stats_r(&mut sz);
            let pss = std::slice::from_raw_parts(ps_ptr, sz);

            for ps in pss {
                let state = match (ps).state {
                    libstatgrab_sys::sg_process_state_SG_PROCESS_STATE_RUNNING => ProcessState::Running,
                    libstatgrab_sys::sg_process_state_SG_PROCESS_STATE_SLEEPING => ProcessState::Sleeping,
                    libstatgrab_sys::sg_process_state_SG_PROCESS_STATE_STOPPED => ProcessState::Stopped,
                    libstatgrab_sys::sg_process_state_SG_PROCESS_STATE_ZOMBIE => ProcessState::Zombie,
                    libstatgrab_sys::sg_process_state_SG_PROCESS_STATE_UNKNOWN => ProcessState::Unknown,
                    _ => ProcessState::Unknown,
                };
                r.push(ProcessStats {
                    process_name: std::ffi::CStr::from_ptr((ps).process_name).to_string_lossy().into_owned(),
                    proctitle: std::ffi::CStr::from_ptr((ps).proctitle).to_string_lossy().into_owned(),
                    pid: (ps).pid,
                    parent: (ps).parent,
                    pgid: (ps).pgid,
                    sessid: (ps).sessid,
                    uid: (ps).uid,
                    euid: (ps).euid,
                    gid: (ps).gid,
                    egid: (ps).egid,
                    context_switches: (ps).context_switches,
                    voluntary_context_switches: (ps).voluntary_context_switches,
                    involuntary_context_switches: (ps).involuntary_context_switches,
                    proc_size: (ps).proc_size,
                    proc_resident: (ps).proc_resident,
                    start_time: chrono::Duration::seconds((ps).start_time),
                    time_spent: chrono::Duration::seconds((ps).time_spent),
                    cpu_percent: (ps).cpu_percent,
                    nice: (ps).nice,
                    state,
                    systime: chrono::Duration::seconds((ps).systime),
                });
            }
        }
        r
    }

    pub fn get_process_count_of(&self, source: ProcessCountSource) -> ProcessCount {
        let c_source = match source {
            ProcessCountSource::Entire => libstatgrab_sys::sg_process_count_source_sg_entire_process_count,
            ProcessCountSource::Last => libstatgrab_sys::sg_process_count_source_sg_last_process_count,
        };
        unsafe {
            let ps = libstatgrab_sys::sg_get_process_count_of(c_source);
            ProcessCount {
                total: (*ps).total,
                running: (*ps).running,
                sleeping: (*ps).sleeping,
                stopped: (*ps).stopped,
                zombie: (*ps).zombie,
                unknown: (*ps).unknown,
                systime: chrono::Duration::seconds((*ps).systime),
            }
        }
    }
}

#[cfg(test)]
#[allow(unused_comparisons)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn host_info() {
        match init(true) {
            Ok(h) => {
                let hi = h.get_host_info();
                assert_eq!(&hi.os_name, "Linux");
            }
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn cpu_stats() {
        match init(true) {
            Ok(h) => {
                let cs = h.get_cpu_stats();
                assert!(cs.user >= 0);
            }
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn mem_stats() {
        match init(true) {
            Ok(h) => {
                let cs = h.get_mem_stats();
                assert!(cs.total > 0);
            }
            Err(e) => panic!("{:?}", e),
        }
    }

    #[test]
    fn load_stats() {
        match init(true) {
            Ok(h) => {
                let cs = h.get_load_stats();
                assert!(cs.min5 > 0.0);
            }
            Err(e) => panic!("{:?}", e),
        }
    }
}
