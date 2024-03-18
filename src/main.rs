use clap::Parser;
use std::arch::x86_64::{CpuidResult, __cpuid, __cpuid_count};

const COLOR_WHITE_START: &str = "\x1b[1;97m";
const COLOR_END: &str = "\x1b[0m";

const CPU_VENDOR_INTEL: u32 = 0x756e6547;

#[allow(dead_code)]
// Thanks to @lake@shonk.social for the ID
const CPU_VENDOR_AMD: u32 = 0x68747541;

#[derive(Parser)]
#[clap(about = "lsce: Display supported CPU features for Unix-like systems")]
struct Args {
    /// Print CPU vendor name
    #[arg(short, long)]
    vendor: bool,

    /// Print CPU package name
    #[arg(short, long)]
    name: bool,

    /// Print available CPU features
    #[arg(short, long)]
    feats: bool,

    /// Print identity of the CPU (e.g. family, model, etc.)
    #[arg(short, long)]
    identity: bool,
}

// Lsce implementation structure
struct Lsce {
    /// Name of the CPU vendor
    cpu_vendor: [char; 12],

    /// Name of the CPU
    cpu_name: String,

    /// CPU model ID
    cpu_model: u32,

    /// CPU extended model ID
    cpu_ext_model: u32,

    /// CPU model synth
    cpu_model_synth: u32,

    /// CPU family
    cpu_family: u32,

    /// CPU extended family
    cpu_ext_family: u32,

    /// CPU family synth
    cpu_family_synth: u32,

    /// List of CPU features
    cpu_feats: String,
}

// Extract 1-byte on each iteration, total of 4-bytes
macro_rules! extract_bytes {
    ($func:expr, $reg:expr) => {
        for i in 0..4 {
            $func.push(($reg >> (i * 8) & 0xff) as u8 as char);
        }
    };
}

// Test whether a CPU feature is available or not
macro_rules! add_if_supports {
    ($cpu_feats:expr, $reg:expr, $bit:expr, $feat:expr) => {
        if (1 << $bit) & $reg != 0 {
            $cpu_feats.push_str($feat);
            $cpu_feats.push(' ');
        }
    };
}

impl Lsce {
    fn new() -> Lsce {
        Lsce {
            cpu_vendor: ['\0'; 12],
            cpu_name: "".to_string(),
            cpu_model: 0,
            cpu_ext_model: 0,
            cpu_model_synth: 0,
            cpu_family: 0,
            cpu_ext_family: 0,
            cpu_family_synth: 0,
            cpu_feats: "".to_string(),
        }
    }

    #[inline]
    fn cpuid(&self, leaf: u32) -> CpuidResult {
        unsafe { __cpuid(leaf) }
    }

    #[inline]
    fn cpuid_count(&self, leaf: u32, sub_leaf: u32) -> CpuidResult {
        unsafe { __cpuid_count(leaf, sub_leaf) }
    }

    #[inline]
    fn cpu_is_from(&self) -> u32 {
        // Return a register than has valid information
        // and can be used to determine a CPU vendor
        self.cpuid(0x0).ebx
    }

    fn get_cpu_vendor(&mut self) {
        let reg = self.cpuid(0x0);

        // First 4-bytes from ebx
        self.cpu_vendor[0] = (reg.ebx & 0xff) as u8 as char;
        self.cpu_vendor[1] = ((reg.ebx >> 8) & 0xff) as u8 as char;
        self.cpu_vendor[2] = ((reg.ebx >> 16) & 0xff) as u8 as char;
        self.cpu_vendor[3] = ((reg.ebx >> 24) & 0xff) as u8 as char;

        // Second 4-bytes from edx
        self.cpu_vendor[4] = (reg.edx & 0xff) as u8 as char;
        self.cpu_vendor[5] = ((reg.edx >> 8) & 0xff) as u8 as char;
        self.cpu_vendor[6] = ((reg.edx >> 16) & 0xff) as u8 as char;
        self.cpu_vendor[7] = ((reg.edx >> 24) & 0xff) as u8 as char;

        // Third 4-bytes from ecx
        self.cpu_vendor[8] = (reg.ecx & 0xff) as u8 as char;
        self.cpu_vendor[9] = ((reg.ecx >> 8) & 0xff) as u8 as char;
        self.cpu_vendor[10] = ((reg.ecx >> 16) & 0xff) as u8 as char;
        self.cpu_vendor[11] = ((reg.ecx >> 24) & 0xff) as u8 as char;
    }

    fn get_cpu_name(&mut self) {
        // For leaf 80000002H, extract 4-bytes from each iteration
        // and total 16-bytes
        let mut reg = self.cpuid(0x80000002);
        extract_bytes!(self.cpu_name, reg.eax);
        extract_bytes!(self.cpu_name, reg.ebx);
        extract_bytes!(self.cpu_name, reg.ecx);
        extract_bytes!(self.cpu_name, reg.edx);

        // For leaf 80000003H, and same as above
        reg = self.cpuid(0x80000003);
        extract_bytes!(self.cpu_name, reg.eax);
        extract_bytes!(self.cpu_name, reg.ebx);
        extract_bytes!(self.cpu_name, reg.ecx);
        extract_bytes!(self.cpu_name, reg.edx);

        // For leaf 80000004H, and same as above
        reg = self.cpuid(0x80000004);
        extract_bytes!(self.cpu_name, reg.eax);
        extract_bytes!(self.cpu_name, reg.ebx);
        extract_bytes!(self.cpu_name, reg.ecx);
        extract_bytes!(self.cpu_name, reg.edx);

        self.cpu_name = self.cpu_name.trim_start().to_string();
    }

    fn get_cpu_identity(&mut self) {
        let reg = self.cpuid(0x1);

        self.cpu_model = (reg.eax >> 4) & 0xf;
        self.cpu_ext_model = (reg.eax >> 16) & 0xf;
        self.cpu_family = (reg.eax >> 8) & 0xf;
        self.cpu_ext_family = (reg.eax >> 20) & 0xf;

        self.cpu_family_synth = if self.cpu_family != 0xf {
            self.cpu_family
        } else {
            self.cpu_ext_family + self.cpu_family
        };

        // According to the Intel Documentation, if CPU family ID is either
        // 0x6 or 0xf, the CPU family ID should be (extended model << 4) + model.
        // However, I *don't* think you always would like to have that so
        // if the conditions are met, cpu_model_synth will hold that value
        // otherwise it will always going to be 0.
        match self.cpu_family {
            0x6 | 0xf => {
                self.cpu_model_synth = (self.cpu_ext_model << 4) + self.cpu_model;
            }

            // If CPU family isn't 0x6 or 0xf
            _ => {
                self.cpu_model_synth = self.cpu_model;
            }
        }
    }

    fn get_first_general_feats(&mut self) {
        let reg = self.cpuid(0x1);

        // Check ecx register for feature flag
        add_if_supports!(self.cpu_feats, reg.ecx, 0, "sse3");
        add_if_supports!(self.cpu_feats, reg.ecx, 1, "pclmulqdq");
        add_if_supports!(self.cpu_feats, reg.ecx, 2, "dtes64");
        add_if_supports!(self.cpu_feats, reg.ecx, 3, "monitor");
        add_if_supports!(self.cpu_feats, reg.ecx, 4, "ds_cpl");
        add_if_supports!(self.cpu_feats, reg.ecx, 5, "vmx");
        add_if_supports!(self.cpu_feats, reg.ecx, 6, "smx");
        add_if_supports!(self.cpu_feats, reg.ecx, 7, "eist");
        add_if_supports!(self.cpu_feats, reg.ecx, 8, "tm2");
        add_if_supports!(self.cpu_feats, reg.ecx, 9, "ssse3");
        add_if_supports!(self.cpu_feats, reg.ecx, 10, "cnxt_id");
        add_if_supports!(self.cpu_feats, reg.ecx, 11, "sdbg");
        add_if_supports!(self.cpu_feats, reg.ecx, 12, "fma");
        add_if_supports!(self.cpu_feats, reg.ecx, 13, "cx16b");
        add_if_supports!(self.cpu_feats, reg.ecx, 14, "xtpr");
        add_if_supports!(self.cpu_feats, reg.ecx, 15, "pdcm");

        // Bit 16 - Reserved
        add_if_supports!(self.cpu_feats, reg.ecx, 17, "pcid");
        add_if_supports!(self.cpu_feats, reg.ecx, 18, "dca");
        add_if_supports!(self.cpu_feats, reg.ecx, 19, "sse4_1");
        add_if_supports!(self.cpu_feats, reg.ecx, 20, "sse4_2");
        add_if_supports!(self.cpu_feats, reg.ecx, 21, "x2apic");
        add_if_supports!(self.cpu_feats, reg.ecx, 22, "movbe");
        add_if_supports!(self.cpu_feats, reg.ecx, 23, "popcnt");
        add_if_supports!(self.cpu_feats, reg.ecx, 24, "tsc_deadline");
        add_if_supports!(self.cpu_feats, reg.ecx, 25, "aesni");
        add_if_supports!(self.cpu_feats, reg.ecx, 26, "xsave");
        add_if_supports!(self.cpu_feats, reg.ecx, 27, "osxsave");
        add_if_supports!(self.cpu_feats, reg.ecx, 28, "avx");
        add_if_supports!(self.cpu_feats, reg.ecx, 29, "f16c");
        add_if_supports!(self.cpu_feats, reg.ecx, 30, "rdrand");
        add_if_supports!(self.cpu_feats, reg.ecx, 31, "hv");

        // Same as above, but for the edx register
        add_if_supports!(self.cpu_feats, reg.edx, 0, "fpu");
        add_if_supports!(self.cpu_feats, reg.edx, 1, "vme");
        add_if_supports!(self.cpu_feats, reg.edx, 2, "de");
        add_if_supports!(self.cpu_feats, reg.edx, 3, "pse");
        add_if_supports!(self.cpu_feats, reg.edx, 4, "tsc");
        add_if_supports!(self.cpu_feats, reg.edx, 5, "msr");
        add_if_supports!(self.cpu_feats, reg.edx, 6, "pae");
        add_if_supports!(self.cpu_feats, reg.edx, 7, "mce");
        add_if_supports!(self.cpu_feats, reg.edx, 8, "cx8b");
        add_if_supports!(self.cpu_feats, reg.edx, 9, "apic");

        // Bit 10 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 11, "sep");
        add_if_supports!(self.cpu_feats, reg.edx, 12, "mtrr");
        add_if_supports!(self.cpu_feats, reg.edx, 13, "pge");
        add_if_supports!(self.cpu_feats, reg.edx, 14, "mca");
        add_if_supports!(self.cpu_feats, reg.edx, 15, "cmov");
        add_if_supports!(self.cpu_feats, reg.edx, 16, "pat");
        add_if_supports!(self.cpu_feats, reg.edx, 17, "pse_36");
        add_if_supports!(self.cpu_feats, reg.edx, 18, "psn");
        add_if_supports!(self.cpu_feats, reg.edx, 19, "clfsh");

        // Bit 20 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 21, "ds");
        add_if_supports!(self.cpu_feats, reg.edx, 22, "acpi");
        add_if_supports!(self.cpu_feats, reg.edx, 23, "mmx");
        add_if_supports!(self.cpu_feats, reg.edx, 24, "fxsr");
        add_if_supports!(self.cpu_feats, reg.edx, 25, "sse");
        add_if_supports!(self.cpu_feats, reg.edx, 26, "sse2");
        add_if_supports!(self.cpu_feats, reg.edx, 27, "ss");
        add_if_supports!(self.cpu_feats, reg.edx, 28, "htt");
        add_if_supports!(self.cpu_feats, reg.edx, 29, "tm");

        // Bit 30 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 31, "pbe");
    }

    fn get_second_general_feats(&mut self) {
        let reg = self.cpuid(0x7);

        // Values from the ebx register
        add_if_supports!(self.cpu_feats, reg.ebx, 0, "fsgsbase");
        add_if_supports!(self.cpu_feats, reg.ebx, 1, "tsc_adjust");
        add_if_supports!(self.cpu_feats, reg.ebx, 2, "sgx");
        add_if_supports!(self.cpu_feats, reg.ebx, 3, "bm1");
        add_if_supports!(self.cpu_feats, reg.ebx, 4, "hle");
        add_if_supports!(self.cpu_feats, reg.ebx, 5, "avx2");
        add_if_supports!(self.cpu_feats, reg.ebx, 6, "fdp_excptn_only");
        add_if_supports!(self.cpu_feats, reg.ebx, 7, "smep");
        add_if_supports!(self.cpu_feats, reg.ebx, 8, "bmi2");
        add_if_supports!(self.cpu_feats, reg.ebx, 9, "enh_rep_movsb");
        add_if_supports!(self.cpu_feats, reg.ebx, 10, "invpcid");
        add_if_supports!(self.cpu_feats, reg.ebx, 11, "rtm");
        add_if_supports!(self.cpu_feats, reg.ebx, 12, "rdt_m");
        add_if_supports!(self.cpu_feats, reg.ebx, 13, "dep_fpu_csds");

        // MPX is only available for Intel CPUs
        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ebx, 14, "mpx");
        }
        add_if_supports!(self.cpu_feats, reg.ebx, 15, "rdt_a");
        add_if_supports!(self.cpu_feats, reg.ebx, 16, "avx512f");
        add_if_supports!(self.cpu_feats, reg.ebx, 17, "avx512dq");
        add_if_supports!(self.cpu_feats, reg.ebx, 18, "rdseed");
        add_if_supports!(self.cpu_feats, reg.ebx, 19, "adx");
        add_if_supports!(self.cpu_feats, reg.ebx, 20, "smap");
        add_if_supports!(self.cpu_feats, reg.ebx, 21, "avx512_ifma");

        // Bit 22 - Reserved
        add_if_supports!(self.cpu_feats, reg.ebx, 23, "clflushopt");
        add_if_supports!(self.cpu_feats, reg.ebx, 24, "clwb");
        add_if_supports!(self.cpu_feats, reg.ebx, 25, "intel_ptrace");

        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ebx, 26, "avx512pf");
            add_if_supports!(self.cpu_feats, reg.ebx, 27, "avx512er");
        }
        add_if_supports!(self.cpu_feats, reg.ebx, 28, "avx512cd");
        add_if_supports!(self.cpu_feats, reg.ebx, 29, "sha");
        add_if_supports!(self.cpu_feats, reg.ebx, 30, "avx512bw");
        add_if_supports!(self.cpu_feats, reg.ebx, 31, "avx512vl");

        // Values from the ecx register
        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ecx, 0, "prefetchwt1");
        }
        add_if_supports!(self.cpu_feats, reg.ecx, 1, "avx512_vbmi");
        add_if_supports!(self.cpu_feats, reg.ecx, 2, "umip");
        add_if_supports!(self.cpu_feats, reg.ecx, 3, "pku");
        add_if_supports!(self.cpu_feats, reg.ecx, 4, "ospke");
        add_if_supports!(self.cpu_feats, reg.ecx, 5, "waitpkg");
        add_if_supports!(self.cpu_feats, reg.ecx, 6, "avx512_vbmi2");
        add_if_supports!(self.cpu_feats, reg.ecx, 7, "cert_ss");
        add_if_supports!(self.cpu_feats, reg.ecx, 8, "gfni");
        add_if_supports!(self.cpu_feats, reg.ecx, 9, "vaes");
        add_if_supports!(self.cpu_feats, reg.ecx, 10, "vpclmulqdq");
        add_if_supports!(self.cpu_feats, reg.ecx, 11, "avx512_vnni");
        add_if_supports!(self.cpu_feats, reg.ecx, 12, "avx512_bitalg");
        add_if_supports!(self.cpu_feats, reg.ecx, 13, "tme_en");
        add_if_supports!(self.cpu_feats, reg.ecx, 14, "avx512_vpopcntdq");

        // Bit 15 - Reserved
        add_if_supports!(self.cpu_feats, reg.ecx, 16, "la57");
        add_if_supports!(self.cpu_feats, reg.ecx, 22, "rdpid");
        add_if_supports!(self.cpu_feats, reg.ecx, 23, "kl");
        add_if_supports!(self.cpu_feats, reg.ecx, 25, "cldemote");

        // Bit 26 - Reserved
        add_if_supports!(self.cpu_feats, reg.ecx, 27, "movdiri");
        add_if_supports!(self.cpu_feats, reg.ecx, 28, "movdiri64b");
        add_if_supports!(self.cpu_feats, reg.ecx, 29, "enqcmd");
        add_if_supports!(self.cpu_feats, reg.ecx, 30, "sgx_lc");
        add_if_supports!(self.cpu_feats, reg.ecx, 31, "pks");

        // Values form the edx register
        // Bit 0 - Reserved
        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.edx, 1, "sgx_keys");
            add_if_supports!(self.cpu_feats, reg.edx, 2, "avx512_4vnniw");
            add_if_supports!(self.cpu_feats, reg.edx, 3, "avx512_4fmaps");
        }

        add_if_supports!(self.cpu_feats, reg.edx, 4, "fast_srmov");
        add_if_supports!(self.cpu_feats, reg.edx, 5, "uintr");

        // Bit 6-7 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 8, "avx512_vp2intersect");
        add_if_supports!(self.cpu_feats, reg.edx, 9, "srbds_ctrl");
        add_if_supports!(self.cpu_feats, reg.edx, 10, "md_clear");
        add_if_supports!(self.cpu_feats, reg.edx, 11, "rtm_always_abort");

        // Bit 12 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 13, "rtm_force_abort");
        add_if_supports!(self.cpu_feats, reg.edx, 14, "serialize");
        add_if_supports!(self.cpu_feats, reg.edx, 15, "hybrid");

        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.edx, 16, "tsxldtrk");
        }

        // Bit 17 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 18, "pconfig");
        add_if_supports!(self.cpu_feats, reg.edx, 19, "arch_lbrs");
        add_if_supports!(self.cpu_feats, reg.edx, 20, "cert_ibt");

        // Bit 21 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 22, "amx_bf16");
        add_if_supports!(self.cpu_feats, reg.edx, 23, "avx512_fp16");
        add_if_supports!(self.cpu_feats, reg.edx, 24, "amx_tile");
        add_if_supports!(self.cpu_feats, reg.edx, 25, "amx_int8");

        // TODO: Structured Extended Feature Enumeration Sub-leaf (Initial EAX Value = 07H, ECX = 1)
        // at page 819
    }

    fn get_first_extended_feats(&mut self) {
        let reg = self.cpuid_count(0x7, 2);

        // Bits 0-3 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 4, "avx_vnni");
        add_if_supports!(self.cpu_feats, reg.eax, 5, "avx512_bf16");

        // Bits 6-9 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 10, "fast_rmovsb");
        add_if_supports!(self.cpu_feats, reg.eax, 11, "fast_rstosb");
        add_if_supports!(self.cpu_feats, reg.eax, 12, "fast_rcmpsb");

        // Bits 13-22 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 22, "hreset");
    }

    fn get_second_extended_feats(&mut self) {
        let reg = self.cpuid_count(0xd, 1);

        add_if_supports!(self.cpu_feats, reg.eax, 0, "xsaveopt");
        add_if_supports!(self.cpu_feats, reg.eax, 1, "xsavec compact_xrstor");
        add_if_supports!(self.cpu_feats, reg.eax, 2, "xgetbv");
        add_if_supports!(self.cpu_feats, reg.eax, 3, "xsaves");
        add_if_supports!(self.cpu_feats, reg.eax, 4, "xfd");
    }

    fn get_third_extended_feats(&mut self) {
        let reg = self.cpuid(0x80000001);

        // This section is for the ecx register
        add_if_supports!(self.cpu_feats, reg.ecx, 0, "lahf");

        // Bits 1-4 - Reserved
        add_if_supports!(self.cpu_feats, reg.ecx, 5, "lzcnt");

        // Bits 6-7 - Reserved
        add_if_supports!(self.cpu_feats, reg.ecx, 8, "prefetchw");

        // This section is for the edx register
        add_if_supports!(self.cpu_feats, reg.edx, 11, "syscall");

        // Bits 12-19 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 20, "nx");

        // Bits 21-25 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 26, "1gb_pages");
        add_if_supports!(self.cpu_feats, reg.edx, 27, "rdtscp");

        // We don't need to test this if we're already compiling
        // on a x86_64 architecture
        #[cfg(target_arch = "x86_64")]
        // Bit 28 - Reserved
        add_if_supports!(self.cpu_feats, reg.edx, 29, "x86_64");
    }

    fn get_first_thpow_feats(&mut self) {
        let reg = self.cpuid(0x6);

        add_if_supports!(self.cpu_feats, reg.eax, 0, "dts");
        add_if_supports!(self.cpu_feats, reg.eax, 1, "intel_tbt");
        add_if_supports!(self.cpu_feats, reg.eax, 2, "arat");

        // Bit 3 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 4, "pln");
        add_if_supports!(self.cpu_feats, reg.eax, 5, "ecmd");
        add_if_supports!(self.cpu_feats, reg.eax, 6, "ptm");
        add_if_supports!(self.cpu_feats, reg.eax, 7, "hwp");
        add_if_supports!(self.cpu_feats, reg.eax, 8, "hwp_noti");
        add_if_supports!(self.cpu_feats, reg.eax, 9, "hwp_acti");
        add_if_supports!(self.cpu_feats, reg.eax, 10, "hwp_ener");
        add_if_supports!(self.cpu_feats, reg.eax, 11, "hwp_pack");

        // Bit 12 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 13, "hdc");
        add_if_supports!(self.cpu_feats, reg.eax, 14, "intel_tbt3");
        add_if_supports!(self.cpu_feats, reg.eax, 15, "hperfc");
        add_if_supports!(self.cpu_feats, reg.eax, 16, "hwp_peci");
        add_if_supports!(self.cpu_feats, reg.eax, 17, "flex_hwp");
        add_if_supports!(self.cpu_feats, reg.eax, 18, "fast_am");

        // Bit 21-22 - Reserved
        add_if_supports!(self.cpu_feats, reg.eax, 23, "intel_td");
    }

    fn get_fourth_extended_feats(&mut self) {
        let reg = self.cpuid(0x7);

        add_if_supports!(self.cpu_feats, reg.ebx, 0, "fsgsbase");
        add_if_supports!(self.cpu_feats, reg.ebx, 1, "tsc_adjust_msr");

        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ebx, 2, "sgx");
        }
        add_if_supports!(self.cpu_feats, reg.ebx, 3, "bmi1");
        add_if_supports!(self.cpu_feats, reg.ebx, 4, "hle");
        add_if_supports!(self.cpu_feats, reg.ebx, 5, "avx2");
        add_if_supports!(self.cpu_feats, reg.ebx, 6, "fdp_excptn_only");
        add_if_supports!(self.cpu_feats, reg.ebx, 7, "smep");
        add_if_supports!(self.cpu_feats, reg.ebx, 8, "bmi2");
        add_if_supports!(self.cpu_feats, reg.ebx, 9, "emovsb");
        add_if_supports!(self.cpu_feats, reg.ebx, 10, "invpcid");
        add_if_supports!(self.cpu_feats, reg.ebx, 11, "rtm");
        add_if_supports!(self.cpu_feats, reg.ebx, 12, "rdt_m");
        add_if_supports!(self.cpu_feats, reg.ebx, 13, "dep_fpu_csds");
        add_if_supports!(self.cpu_feats, reg.ebx, 14, "mpx");
        add_if_supports!(self.cpu_feats, reg.ebx, 15, "rdt_a");
        add_if_supports!(self.cpu_feats, reg.ebx, 16, "avx512f");
        add_if_supports!(self.cpu_feats, reg.ebx, 17, "avx512dq");
        add_if_supports!(self.cpu_feats, reg.ebx, 18, "rdseed");
        add_if_supports!(self.cpu_feats, reg.ebx, 19, "adx");
        add_if_supports!(self.cpu_feats, reg.ebx, 20, "smap");
        add_if_supports!(self.cpu_feats, reg.ebx, 21, "avx512_ifma");

        // Bit 22 - Reserved
        add_if_supports!(self.cpu_feats, reg.ebx, 23, "clflushopt");
        add_if_supports!(self.cpu_feats, reg.ebx, 24, "clwb");
        add_if_supports!(self.cpu_feats, reg.ebx, 25, "intel_ptrace");

        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ebx, 26, "avx512pf");
            add_if_supports!(self.cpu_feats, reg.ebx, 27, "avx512er");
        }
        add_if_supports!(self.cpu_feats, reg.ebx, 28, "avx512cd");
        add_if_supports!(self.cpu_feats, reg.ebx, 29, "sha");
        add_if_supports!(self.cpu_feats, reg.ebx, 30, "avx512bw");
        add_if_supports!(self.cpu_feats, reg.ebx, 31, "avx512vl");

        if self.cpu_is_from() == CPU_VENDOR_INTEL {
            add_if_supports!(self.cpu_feats, reg.ecx, 0, "prefetchwt1");
        }
    }
}

fn default_no_arg_display(lsce: &mut Lsce) {
    lsce.get_cpu_name();
    lsce.get_cpu_vendor();
    lsce.get_first_general_feats();
    lsce.get_second_general_feats();
    lsce.get_first_extended_feats();
    lsce.get_second_extended_feats();
    lsce.get_third_extended_feats();
    lsce.get_first_thpow_feats();
    lsce.get_fourth_extended_feats();
    lsce.get_cpu_identity();

    println!(
        "{}Vendor{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_vendor.iter().map(|&m| m).collect::<String>()
    );
    println!("{}Name{}: {}", COLOR_WHITE_START, COLOR_END, lsce.cpu_name);
    println!(
        "{}Model{}: {}\n{}Extended Model{}: {}\n{}Model Synth{}: {}\n{}Family{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_model,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_ext_model,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_model_synth,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_family
    );
    println!(
        "{}Extended Family{}: {}\n{}Family Synth{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_ext_family,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_family_synth
    );
    println!(
        "{}Features{}: {}",
        COLOR_WHITE_START, COLOR_END, lsce.cpu_feats
    );
}

fn with_arg_identity(lsce: &mut Lsce) {
    lsce.get_cpu_identity();

    print!(
        "{}Model ID{}: {}\n{}Extended Model ID{}: {}\n",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_model,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_ext_model
    );
    println!(
        "{}Model Synth ID{}: {}\n{}Family ID{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_model_synth,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_family
    );
    println!(
        "{}Extended Family ID{}: {}\n{}Family Synth{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_ext_family,
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_family_synth
    );
}

fn with_arg_feats(lsce: &mut Lsce) {
    lsce.get_first_general_feats();
    lsce.get_second_general_feats();

    println!(
        "{}CPU Features{}: {}",
        COLOR_WHITE_START, COLOR_END, lsce.cpu_feats
    );
}

fn with_arg_vendor(lsce: &mut Lsce) {
    lsce.get_cpu_vendor();

    println!(
        "{}Package Vendor{}: {}",
        COLOR_WHITE_START,
        COLOR_END,
        lsce.cpu_vendor.iter().map(|&m| m).collect::<String>()
    );
}

fn with_arg_name(lsce: &mut Lsce) {
    lsce.get_cpu_name();

    println!(
        "{}Package Name{}: {}",
        COLOR_WHITE_START, COLOR_END, lsce.cpu_name
    );
}

fn main() {
    let args: Args = Args::parse();
    let mut lsce: Lsce = Lsce::new();

    // If argument is --name (or -n)
    if args.name {
        with_arg_name(&mut lsce);
    }
    // If argument is --vendor (or -v)
    else if args.vendor {
        with_arg_vendor(&mut lsce);
    }
    // If argument is --feats (or -f)
    else if args.feats {
        with_arg_feats(&mut lsce);
    }
    // If argument is --identity (or -i)
    else if args.identity {
        with_arg_identity(&mut lsce);
    }
    // If no argument is provided
    else {
        default_no_arg_display(&mut lsce);
    }
}
