/*
 * ___________         __                        __   
 * \_   _____/__  ____/  |_____________    _____/  |_ 
 *   |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\
 *   |        \>    <  |  |  |  | \// __ \\  \___|  |  
 *  /_______  /__/\_ \ |__|  |__|  (____  /\___  >__|  
 *          \/      \/                  \/     \/      
 *    _____                .__              ________   
 *   /     \ _____    ____ |  |__           \_____  \  
 *  /  \ /  \\__  \ _/ ___\|  |  \   ______  /   |   \ 
 * /    Y    \/ __ \\  \___|   Y  \ /_____/ /    |    \
 * \____|__  (____  /\___  >___|  /         \_______  /
 *         \/     \/     \/     \/                  \/ 
 *
 * (c) 2012, fG! - reverser@put.as - http://reverse.put.as
 * 
 * An IDA plugin to extract Mach-O binaries inside code or data segments
 *
 * -> You are free to use this code as long as you keep the original copyright <-
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * mac_includes.h
 *
 */

#ifndef ExtractMachO_mac_includes_h
#define ExtractMachO_mac_includes_h

// OS X includes
#ifdef __MAC__

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/reloc.h>
#include <mach-o/nlist.h>

#else
#include "loader.h"

// these are the contents of fat.h that we need
#define FAT_MAGIC       0xcafebabe
#define FAT_CIGAM       0xbebafeca      /* NXSwapLong(FAT_MAGIC) */

struct fat_header {
    uint32_t        magic;          /* FAT_MAGIC */
    uint32_t        nfat_arch;      /* number of structs that follow */
};

struct fat_arch {
    int      cputype;        /* cpu specifier (int) */
    int   cpusubtype;     /* machine specifier (int) */
    uint32_t        offset;         /* file offset to this object file */
    uint32_t        size;           /* size of this object file */
    uint32_t        align;          /* alignment as a power of 2 */
};

// from reloc.h
struct relocation_info {
    int32_t      r_address;      /* offset in the section to what is being
                                  relocated */
    uint32_t     r_symbolnum:24, /* symbol index if r_extern == 1 or section
                                  ordinal if r_extern == 0 */
r_pcrel:1,      /* was relocated pc relative already */
r_length:2,     /* 0=byte, 1=word, 2=long, 3=quad */
r_extern:1,     /* does not include value of sym referenced */
r_type:4;       /* if not 0, machine specific relocation type */
};

// from nlist.h
struct nlist {
    union {
#ifndef __LP64__
        char *n_name;   /* for use when in-core */
#endif
        int32_t n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    int16_t n_desc;         /* see <mach-o/stab.h> */
    uint32_t n_value;       /* value of this symbol (or stab offset) */
};

struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};


#endif

#endif
