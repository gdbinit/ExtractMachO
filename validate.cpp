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
 * validate.cpp
 *
 */

#include "validate.h"

#define DEBUG 1

/*
 * try to validate if a given address contains a valid mach-o file
 */
uint8_t
validate_macho(void *buffer)
{
    msg("Executing validate macho\n");
    uint32_t magic = *(uint32_t*)buffer;
    // default is failure
    uint8_t retvalue = 1;
    if (magic == MH_MAGIC)
    {
        // validate cpu type
        struct mach_header header;
        memcpy(&header, buffer, sizeof(struct mach_header));
        if (header.cputype == CPU_TYPE_I386)
        {
            // validate cpu sub type
            if (header.cpusubtype == CPU_SUBTYPE_X86_ALL)
            {
                // validate file type
                if (header.filetype == MH_OBJECT ||
                    header.filetype == MH_EXECUTE ||
                    header.filetype == MH_PRELOAD ||
                    header.filetype == MH_DYLIB ||
                    header.filetype == MH_DYLINKER ||
                    header.filetype == MH_BUNDLE)
                {
                    retvalue = 0;
                }
            }
        }
    }
    else if (magic == MH_MAGIC_64)
    {
        // validate cpu type
        struct mach_header_64 header64;
        memcpy(&header64, buffer, sizeof(struct mach_header_64));
        if (header64.cputype == CPU_TYPE_X86_64)
        {
            // validate cpu sub type
            if (header64.cpusubtype == CPU_SUBTYPE_X86_64_ALL)
            {
                // validate file type
                if (header64.filetype == MH_OBJECT ||
                    header64.filetype == MH_EXECUTE ||
                    header64.filetype == MH_PRELOAD ||
                    header64.filetype == MH_DYLIB ||
                    header64.filetype == MH_DYLINKER ||
                    header64.filetype == MH_BUNDLE ||
                    header64.filetype == MH_KEXT_BUNDLE)
                {
                    retvalue = 0;
                }
            }
        }
    }
#if DEBUG
    if (retvalue)
        msg("[DEBUG] validate_macho failed, not a valid binary\n");
#endif
    return retvalue;
}

/*
 * try to validate if a given address contains a valid fat archive
 */
uint8_t 
validate_fat(struct fat_header fatHeader, ea_t position)
{
#if DEBUG
    msg("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    // default is failure
    uint8_t retvalue = 1;
    if (fatHeader.magic == FAT_CIGAM)
    {
        // fat headers are always big endian!
        uint32_t nfat_arch = ntohl(fatHeader.nfat_arch);
        if (nfat_arch > 0)
        {
            msg("[DEBUG] nr fat archs %d\n", ntohl(fatHeader.nfat_arch));
            // we need to read the fat arch headers to validate
            ea_t address = position + sizeof(struct fat_header);
            for (uint32_t i = 0; i < nfat_arch; i++)
            {
                struct fat_arch fatArch;
                get_many_bytes(address, &fatArch, sizeof(struct fat_arch));
                if (ntohl(fatArch.cputype) == CPU_TYPE_X86 || ntohl(fatArch.cputype) == CPU_TYPE_X86_64)
                {
                    if (ntohl(fatArch.cpusubtype) == CPU_SUBTYPE_X86_ALL || ntohl(fatArch.cpusubtype) == CPU_SUBTYPE_X86_64_ALL)
                    {
                        retvalue = 0;
                    }
                }
                address += sizeof(struct fat_arch);
            }
        }
    }
#if DEBUG
    msg("[DEBUG] validate_fat ret %d\n", retvalue);
#endif
    return retvalue;
}
