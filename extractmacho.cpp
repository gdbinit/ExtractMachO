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
 *  v0.1
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
 * extractmacho.cpp
 *
 */

#include "extractmacho.h"

#define DEBUG 0

int counter = 0;

int IDAP_init(void)
{
    if (inf.filetype != f_MACHO)
    {
		// if it's not mach-o binary then plugin is unavailable
		msg("[macho plugin] Executable format must be Mach-O!");
		return PLUGIN_SKIP;
    }   
    return PLUGIN_KEEP;
}

void IDAP_term(void) 
{
    return;
}

void IDAP_run(int arg)
{
 
    extern plugin_t PLUGIN;
//#ifdef __MAC__
	PLUGIN.flags |= PLUGIN_UNL;
//#endif

    // retrieve current cursor address and it's value
    // so we can verify if it can be a mach-o binary
    ea_t ea = get_screen_ea();
    uint32 magicValue = get_long(ea);
    
    struct mach_header *mach_header = NULL;
    struct mach_header_64 *mach_header64 = NULL;
    
    uint8 arch = 0;
    
    if (magicValue == MH_MAGIC)
    {
        mach_header = (struct mach_header *)qalloc(sizeof(struct mach_header));
        if(!get_many_bytes(ea, mach_header, sizeof(struct mach_header)))
        {
            msg("Read bytes failed!\n");
            return;
        }
        msg("%x %x\n", mach_header->magic, mach_header->sizeofcmds);
    }
    else if (magicValue == MH_MAGIC_64)
    {
        mach_header64 = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        get_many_bytes(ea, mach_header, sizeof(struct mach_header_64));
        arch = 1;
    }
    else    
    {
        msg("[ERROR] No potentially valid mach-o binary at current location!");
        return;
    }
    
    char *outputFilename = askfile_c(1, NULL, "Select output file...");
    if ( outputFilename == NULL || outputFilename[0] == 0 )
        return;
    
    FILE *outputFile = qfopen(outputFilename, "wb+");
    
    qfwrite(outputFile, mach_header, sizeof(struct mach_header));
    

    // read load commands
    uint8_t *loadcmdsBuffer = NULL;
    loadcmdsBuffer = (uint8_t*)qalloc(mach_header->sizeofcmds);
    get_many_bytes(ea+sizeof(struct mach_header), loadcmdsBuffer, mach_header->sizeofcmds);
    
    qfwrite(outputFile, loadcmdsBuffer, mach_header->sizeofcmds);
    
    struct load_command loadCmd;
    ea_t cmdsBaseAddress = ea + sizeof(struct mach_header);
    ea_t codeOffset = 0;
    // read segments so we can write the code and data
    // only the segment commands have useful information
    for (uint32_t i = 0; i < mach_header->ncmds; i++)
    {
//        loadCmd = (struct load_command*)cmdsBaseAddress;
        get_many_bytes(cmdsBaseAddress, &loadCmd, sizeof(struct load_command));
        struct segment_command segmentCommand;
        if (loadCmd.cmd == LC_SEGMENT)
        {
            
            get_many_bytes(cmdsBaseAddress, &segmentCommand, sizeof(struct segment_command));
            msg("fileoffset %x filesize %x\n", segmentCommand.fileoff, segmentCommand.filesize);
            if (strncmp(segmentCommand.segname, "__TEXT", 16) == 0)
            {
                ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command);
                struct section sectionCommand; 
                // iterate thru all sections to find the first code offset
                // FIXME: we need to find the lowest one since the section info can be reordered
                for (uint32_t x = 0; x < segmentCommand.nsects; x++)
                {
                    get_many_bytes(sectionAddress, &sectionCommand, sizeof(struct section));
                    if (strncmp(sectionCommand.sectname, "__text", 16) == 0)
                    {
                        codeOffset = sectionCommand.offset;
                        break;
                    }
                    sectionAddress += sizeof(struct section);
                }
            
            }
            // write
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_many_bytes(ea + codeOffset, buf, segmentCommand.filesize);
            if (strncmp(segmentCommand.segname, "__TEXT", 16) == 0)
            {
                qfseek(outputFile, codeOffset, SEEK_SET);
            }
            qfwrite(outputFile, buf, segmentCommand.filesize);
            qfree(buf);
        }
        cmdsBaseAddress += loadCmd.cmdsize;
    }
    
    
    qfclose(outputFile);

    qfree(mach_header);
    qfree(loadcmdsBuffer);
//    process_loadcmds(loadcommands, mh->ncmds, textSeg->startEA+mach_header_size, si, mh->cputype);
    
	return;
}

char IDAP_comment[]	= "Plugin to extract Mach-O binaries from disassembly";
char IDAP_help[]	= "Extract Mach-O";
char IDAP_name[]	= "Extract Mach-O";
char IDAP_hotkey[]	= "Alt-X";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	IDAP_init,
	IDAP_term,
	IDAP_run,
	IDAP_comment,
	IDAP_help,
	IDAP_name,
	IDAP_hotkey
};
