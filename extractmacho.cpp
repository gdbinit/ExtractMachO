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

int IDAP_init(void)
{
//    if (inf.filetype != f_MACHO)
//    {
//		// if it's not mach-o binary then plugin is unavailable
//		msg("[macho plugin] Executable format must be Mach-O, not loading plugin!");
//		return PLUGIN_SKIP;
//    }   
    return PLUGIN_KEEP;
}

void IDAP_term(void) 
{
    return;
}

void IDAP_run(int arg)
{ 
    // this is useful for testing - plugin will be unloaded after execution
    // so we can copy a new version and call it again using IDC: RunPlugin("extractmacho", -1);
    // this gave (gives?) problems in Windows version
    extern plugin_t PLUGIN;
#ifdef __MAC__
	PLUGIN.flags |= PLUGIN_UNL;
#endif

    // retrieve current cursor address and it's value
    // so we can verify if it can be a mach-o binary
    ea_t cursorAddress = get_screen_ea();
#if DEBUG
    msg("[DEBUG] Cursor Address is %llx\n", cursorAddress);
#endif
    uint32 magicValue = get_long(cursorAddress);
    
    struct mach_header *mach_header = NULL;
    struct mach_header_64 *mach_header64 = NULL;
    
    uint8_t arch = 0;
    uint8_t fat = 0; 
    if (magicValue == MH_MAGIC)
    {
#if DEBUG
        msg("[DEBUG] Target is 32bits!\n");
#endif
        mach_header = (struct mach_header *)qalloc(sizeof(struct mach_header));
        // retrieve mach_header contents
        if(!get_many_bytes(cursorAddress, mach_header, sizeof(struct mach_header)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return;
        }
    }
    else if (magicValue == MH_MAGIC_64)
    {
#if DEBUG
        msg("[DEBUG] Target is 64bits!\n");
#endif
        mach_header64 = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        if(!get_many_bytes(cursorAddress, mach_header64, sizeof(struct mach_header_64)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return;
        }
        arch = 1;
    }
    // FIXME: implement FAT binary support
    else if (magicValue == FAT_CIGAM)
    {
        fat = 1;
    }
    else    
    {
        msg("[ERROR] No potentially valid mach-o binary at current location!\n");
        return;
    }

    // ask for output filename
    char *outputFilename = askfile_c(1, NULL, "Select output file...");
    if (outputFilename == NULL || outputFilename[0] == 0)
        return;
    
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        msg("[ERROR] Could not open %s file!\n", outputFilename);
        return;
    }
    
    /*
     * we need to write 3 distinct blocks of data:
     * 1) the mach_header
     * 2) the load commands
     * 3) the code and data from the LC_SEGMENT/LC_SEGMENT_64 commands
     */
    
    // write the mach_header to the file
    if (arch)
        qfwrite(outputFile, mach_header64, sizeof(struct mach_header_64));
    else
        qfwrite(outputFile, mach_header, sizeof(struct mach_header));

    // read the load commands
    uint32_t ncmds = arch ? mach_header64->ncmds : mach_header->ncmds;
    uint32_t sizeofcmds = arch ? mach_header64->sizeofcmds : mach_header->sizeofcmds;
    uint32_t headerSize = arch ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    
    uint8_t *loadcmdsBuffer = NULL;
    loadcmdsBuffer = (uint8_t*)qalloc(sizeofcmds);
    
    get_many_bytes(cursorAddress + headerSize, loadcmdsBuffer, sizeofcmds);
    // write all the load commands block to the output file
    // only LC_SEGMENT commands contain further data
    qfwrite(outputFile, loadcmdsBuffer, sizeofcmds);

    // and now process the load commands so we can retrieve code and data
    struct load_command loadCommand;
    ea_t cmdsBaseAddress = cursorAddress + headerSize;    
    ea_t codeOffset = 0;
    
    // read segments so we can write the code and data
    // only the segment commands have useful information
    for (uint32_t i = 0; i < ncmds; i++)
    {
        get_many_bytes(cmdsBaseAddress, &loadCommand, sizeof(struct load_command));
        struct segment_command segmentCommand;
        struct segment_command_64 segmentCommand64;
        // 32bits targets
        if (loadCommand.cmd == LC_SEGMENT)
        {
            get_many_bytes(cmdsBaseAddress, &segmentCommand, sizeof(struct segment_command));
            // the file offset info in LC_SEGMENT is zero at __TEXT so we need to get it from the sections
            // the size is ok to be used
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
            // for all other segments the fileoffset info in the LC_SEGMENT is valid so we can use it
            else
            {
                codeOffset = segmentCommand.fileoff;
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_many_bytes(cursorAddress + codeOffset, buf, segmentCommand.filesize);
            // always set the offset
            qfseek(outputFile, codeOffset, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand.filesize);
            qfree(buf);
        }
        // 64bits targets
        else if (loadCommand.cmd == LC_SEGMENT_64)
        {
            get_many_bytes(cmdsBaseAddress, &segmentCommand64, sizeof(struct segment_command_64));
            if(strncmp(segmentCommand64.segname, "__TEXT", 16) == 0)
            {
                ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command_64);
                struct section_64 sectionCommand64;
                for (uint32_t x = 0; x < segmentCommand64.nsects; x++)
                {
                    get_many_bytes(sectionAddress, &sectionCommand64, sizeof(struct section_64));
                    if (strncmp(sectionCommand64.sectname, "__text", 16) == 0)
                    {
                        codeOffset = sectionCommand64.offset;
                        break;
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
            else
            {
                codeOffset = segmentCommand64.fileoff;
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand64.filesize);
            get_many_bytes(cursorAddress + codeOffset, buf, segmentCommand64.filesize);
            qfseek(outputFile, codeOffset, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand64.filesize);
            qfree(buf);
        }
        cmdsBaseAddress += loadCommand.cmdsize;
    }
    
    // all done, close file and free remaining buffers!
    qfclose(outputFile);
    qfree(mach_header);
    qfree(mach_header64);
    qfree(loadcmdsBuffer);
    msg("Mach-O binary extracted successfully!\n");
    // it's over!
	return;
}

char IDAP_comment[]	= "Plugin to extract Mach-O binaries from disassembly";
char IDAP_help[]	= "Extract Mach-O";
char IDAP_name[]	= "Extract Mach-O";
char IDAP_hotkey[]	= "";

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
