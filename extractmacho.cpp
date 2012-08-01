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
#include "validate.h"
#include "uthash.h"

#define DEBUG 1

uint8_t extract_macho(ea_t address, char *outputFilename);
uint8_t extract_mhobject(ea_t address, char *outputFilename);
uint8_t extract_fat(ea_t address, char *outputFilename);
uint8_t extract_binary(ea_t address, char *outputFilename);
void add_to_fat_list(ea_t address);

struct found_fat
{
    ea_t id;
    UT_hash_handle hh;
};

struct found_fat *found_fat = NULL;

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
    msg("[DEBUG] Cursor Address is %x\n", cursorAddress);
#endif
    uint32 magicValue = get_long(cursorAddress);
#if DEBUG
    msg("[DEBUG] Magic value: %x\n", magicValue);
#endif
    
    uint8_t globalSearch = 1;
    char *outputFilename = NULL;
    // test if current cursor position has a valid mach-o
    // if yes, ask user if he wants to extract only this one or search for all
#if 1
    if (magicValue == MH_MAGIC || magicValue == MH_MAGIC_64 || magicValue == FAT_CIGAM)
    {
        int answer = askyn_c(0, "Current location contains a potential Mach-O binary! Attempt to extract only this one?");
        // user wants to extract this binary
        if (answer == 1)
        {
            // ask for output location & name
            // ask for output filename
            outputFilename = askfile_c(1, NULL, "Select output file...");
            if (outputFilename == NULL || outputFilename[0] == 0)
                return;
            extract_binary(cursorAddress, outputFilename);
            return;
        }
        globalSearch = answer ? 0 : 1;
    }

    if (globalSearch)
    {
        char form[]="Choose output directory\n<~O~utput directory:F:1:64::>";
        char outputDir[MAXSTR] = "";
        if (AskUsingForm_c(form, outputDir) == 0)
            return;
        
        int findAddress = 0;
        char magic32Bits[] = "CE FA ED FE";
        char magic64Bits[] = "CF FA ED FE";
        char magicFat[]    = "CA FE BA BE";
        
        // we have a small problem here
        // fat archives contain valid mach-o binaries so they will be found if we search for fat and non-fat binaries
        // solution is to first lookup the fat archives and add the binaries location to a list
        // then match against that list when searching for non-fat binaries and skip extraction if it's on that list

        // lookup fat archives
        while (findAddress != BADADDR)
        {
            findAddress = find_binary(findAddress, inf.maxEA, magicFat, 16, SEARCH_DOWN|SEARCH_NEXT);
            if (findAddress != BADADDR)
            {
                add_to_fat_list(findAddress);
                char output[MAXSTR];
                qsnprintf(output, sizeof(output)-1, "%s/extracted_%x_%d_fat", outputDir, findAddress, findAddress);
                extract_binary(findAddress, output);
            }
        }

        findAddress = 0;
        // look up 32 bits binaries
        while (findAddress != BADADDR)
        {
            findAddress = find_binary(findAddress, inf.maxEA, magic32Bits, 16, SEARCH_DOWN|SEARCH_NEXT);
            struct found_fat *f = NULL;
            HASH_FIND(hh, found_fat, &findAddress, sizeof(ea_t), f);
            if (findAddress != BADADDR && f == NULL)
            {
                char output[MAXSTR];
                qsnprintf(output, sizeof(output)-1, "%s/extracted_%x_%d", outputDir, findAddress, findAddress);
                extract_binary(findAddress, output);
            }
        }
        findAddress = 0;
        // look up 64 bits binaries
        while (findAddress != BADADDR)
        {
            findAddress = find_binary(findAddress, inf.maxEA, magic64Bits, 16, SEARCH_DOWN|SEARCH_NEXT);
            struct found_fat *f = NULL;
            HASH_FIND(hh, found_fat, &findAddress, sizeof(ea_t), f);
            if (findAddress != BADADDR && f == NULL)
            {
                char output[MAXSTR];
                qsnprintf(output, sizeof(output)-1, "%s/extracted_%x_%d", outputDir, findAddress, findAddress);
                extract_binary(findAddress, output);
            }
        }
    }
#endif

    msg("Successful extraction!\n");
    // it's over!
	return;
}

/*
 * build a list of binaries location inside a fat archive so we don't extract binaries inside fat archives
 * while searching for non-fat binaries
 */
void
add_to_fat_list(ea_t address)
{
    // process the fat structures
    struct fat_header fatHeader;
    get_many_bytes(address, &fatHeader, sizeof(struct fat_header));
    if (fatHeader.magic == FAT_CIGAM)
    {
        // fat headers are always big endian!
        uint32_t nfat_arch = ntohl(fatHeader.nfat_arch);
        if (nfat_arch > 0)
        {
            // we need to read the fat arch headers to validate
            ea_t archAddress = address + sizeof(struct fat_header);
            for (uint32_t i = 0; i < nfat_arch; i++)
            {
                struct fat_arch fatArch;
                get_many_bytes(archAddress, &fatArch, sizeof(struct fat_arch));
                // binary is located at start of fat magic plus offset found in the fat_arch structure
                ea_t binLocation = address + ntohl(fatArch.offset);
                
                struct found_fat *new_found_fat = (struct found_fat*)qalloc(sizeof(struct found_fat));
                new_found_fat->id = binLocation;
                HASH_ADD_INT(found_fat, id, new_found_fat);
                archAddress += sizeof(struct fat_arch);
            }
        }
    }

}

/*
 * entry function to validate and extract fat and non-fat binaries
 */
uint8_t 
extract_binary(ea_t address, char *outputFilename)
{
    uint8_t retValue = 0;
    uint32 magicValue = get_long(address);
    if (magicValue == MH_MAGIC || magicValue == MH_MAGIC_64)
    {
        if(validate_macho(address))
        {
            msg("[ERROR] Not a valid mach-o binary at %x\n", address);
            return 1;
        }
        // we just need to read mach_header.filetype so no problem in using the 32bit struct
        struct mach_header header;
        get_many_bytes(address, &header, sizeof(struct mach_header));
        if (header.filetype == MH_OBJECT)
            retValue = extract_mhobject(address, outputFilename);
        else
            retValue = extract_macho(address, outputFilename);
    }
    else if (magicValue == FAT_CIGAM)
    {
       retValue = extract_fat(address, outputFilename);
    }
    else    
    {
        msg("[ERROR] No potentially valid mach-o binary at current location!\n");
        retValue = 1;
    }
    return retValue;
}

uint8_t
extract_mhobject(ea_t address, char *outputFilename)
{
    uint32 magicValue = get_long(address);
    
    struct mach_header *mach_header = NULL;
    struct mach_header_64 *mach_header64 = NULL;
        
    uint8_t arch = 0;
    if (magicValue == MH_MAGIC)
    {
#if DEBUG
        msg("[DEBUG] Target is 32bits!\n");
#endif
        mach_header = (struct mach_header *)qalloc(sizeof(struct mach_header));
        // retrieve mach_header contents
        if(!get_many_bytes(address, mach_header, sizeof(struct mach_header)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
    }
    else if (magicValue == MH_MAGIC_64)
    {
#if DEBUG
        msg("[DEBUG] Target is 64bits!\n");
#endif
        mach_header64 = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        if(!get_many_bytes(address, mach_header64, sizeof(struct mach_header_64)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
        arch = 1;
    }
    
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        msg("[ERROR] Could not open %s file!\n", outputFilename);
        return 1;
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
    
    get_many_bytes(address + headerSize, loadcmdsBuffer, sizeofcmds);
    // write all the load commands block to the output file
    // only LC_SEGMENT commands contain further data
    qfwrite(outputFile, loadcmdsBuffer, sizeofcmds);
    
    // and now process the load commands so we can retrieve code and data
    struct load_command loadCommand;
    ea_t cmdsBaseAddress = address + headerSize;    
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
            if (strncmp(segmentCommand.segname, "", 16) == 0)
            {
                ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command);
                struct section sectionCommand; 
                // iterate thru all sections to find the first code offset
                // FIXME: we need to find the lowest one since the section info can be reordered
                for (uint32_t x = 0; x < segmentCommand.nsects; x++)
                {
                    get_many_bytes(sectionAddress, &sectionCommand, sizeof(struct section));
                    if (sectionCommand.nreloc > 0)
                    {
                        uint32_t size = sectionCommand.nreloc*sizeof(struct relocation_info);
                        uint8_t *buf = (uint8_t*)qalloc(size);
                        get_many_bytes(address + sectionCommand.reloff, buf, size);
                        qfseek(outputFile, sectionCommand.reloff, SEEK_SET);
                        qfwrite(outputFile, buf, size);
                        qfree(buf);
                    }
                    sectionAddress += sizeof(struct section);
                }
                codeOffset = segmentCommand.fileoff;
            }
            // for all other segments the fileoffset info in the LC_SEGMENT is valid so we can use it
            else
            {
                codeOffset = segmentCommand.fileoff;
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_many_bytes(address + codeOffset, buf, segmentCommand.filesize);
            // always set the offset
            qfseek(outputFile, codeOffset, SEEK_SET);
            qfwrite(outputFile, buf, segmentCommand.filesize);
            qfree(buf);
        }
        else if (loadCommand.cmd == LC_SYMTAB)
        {
            struct symtab_command symtabCommand;
            get_many_bytes(cmdsBaseAddress, &symtabCommand, sizeof(struct symtab_command));
            if (symtabCommand.symoff > 0)
            {
                void *buf = qalloc(symtabCommand.nsyms*sizeof(struct nlist));
                get_many_bytes(address + symtabCommand.symoff, buf, symtabCommand.nsyms*sizeof(struct nlist));
                qfseek(outputFile, symtabCommand.symoff, SEEK_SET);
                qfwrite(outputFile, buf, symtabCommand.nsyms*sizeof(struct nlist));
                qfree(buf);
            }
            if (symtabCommand.stroff > 0)
            {
                void *buf = qalloc(symtabCommand.strsize);
                get_many_bytes(address + symtabCommand.stroff, buf, symtabCommand.strsize);
                qfseek(outputFile, symtabCommand.stroff, SEEK_SET);
                qfwrite(outputFile, buf, symtabCommand.strsize);
                qfree(buf);
            }
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
            get_many_bytes(address + codeOffset, buf, segmentCommand64.filesize);
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
    return 0;

}

/*
 * function to extract non-fat binaries, 32 and 64bits
 */
uint8_t 
extract_macho(ea_t address, char *outputFilename)
{
    uint32 magicValue = get_long(address);
    
    struct mach_header *mach_header = NULL;
    struct mach_header_64 *mach_header64 = NULL;
        
    uint8_t arch = 0;
    if (magicValue == MH_MAGIC)
    {
#if DEBUG
        msg("[DEBUG] Target is 32bits!\n");
#endif
        mach_header = (struct mach_header *)qalloc(sizeof(struct mach_header));
        // retrieve mach_header contents
        if(!get_many_bytes(address, mach_header, sizeof(struct mach_header)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
    }
    else if (magicValue == MH_MAGIC_64)
    {
#if DEBUG
        msg("[DEBUG] Target is 64bits!\n");
#endif
        mach_header64 = (struct mach_header_64 *)qalloc(sizeof(struct mach_header_64));
        if(!get_many_bytes(address, mach_header64, sizeof(struct mach_header_64)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
        arch = 1;
    }
    
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        msg("[ERROR] Could not open %s file!\n", outputFilename);
        return 1;
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
    
    get_many_bytes(address + headerSize, loadcmdsBuffer, sizeofcmds);
    // write all the load commands block to the output file
    // only LC_SEGMENT commands contain further data
    qfwrite(outputFile, loadcmdsBuffer, sizeofcmds);
    
    // and now process the load commands so we can retrieve code and data
    struct load_command loadCommand;
    ea_t cmdsBaseAddress = address + headerSize;    
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
            get_many_bytes(address + codeOffset, buf, segmentCommand.filesize);
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
            get_many_bytes(address + codeOffset, buf, segmentCommand64.filesize);
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
    return 0;
}

/*
 * function to extract fat archives
 */
uint8_t 
extract_fat(ea_t address, char *outputFilename)
{
#if DEBUG
    msg("[DEBUG] Target is a fat binary!\n");
#endif
    struct fat_header fatHeader;
    get_many_bytes(address, &fatHeader, sizeof(struct fat_header));
    validate_fat(fatHeader, address);
    // for fat binaries things are much easier to dump
    // since the fat_arch struct contains total size of the binary :-)
    // open output file
    FILE *outputFile = qfopen(outputFilename, "wb+");
    if (outputFile == NULL)
    {
        msg("[ERROR] Could not open %s file!\n", outputFilename);
        return 1;
    }
    // write fat_header
    qfwrite(outputFile, &fatHeader, sizeof(struct fat_header));
    // read fat_arch
    ea_t fatArchAddress = address + sizeof(struct fat_header);
    void *tempBuf = qalloc(sizeof(struct fat_arch)*ntohl(fatHeader.nfat_arch));
    get_many_bytes(fatArchAddress, tempBuf, sizeof(struct fat_arch)*ntohl(fatHeader.nfat_arch));
    qfwrite(outputFile, tempBuf, sizeof(struct fat_arch)*ntohl(fatHeader.nfat_arch));
    
    for (uint32_t i = 0; i < ntohl(fatHeader.nfat_arch) ; i++)
    {
        struct fat_arch tempFatArch;        
        get_many_bytes(fatArchAddress, &tempFatArch, sizeof(struct fat_arch));
        void *tempBuf = qalloc(ntohl(tempFatArch.size));
        get_many_bytes(address+ntohl(tempFatArch.offset), tempBuf, ntohl(tempFatArch.size));
        qfseek(outputFile, ntohl(tempFatArch.offset), SEEK_SET);
        qfwrite(outputFile, tempBuf, ntohl(tempFatArch.size));
        fatArchAddress += sizeof(struct fat_arch);
    }
    qfree(tempBuf);
    qfclose(outputFile);
    return 0;
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
