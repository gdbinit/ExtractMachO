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
 * extractors.cpp
 *
 */

#include "extractors.h"
#include "validate.h"

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
                    uint8_t *relocBuf = (uint8_t*)qalloc(size);
                    get_many_bytes(address + sectionCommand.reloff, relocBuf, size);
                    qfseek(outputFile, sectionCommand.reloff, SEEK_SET);
                    qfwrite(outputFile, relocBuf, size);
                    qfree(relocBuf);
                }
                sectionAddress += sizeof(struct section);
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand.filesize);
            get_many_bytes(address + segmentCommand.fileoff, buf, segmentCommand.filesize);
            // always set the offset
            qfseek(outputFile, segmentCommand.fileoff, SEEK_SET);
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
        // FIXME: will this work ? needs to be tested :-)
        else if (loadCommand.cmd == LC_SEGMENT_64)
        {
            get_many_bytes(cmdsBaseAddress, &segmentCommand64, sizeof(struct segment_command_64));
            ea_t sectionAddress = cmdsBaseAddress + sizeof(struct segment_command_64);
            struct section_64 sectionCommand64;
            for (uint32_t x = 0; x < segmentCommand64.nsects; x++)
            {
                get_many_bytes(sectionAddress, &sectionCommand64, sizeof(struct section_64));
                if (sectionCommand64.nreloc > 0)
                {
                    uint32_t size = sectionCommand64.nreloc*sizeof(struct relocation_info);
                    uint8_t *relocBuf = (uint8_t*)qalloc(size);
                    get_many_bytes(address + sectionCommand64.reloff, relocBuf, size);
                    qfseek(outputFile, sectionCommand64.reloff, SEEK_SET);
                    qfwrite(outputFile, relocBuf, size);
                    qfree(relocBuf);
                }
                sectionAddress += sizeof(struct section_64);
            }
            // read and write the data
            uint8_t *buf = (uint8_t*)qalloc(segmentCommand64.filesize);
            get_many_bytes(address + segmentCommand64.fileoff, buf, segmentCommand64.filesize);
            qfseek(outputFile, segmentCommand64.fileoff, SEEK_SET);
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
        // FIXME: do we also need to dump the relocs info here ?
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
    msg("[DEBUG] Trying to extract a fat binary target!\n");
#endif
    struct fat_header fatHeader;
    if(!get_many_bytes(address, &fatHeader, sizeof(struct fat_header)))
    {
        msg("[ERROR] Read bytes failed!\n");
        return 1;
    }
    if(validate_fat(fatHeader, address))
        return 1;
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
    uint32_t fatArchSize = sizeof(struct fat_arch)*ntohl(fatHeader.nfat_arch);
    // write all fat_arch structs
    void *fatArchBuf = qalloc(fatArchSize);
    if(!get_many_bytes(fatArchAddress, fatArchBuf, fatArchSize))
    {
        msg("[ERROR] Read bytes failed!\n");
        return 1;
    }
    qfwrite(outputFile, fatArchBuf, fatArchSize);
    qfree(fatArchBuf);
    // write the mach-o binaries inside the fat archive
    for (uint32_t i = 0; i < ntohl(fatHeader.nfat_arch) ; i++)
    {
        struct fat_arch tempFatArch;
        // read the fat_arch struct
        if(!get_many_bytes(fatArchAddress, &tempFatArch, sizeof(struct fat_arch)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
        // read and write the mach-o binary pointed by each fat_arch struct
        void *tempBuf = qalloc(ntohl(tempFatArch.size));
        if(!get_many_bytes(address+ntohl(tempFatArch.offset), tempBuf, ntohl(tempFatArch.size)))
        {
            msg("[ERROR] Read bytes failed!\n");
            return 1;
        }
        qfseek(outputFile, ntohl(tempFatArch.offset), SEEK_SET);
        qfwrite(outputFile, tempBuf, ntohl(tempFatArch.size));
        qfree(tempBuf);
        // advance to next fat_arch struct
        fatArchAddress += sizeof(struct fat_arch);
    }
    // all done
    qfclose(outputFile);
    return 0;
}

