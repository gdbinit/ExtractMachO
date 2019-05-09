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
 *  v1.1
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
#include "extractors.h"
#include "validate.h"
#include "uthash.h"

#define VERSION "1.1.1"
//#define DEBUG 0

uint8_t extract_binary(ea_t address, char *outputFilename);
void add_to_fat_list(ea_t address);
void add_to_hits_list(ea_t address, uint8_t type, uint8_t extracted);
void do_report(void);

// structure to add the address of binaries inside fat archives so we don't extract them again
struct found_fat
{
    ea_t id;          // magic value address
    UT_hash_handle hh;
};

struct found_fat *found_fat = NULL;

// structure for reports
struct report
{
    ea_t id;           // magic value address
    uint8_t type;      // 0 = 32bits, 1 = 64bits, 2 = FAT
    uint8_t extracted; // 0 = extracted, 1 = not extracted
    UT_hash_handle hh;
};

struct report *report = NULL;

#define TARGET_32  0
#define TARGET_64  1
#define TARGET_FAT 2

int IDAP_init(void)
{
    msg("----------------------------------\n");
    msg("Extract Mach-O plugin loaded, v%s\n", VERSION);
    msg("(c) fG!, 2012 - reverser@put.as\n");
    msg("----------------------------------\n");
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
    uint32 magicValue = get_long(cursorAddress);
    
    uint8_t globalSearch = 1;
    char *outputFilename = NULL;
    // test if current cursor position has a valid mach-o
    // if yes, ask user if he wants to extract only this one or search for all

    if (magicValue == MH_MAGIC || magicValue == MH_MAGIC_64 || magicValue == FAT_CIGAM)
    {
        int answer = askyn_c(0, "Current location contains a potential Mach-O binary! Attempt to extract only this one?");
        // user wants to extract this binary
        if (answer == 1)
        {
            // ask for output location & name
            outputFilename = askfile_c(1, NULL, "Select output file...");
            if (outputFilename == NULL || outputFilename[0] == 0)
                return;
            extract_binary(cursorAddress, outputFilename);
            do_report();
            return;
        }
        // cancelled
        if (answer == -1)
            return;
        
        globalSearch = answer ? 0 : 1;
    }

    if (globalSearch)
    {
        char form[]="Choose output directory\n<~O~utput directory:F:0:64::>";
        char outputDir[MAXSTR] = "";
        // cancelled
        if (AskUsingForm_c(form, outputDir) == 0)
            return;
        
        // we want to avoid dumping itself so we start at one byte ahead of the first address in the database
        ea_t findAddress = inf.minEA+1;
        uchar magicFat[]    = "\xCA\xFE\xBA\xBE";
        
        // we have a small problem here
        // fat archives contain valid mach-o binaries so they will be found if we search for fat and non-fat binaries
        // solution is to first lookup the fat archives and add the binaries location to a list
        // then match against that list when searching for non-fat binaries and skip extraction if it's on that list

        // lookup fat archives
        while (findAddress != BADADDR)
        {
            findAddress = bin_search(findAddress, inf.maxEA, magicFat, NULL, 4, BIN_SEARCH_FORWARD, BIN_SEARCH_NOCASE);
            if (findAddress != BADADDR)
            {
                add_to_fat_list(findAddress);
                char output[MAXSTR];
#ifdef __EA64__
                qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%llx_fat", outputDir, findAddress);
#else
                qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%x_fat", outputDir, findAddress);
#endif
                extract_binary(findAddress, output);
                findAddress += 1;
            }
        }

        findAddress = inf.minEA+1;
        
#define NR_ARCHS 4
        uchar* archmagic[NR_ARCHS];
        archmagic[0] = (uchar*)"\xCE\xFA\xED\xFE";
        archmagic[1] = (uchar*)"\xCF\xFA\xED\xFE";
        archmagic[2] = (uchar*)"\xFE\xED\xFA\xCE";
        archmagic[3] = (uchar*)"\xFE\xED\xFA\xCF";
        
        for (uint32_t i = 0; i < NR_ARCHS; i++)
        {
            while (findAddress != BADADDR)
            {
                findAddress = bin_search(findAddress, inf.maxEA, archmagic[i], NULL, 4, BIN_SEARCH_FORWARD, BIN_SEARCH_NOCASE);
                struct found_fat *f = NULL;
                HASH_FIND(hh, found_fat, &findAddress, 4, f);
                if (findAddress != BADADDR && f == NULL)
                {
                    char output[MAXSTR];
#ifdef __EA64__
                    qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%llx", outputDir, findAddress);
#else
                    qsnprintf(output, sizeof(output)-1, "%s/extracted_offset_0x%x", outputDir, findAddress);
#endif
                    extract_binary(findAddress, output);
                    findAddress += 1;
                }
                // we need to advance anyway in case binary is in the fat list
                else if (findAddress != BADADDR)
                    findAddress += 1;
            }
            // reset start address
            findAddress = inf.minEA+1;
        }
    }

    // output a final report of what happened
    do_report();
    // it's over!
	return;
}

/*
 * entry function to validate and extract fat and non-fat binaries
 */
uint8_t 
extract_binary(ea_t address, char *outputFilename)
{
    uint8_t retValue = 0;
    uint32 magicValue = get_long(address);
    switch (magicValue)
    {
        case MH_MAGIC:
        case MH_MAGIC_64:
        case MH_CIGAM_64:
        case MH_CIGAM:
        {
            if(validate_macho(address))
            {
#ifdef __EA64__
                msg("[ERROR] Not a valid mach-o binary at %llx\n", address);
#else
                msg("[ERROR] Not a valid mach-o binary at %x\n", address);
#endif
                add_to_hits_list(address, (magicValue == MH_MAGIC || magicValue == MH_CIGAM) ? TARGET_32 : TARGET_64, 1);
                return 1;
            }
            // we just need to read mach_header.filetype so no problem in using the 32bit struct
            struct mach_header header;
            get_many_bytes(address, &header, sizeof(struct mach_header));
            uint32_t filetype = (magicValue == MH_MAGIC || magicValue == MH_MAGIC_64) ? header.filetype : ntohl(header.filetype);
            if (filetype == MH_OBJECT)
                retValue = extract_mhobject(address, outputFilename);
            else
                retValue = extract_macho(address, outputFilename);
            
            add_to_hits_list(address, (magicValue == MH_MAGIC || magicValue == MH_CIGAM) ? TARGET_32 : TARGET_64, retValue);
            break;
        }
        case FAT_CIGAM:
        {
            retValue = extract_fat(address, outputFilename);
            add_to_hits_list(address, TARGET_FAT, retValue);
            break;
        }
        default:
        {
            msg("[ERROR] No potentially valid mach-o binary at current location!\n");
            retValue = 1;
            break;
        }
    }
    return retValue;
}

/*
 * sorter
 */
int id_sort(struct report *a, struct report *b) {
    return (a->id - b->id);
}

/*
 * output final extraction report
 */
void
do_report(void)
{
    HASH_SORT(report, id_sort);
    msg("Mach-O extraction Report:\n");
    struct report *tempReport;
    for (tempReport = report; tempReport != NULL; tempReport = (struct report*)tempReport->hh.next)
    {
#ifdef __EA64__
        msg("Address: 0x%016llx Type: %6s Extracted: %s\n", tempReport->id, 
            tempReport->type == 0 ? "32bits" : tempReport->type == 1 ? "64bits" : "Fat",
            tempReport->extracted ? "No" : "Yes");
#else
        msg("Address: 0x%016x Type: %6s Extracted: %s\n", tempReport->id, 
            tempReport->type == 0 ? "32bits" : tempReport->type == 1 ? "64bits" : "Fat",
            tempReport->extracted ? "No" : "Yes");
#endif
    }    
    msg("Mach-O extraction is over!\n");
}

/*
 * list where we add information for the final report
 */
void
add_to_hits_list(ea_t address, uint8_t type, uint8_t extracted)
{
    struct report *new_report = (struct report*)qalloc(sizeof(struct report));
    new_report->id = address;
    new_report->type = type;
    new_report->extracted = extracted;
    HASH_ADD_INT(report, id, new_report);
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
