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
 * validate.h
 *
 */

#ifndef ExtractMachO_validate_cpp
#define ExtractMachO_validate_cpp

#include <stdint.h>
// IDA SDK includes
#include <ida.hpp> 
#include <idp.hpp> 
#include <bytes.hpp>
#include <kernwin.hpp>

#include "mac_includes.h"

uint8_t validate_macho(ea_t address);
uint8_t validate_fat(struct fat_header fatHeader, ea_t position);

#endif
