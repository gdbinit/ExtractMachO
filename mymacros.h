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
 * mymacros.h
 *
 */

#ifndef _MYMACROS_H
#define _MYMACROS_H

#define LOADSTRING(msg,value) \
qsnprintf(buf, sizeof(buf), "%s %d", msg, value); si->sv.push_back(simpleline_t(buf));

#define CONTENTSTRING(msg,value) \
memset(buf, 0, sizeof(buf));qsnprintf(buf, sizeof(buf), "%s %s", msg, value); si->sv.push_back(simpleline_t(buf));

#define CONTENTHEX(msg,value) \
qsnprintf(buf, sizeof(buf), "%s 0x%08x", msg, value); si->sv.push_back(simpleline_t(buf));

#define CONTENTHEX64(msg,value) \
qsnprintf(buf, sizeof(buf), "%s 0x%016x", msg, value); si->sv.push_back(simpleline_t(buf));

#define CONTENTDEC(msg,value) \
qsnprintf(buf, sizeof(buf), "%s %d", msg, value); si->sv.push_back(simpleline_t(buf));

#define SECTIONHEADER() \
qsnprintf(buf, sizeof(buf), "Section"); si->sv.push_back(simpleline_t(buf));

#define SPACE() \
qsnprintf(buf, sizeof(buf), ""); si->sv.push_back(simpleline_t(buf));

#define COMMENT_STRING(addr, length, msg) \
doASCI(addr, length); set_cmt(addr, msg, 0);

#define COMMENT_DWORD(addr, msg) \
doDwrd(addr, 4); set_cmt(addr, msg, 0);

#define COMMENT_QWORD(addr, msg) \
doQwrd(addr, 4); set_cmt(addr, msg, 0);

#define CONTENT_STRING_STRING(msg, value, addr, length, msg2) \
memset(buf, 0, sizeof(buf));qsnprintf(buf, sizeof(buf), "%s %s", msg, value); si->sv.push_back(simpleline_t(buf));doASCI(addr, length); set_cmt(addr, msg2, 0);

// limit string size because sectname and segname sometimes use the full 16bytes without space for the null byte
#define CONTENT_STRING16_STRING(msg, value, addr, length, msg2) \
memset(buf, 0, sizeof(buf));qsnprintf(buf, sizeof(buf), "%s %.16s", msg, value); si->sv.push_back(simpleline_t(buf));doASCI(addr, length); set_cmt(addr, msg2, 0);

#define CONTENT_STRING_DWORD(msg, value, addr, msg2) \
memset(buf, 0, sizeof(buf));qsnprintf(buf, sizeof(buf), "%s %s", msg, value); si->sv.push_back(simpleline_t(buf));doDwrd(addr, 4); set_cmt(addr, msg2, 0);

#define CONTENT_HEX_STRING(msg, value, addr, length, msg2) \
qsnprintf(buf, sizeof(buf), "%s 0x%08x", msg, value); si->sv.push_back(simpleline_t(buf));doASCI(addr, length); set_cmt(addr, msg2, 0);

#define CONTENT_HEX_DWORD(msg, value, addr, msg2) \
qsnprintf(buf, sizeof(buf), "%s 0x%08x", msg, value); si->sv.push_back(simpleline_t(buf));doDwrd(addr, 4); set_cmt(addr, msg2, 0);

#define CONTENT_HEX64_STRING(msg, value, addr, length, msg2) \
qsnprintf(buf, sizeof(buf), "%s 0x%016llx", msg, value); si->sv.push_back(simpleline_t(buf));doASCI(addr, length); set_cmt(addr, msg2, 0);

#define CONTENT_HEX64_DWORD(msg, value, addr, msg2) \
qsnprintf(buf, sizeof(buf), "%s 0x%016llx", msg, value); si->sv.push_back(simpleline_t(buf));doQwrd(addr, 4); set_cmt(addr, msg2, 0);

#define CONTENT_DEC_DWORD(msg, value, addr, msg2) \
qsnprintf(buf, sizeof(buf), "%s %d", msg, value); si->sv.push_back(simpleline_t(buf));doDwrd(addr, 4); set_cmt(addr, msg2, 0);

#define PUSHBACK si->sv.push_back(simpleline_t(buf));

#endif
