#include <stdio.h>
#include <stdlib.h>

#include "../interpreter/wasm_runtime.h"
#include "wasm_migration.h"
#include "wasm_dump.h"
#include "wasm_dispatch.h"

// #define skip_leb(p) while (*p++ & 0x80)
#define skip_leb(p)                     \
    while (1) {                         \
        if (*p & 0x80)p++;              \
        else break;                     \
    }                                   \

/* common_functions */
int dump_value(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (stream == NULL) {
        return -1;
    }
    return fwrite(ptr, size, nmemb, stream);
}

int debug_memories(WASMModuleInstance *module) {
    printf("=== debug memories ===\n");
    printf("memory_count: %d\n", module->memory_count);
    
    // bytes_per_page
    for (int i = 0; i < module->memory_count; i++) {
        WASMMemoryInstance *memory = (WASMMemoryInstance *)(module->memories[i]);
        printf("%d) bytes_per_page: %d\n", i, memory->num_bytes_per_page);
        printf("%d) cur_page_count: %d\n", i, memory->cur_page_count);
        printf("%d) max_page_count: %d\n", i, memory->max_page_count);
        printf("\n");
    }

    printf("=== debug memories ===\n");
}

// 積まれてるframe stackを出力する
void debug_frame_info(WASMExecEnv* exec_env, WASMInterpFrame *frame) {
    WASMModuleInstance *module = exec_env->module_inst;

    int cnt = 0;
    printf("=== DEBUG Frame Stack ===\n");
    do {
        cnt++;
        if (frame->function == NULL) {
            printf("%d) func_idx: -1\n", cnt);
        }
        else {
            printf("%d) func_idx: %d\n", cnt, frame->function - module->e->functions);
        }
    } while (frame = frame->prev_frame);
    printf("=== DEBUG Frame Stack ===\n");
}

// func_instの先頭からlimitまでのopcodeを出力する
int debug_function_opcodes(WASMModuleInstance *module, WASMFunctionInstance* func, uint32 limit) {
    FILE *fp = fopen("wamr_opcode.log", "a");
    if (fp == NULL) return -1;

    fprintf(fp, "fidx: %d\n", func - module->e->functions);
    uint8 *ip = wasm_get_func_code(func);
    uint8 *ip_end = wasm_get_func_code_end(func);
    
    for (int i = 0; i < limit; i++) {
        fprintf(fp, "%d) opcode: 0x%x\n", i+1, *ip);
        ip = dispatch(ip, ip_end);
        if (ip >= ip_end) break;
    }

    fclose(fp);
    return 0;
}

// int debug_flag = 0;
// ipからip_limまでにopcodeがいくつかるかを返す
int get_opcode_offset(uint8 *ip, uint8 *ip_lim) {
    uint32 cnt = 0;
    bh_assert(ip != NULL);
    bh_assert(ip_lim != NULL);
    bh_assert(ip <= ip_lim);
    if (ip > ip_lim) return -1;
    if (ip == ip_lim) return 0;
    while (1) {
        // LOG_DEBUG("get_opcode_offset::ip: 0x%x\n", *ip);
        // if (debug_flag) {
        //     printf("(cnt, opcode) = (%d, 0x%x)\n", cnt, *ip);
        // }
        ip = dispatch(ip, ip_lim);
        cnt++;
        if (ip >= ip_lim) break;
    }
    return cnt;
}

/* wasm_dump */
static void
_dump_stack(WASMExecEnv *exec_env, struct WASMInterpFrame *frame, struct FILE *fp)
{
    int i;
    WASMModuleInstance *module = exec_env->module_inst;

    // Entry function
    // wasm_dump_stackの方でdump

    // リターンアドレス
    // NOTE: 1番下のframeのときだけ、prev_frameではなくframeのリターンアドレスを出力する
    WASMInterpFrame* prev_frame = (frame->prev_frame->function ? frame->prev_frame : frame);
    uint32 fidx = prev_frame->function - module->e->functions;
    uint32 offset = prev_frame->ip - wasm_get_func_code(prev_frame->function);
    fwrite(&fidx, sizeof(uint32), 1, fp);
    fwrite(&offset, sizeof(uint32), 1, fp);

    // 型スタックのサイズ
    WASMFunctionInstance *func = frame->function;
    uint32 locals = func->param_count + func->local_count;
    uint32 type_stack_size = (frame->tsp - frame->tsp_bottom);
    uint32 full_type_stack_size = type_stack_size + locals;
    fwrite(&full_type_stack_size, sizeof(uint32), 1, fp);

    // 型スタックの中身
    uint8 type_stack_locals[locals];
    // TODO: ここの実装バグの温床なので、なんとかする
    uint32 *lp = frame->lp;
    for (i = 0; i < func->param_count; i++) {
        switch (func->param_types[i]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
                type_stack_locals[i] = 1;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                type_stack_locals[i] = 2;
                break;
            default:
                type_stack_locals[i] = 4;
                break;
        }
    }
    uint32 local_base = func->param_count;
    for (i = 0; i < func->local_count; i++) {
        switch (func->local_types[i]) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
                type_stack_locals[local_base+i] = 1;
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                type_stack_locals[local_base+i] = 2;
                break;
            default:
                type_stack_locals[local_base+i] = 4;
                break;
        }
    }
    fwrite(&type_stack_locals, sizeof(uint8), locals, fp);

    // TODO: type_stackをuint8*にする
    uint32* tsp_bottom = frame->tsp_bottom;
    for (i = 0; i < type_stack_size; ++i) {
        uint8 type = tsp_bottom[i];
        fwrite(&type, sizeof(uint8), 1, fp);
    }

    // 値スタックの中身
    uint32 local_cell_num = func->param_cell_num + func->local_cell_num;
    uint32 value_stack_size = frame->sp - frame->sp_bottom;
    fwrite(frame->lp, sizeof(uint32), local_cell_num, fp);
    fwrite(frame->sp_bottom, sizeof(uint32), value_stack_size, fp);

    // ラベルスタックのサイズ
    uint32 ctrl_stack_size = frame->csp - frame->csp_bottom;
    fwrite(&ctrl_stack_size, sizeof(uint32), 1, fp);

    // ラベルスタックの中身
    WASMBranchBlock *csp = frame->csp_bottom;
    uint32 addr;
    uint8* ip_start = wasm_get_func_code(frame->function);
    for (i = 0; i < ctrl_stack_size; ++i, ++csp) {
        // uint8 *begin_addr;
        addr = get_addr_offset(csp->begin_addr, ip_start);
        fwrite(&addr, sizeof(uint32), 1, fp);

        // uint8 *target_addr;
        addr = get_addr_offset(csp->target_addr, ip_start);
        fwrite(&addr, sizeof(uint32), 1, fp);

        // uint32 *frame_sp;
        addr = get_addr_offset(csp->frame_sp, frame->sp_bottom);
        fwrite(&addr, sizeof(uint32), 1, fp);

        // uint32 *frame_tsp;
        addr = get_addr_offset(csp->frame_tsp, frame->tsp_bottom);
        fwrite(&addr, sizeof(uint32), 1, fp);
        
        // uint32 cell_num;
        fwrite(&csp->cell_num, sizeof(uint32), 1, fp);

        // uint32 count;
        fwrite(&csp->count, sizeof(uint32), 1, fp);
    }
}


int
wasm_dump_stack(WASMExecEnv *exec_env, struct WASMInterpFrame *frame)
{
    WASMModuleInstance *module =
        (WASMModuleInstance *)exec_env->module_inst;

    // frameをtopからbottomまで走査する
    char file[32];
    int i = 0;
    do {
        // dummy framenならbreak
        if (frame->function == NULL) break;

        ++i;
        sprintf(file, "stack%d.img", i);
        FILE *fp = open_image(file, "wb");

        uint32 entry_fidx = frame->function - module->e->functions;
        fwrite(&entry_fidx, sizeof(uint32), 1, fp);

        _dump_stack(exec_env, frame, fp);
        fclose(fp);
    } while(frame = frame->prev_frame);

    // frame stackのサイズを保存
    FILE *fp = open_image("frame.img", "wb");
    fwrite(&i, sizeof(uint32), 1, fp);
    fclose(fp);

    return 0;
}

int is_page_dirty(const void *virtaddr) {
#define PAGEMAP_LENGTH 8
    int fd;
    char path[64];
    int page_size = sysconf(_SC_PAGESIZE);
    uint64 pagemap_entry;

    // プロセスのpagemapを開く
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("Error opening pagemap");
        return -1;
    }

    // pfnに対応するpagemapエントリを取得
    unsigned long pfn = (unsigned long)virtaddr / page_size;
    off_t offset = sizeof(uint64) * pfn;
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("Error seeking to pagemap entry");
        close(fd);
        return -1;
    }

    if (read(fd, &pagemap_entry, PAGEMAP_LENGTH) != PAGEMAP_LENGTH) {
        perror("Error reading pagemap entry");
        close(fd);
        return -1;
    }

    // ページのdirtyビットを確認
    int is_dirty = (pagemap_entry 
                    & ((1ULL << 55) | (1ULL << 62) | (1ULL << 63)) != 0);

    close(fd);
    return is_dirty;
}
int do_task_reset_dirty_track()
{
	int fd, ret;
	char cmd[] = "4";

    fd = open("/proc/self/clear_refs", O_RDWR);

	if (fd < 0)
		return errno == EACCES ? 1 : -1;

	ret = write(fd, cmd, sizeof(cmd));
	if (ret < 0) {
		if (errno == EINVAL) /* No clear-soft-dirty in kernel */
			ret = 1;
		else {
			ret = -1;
		}
	} else {
		ret = 0;
	}

	close(fd);
	return ret;
}

int is_dirty(uint64 pagemap_entry) {
    return (pagemap_entry>>62&1) | (pagemap_entry>>63&1);
    // return (pagemap_entry 
    //             & (1ULL << 55 | 1ULL << 62 | 1ULL << 63) != 0);
}

int dump_dirty_memory(WASMMemoryInstance *memory) {
#define PAGEMAP_LENGTH 8
#define PAGE_SIZE 4096

    // soft dirtyをreset
    // do_task_reset_dirty_track();

    FILE *new_memory_fp = open_image("memory.img", "wb");
    int fd;
    uint64 pagemap_entry;

    // プロセスのpagemapを開く
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1) {
        perror("Error opening pagemap");
        return -1;
    }

    // pfnに対応するpagemapエントリを取得
    unsigned long pfn = (unsigned long)memory->memory_data / PAGE_SIZE;
    off_t offset = sizeof(uint64) * pfn;
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("Error seeking to pagemap entry");
        close(fd);
        return -1;
    }

    // printf("swapped, present\n", pagemap_entry>>62, pagemap_entry>>63);

    uint8* memory_data = memory->memory_data;
    uint8* memory_data_end = memory->memory_data_end;
    int i = 0;
    for (uint8* addr = memory->memory_data; addr < memory_data_end; addr += PAGE_SIZE, ++i) {
        unsigned long pfn = (unsigned long)addr / PAGE_SIZE;
        off_t offset = sizeof(uint64) * pfn;
        if (lseek(fd, offset, SEEK_SET) == -1) {
            perror("Error seeking to pagemap entry");
            close(fd);
            return -1;
        }

        if (read(fd, &pagemap_entry, PAGEMAP_LENGTH) != PAGEMAP_LENGTH) {
            perror("Error reading pagemap entry");
            close(fd);
            return -1;
        }
        // printf("[%x, %x]: %d, %d\n", i*PAGE_SIZE, (i+1)*PAGE_SIZE, pagemap_entry>>62&1, pagemap_entry>>63&1);

        // dirty pageのみdump
        if (is_dirty(pagemap_entry)) {
            // printf("[%x, %x]: dirty page\n", i*PAGE_SIZE, (i+1)*PAGE_SIZE);
            uint32 offset = (uint64)addr - (uint64)memory_data;
            // printf("i: %d\n", offset);
            fwrite(&offset, sizeof(uint32), 1, new_memory_fp);
            fwrite(addr, PAGE_SIZE, 1, new_memory_fp);
        }
    }

    close(fd);
    fclose(new_memory_fp);
    return is_dirty;
}

int wasm_dump_memory(WASMMemoryInstance *memory) {
    FILE *memory_fp = open_image("all_memory.img", "wb");
    FILE *mem_size_fp = open_image("mem_page_count.img", "wb");

    // WASMMemoryInstance *memory = module->default_memory;
    // uint8* memory_data = memory->memory_data;
    // uint8* memory_data_end = memory->memory_data_end;
    // int page_size = sysconf(_SC_PAGESIZE);
    // uint32 i = 0;
    // for (uint8* addr = memory_data; addr < memory_data_end; addr += page_size, ++i) {
    //     if (is_page_dirty(addr)) {
    //         fwrite(&i, sizeof(uint32), 1, new_memory_fp);
    //         fwrite(addr, page_size, 1, new_memory_fp);
    //     }
    // }
    dump_dirty_memory(memory);

    fwrite(memory->memory_data, sizeof(uint8),
           memory->num_bytes_per_page * memory->cur_page_count, memory_fp);

    printf("page_count: %d\n", memory->cur_page_count);
    fwrite(&(memory->cur_page_count), sizeof(uint32), 1, mem_size_fp);

    fclose(memory_fp);
    fclose(mem_size_fp);
}

int wasm_dump_global(WASMModuleInstance *module, WASMGlobalInstance *globals, uint8* global_data) {
    FILE *fp;
    const char *file = "global.img";
    fp = fopen(file, "wb");
    if (fp == NULL) {
        fprintf(stderr, "failed to open %s\n", file);
        return -1;
    }

    // WASMMemoryInstance *memory = module->default_memory;
    uint8 *global_addr;
    for (int i = 0; i < module->e->global_count; i++) {
        switch (globals[i].type) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_F32:
                global_addr = get_global_addr_for_migration(global_data, (globals+i));
                fwrite(global_addr, sizeof(uint32), 1, fp);
                break;
            case VALUE_TYPE_I64:
            case VALUE_TYPE_F64:
                global_addr = get_global_addr_for_migration(global_data, (globals+i));
                fwrite(global_addr, sizeof(uint64), 1, fp);
                break;
            default:
                printf("type error:B\n");
                break;
        }
    }

    fclose(fp);
    return 0;
}

int wasm_dump_program_counter(
    WASMModuleInstance *module,
    WASMFunctionInstance *func,
    uint8 *frame_ip
)
{
    FILE *fp;
    const char *file = "program_counter.img";
    fp = fopen(file, "wb");
    if (fp == NULL) {
        fprintf(stderr, "failed to open %s\n", file);
        return -1;
    }

    uint32 fidx, p_offset;
    fidx = func - module->e->functions;
    p_offset = frame_ip - wasm_get_func_code(func);

    dump_value(&fidx, sizeof(uint32), 1, fp);
    dump_value(&p_offset, sizeof(uint32), 1, fp);
}

int wasm_dump(WASMExecEnv *exec_env,
         WASMModuleInstance *module,
         WASMMemoryInstance *memory,
         WASMGlobalInstance *globals,
         uint8 *global_data,
         uint8 *global_addr,
         WASMFunctionInstance *cur_func,
         struct WASMInterpFrame *frame,
         register uint8 *frame_ip,
         register uint32 *frame_sp,
         WASMBranchBlock *frame_csp,
         uint32 *frame_tsp,
         uint8 *frame_ip_end,
         uint8 *else_addr,
         uint8 *end_addr,
         uint8 *maddr,
         bool done_flag)
{
    int rc;
    // dump linear memory
    rc = wasm_dump_memory(memory);
    if (rc < 0) {
        LOG_ERROR("Failed to dump linear memory\n");
        return rc;
    }

    // dump globals
    rc = wasm_dump_global(module, globals, global_data);
    if (rc < 0) {
        LOG_ERROR("Failed to dump globals\n");
        return rc;
    }

    // dump program counter
    rc = wasm_dump_program_counter(module, cur_func, frame_ip);
    if (rc < 0) {
        LOG_ERROR("Failed to dump program_counter\n");
        return rc;
    }

    // dump frame
    rc = wasm_dump_stack(exec_env, frame);
    if (rc < 0) {
        LOG_ERROR("Failed to dump frame\n");
        return rc;
    }

    LOG_VERBOSE("Success to dump img for wamr\n");
    return 0;
}
