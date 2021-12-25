//
//  main.c
//  mach-o-utility
//
//  Created by Artur Mubarakshin on 06.12.2021.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define MAIN_FORMAT_ERROR 1
#define MAIN_CHECK_FAT_ERROR 2
#define MAIN_READ_ERROR 3
#define MAIN_WRITE_ERROR 4
#define MAIN_READ_LCS_ERROR 5
#define MAIN_READ_SECTS_ERROR 6
#define MAIN_EXTRACT_SECT_ERROR 7
#define MAIN_STRIP_LCS_ERROR 8
#define MAIN_STRIP_SECTS_ERROR 9

#define UNEXPECTED_EOF 1

#define FILE_IS_NOT_64_ORIENTED 2
#define FILE_IS_NOT_MACH_O 3
#define FILE_IS_EMPTY 4

#define UNABLE_TO_ALLOCATE_MEMORY 5
#define UNABLE_TO_OPEN_FILE 6
#define UNABLE_TO_CLOSE_FILE 7
#define UNABLE_TO_READ_FILE 8
#define UNABLE_TO_WRITE_FILE 9
#define UNABLE_TO_OBTAIN_FILE_SIZE 10

#define SECTION_IS_NOT_FOUND 11

#define MIN_ALLOCATION_CAPACITY 20

struct section_pointer {
    uint8_t* pointer;
    bool is_64;
    char* segname;
    char* sectname;
    uint32_t offset;
    uint64_t size;
};

typedef uint32_t (*swap32func)(uint32_t);
typedef uint64_t (*swap64func)(uint64_t);

void print_usage(void);

int check_file_fat(const char*, bool*);

int file_size(const char*, size_t*);
int read_file(const char*, uint8_t**, size_t*);
int write_file(const char*, uint8_t*, size_t);

int read_lcs(uint8_t*, size_t, struct load_command***, size_t*);
int read_sects(uint8_t*, size_t, struct load_command**, size_t, struct section_pointer**, size_t*);

int strip_lcs(uint8_t*, size_t, struct load_command**, size_t);
int strip_sects(uint8_t*, size_t, struct section_pointer*, size_t);

int extract_sect(uint8_t*, size_t, const char*, const char*, struct section_pointer*, size_t, uint32_t*, uint64_t*);

int obtain_swap(uint8_t*, size_t, swap32func*, swap64func*);

uint32_t swap_big_to_host(uint32_t);
uint32_t swap_little_to_host(uint32_t);
uint64_t swap_big_to_host_64(uint64_t);
uint64_t swap_little_to_host_64(uint64_t);

int main(int argc, const char * argv[]) {
    if (argc < 2) {
        print_usage();
        return MAIN_FORMAT_ERROR;
    }
    
    const char* action = argv[1];
    
    if (strcmp(action, "--is-fat") == 0 && argc == 3) {
        const char* input_file = argv[2];
        bool is_fat;
        
        int result = check_file_fat(input_file, &is_fat);
        if (result != 0) {
            printf("An error occured while checking file %s. Error code: %i.\n", input_file, result);
            return MAIN_CHECK_FAT_ERROR;
        }
        
        if (is_fat) {
            printf("File %s is a fat mach-o file.\n", input_file);
        } else {
            printf("File %s is not a fat mach-o file.\n", input_file);
        }
        
        return 0;
        
    } else if (strcmp(action, "--extract") == 0 && argc == 6) {
        const char* seg_name = argv[2];
        const char* sect_name = argv[3];
        const char* input_file = argv[4];
        const char* output_file = argv[5];
        
        int step_result = 0;
        int result = 0;
        
        uint8_t* buffer = NULL;
        size_t size;
        
        struct load_command** cmds = NULL;
        size_t cmds_count;
        
        struct section_pointer* sects = NULL;
        size_t sects_count;
        
        uint32_t sect_offset;
        uint64_t sect_size;
        
        step_result = read_file(input_file, &buffer, &size);
        if (step_result != 0) {
            printf("An error occured while reading file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_ERROR;
            goto extract_exit;
        }
        
        step_result = read_lcs(buffer, size, &cmds, &cmds_count);
        if (step_result != 0) {
            printf("An error occured while reading load commands from file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_LCS_ERROR;
            goto extract_exit;
        }
        
        step_result = read_sects(buffer, size, cmds, cmds_count, &sects, &sects_count);
        if (step_result != 0) {
            printf("An error occured while reading sections from file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_SECTS_ERROR;
            goto extract_exit;
        }
        
        step_result = extract_sect(buffer, size, seg_name, sect_name, sects, sects_count, &sect_offset, &sect_size);
        if (step_result != 0) {
            printf("An error occured while extracting section (%s, %s) from file %s. Error code: %i.\n", seg_name, sect_name, input_file, step_result);
            result = MAIN_EXTRACT_SECT_ERROR;
            goto extract_exit;
        }
        
        step_result = write_file(output_file, buffer + sect_offset, sect_size);
        if (step_result != 0) {
            printf("An error occured while writing to file %s. Error code: %i.\n", output_file, step_result);
            result = MAIN_WRITE_ERROR;
            goto extract_exit;
        }
        
    extract_exit:
        free(cmds);
        free(sects);
        free(buffer);
        
        return result;
        
    } else if (strcmp(action, "--contains") == 0 && argc == 5) {
        const char* input_file = argv[2];
        const char* seg_name = argv[3];
        const char* sect_name = argv[4];
        
        int step_result = 0;
        int result = 0;
        
        uint8_t* buffer = NULL;
        size_t size;
        
        struct load_command** cmds = NULL;
        size_t cmds_count;
        
        struct section_pointer* sects = NULL;
        size_t sects_count;
        
        step_result = read_file(input_file, &buffer, &size);
        if (step_result != 0) {
            printf("An error occured while reading file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_ERROR;
            goto contains_exit;
        }
        
        step_result = read_lcs(buffer, size, &cmds, &cmds_count);
        if (step_result != 0) {
            printf("An error occured while reading load commands from file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_LCS_ERROR;
            goto contains_exit;
        }
        
        step_result = read_sects(buffer, size, cmds, cmds_count, &sects, &sects_count);
        if (step_result != 0) {
            printf("An error occured while reading sections from file %s. Error code: %i.\n", input_file, step_result);
            result = MAIN_READ_SECTS_ERROR;
            goto contains_exit;
        }
        
        char* current_seg_name;
        char* current_sect_name;
        bool found = false;
        
        for (int i = 0; i < sects_count; i++) {
            current_seg_name = sects[i].segname;
            current_sect_name = sects[i].sectname;

            if (strcmp(seg_name, current_seg_name) == 0 && strcmp(sect_name, current_sect_name) == 0) {
                found = true;
                break;
            }
        }
        
        if (found) {
            printf("Section (%s, %s) is present in file %s.\n", seg_name, sect_name, input_file);
        } else {
            printf("Section (%s, %s) is not present in file %s.\n", seg_name, sect_name, input_file);
        }
        
    contains_exit:
        free(buffer);
        free(cmds);
        free(sects);
        
        return result;
        
    } else if (strcmp(action, "--validate") == 0 && argc == 4) {
        const char* input_file_a = argv[2];
        const char* input_file_b = argv[3];
        
        int step_result = 0;
        int result = 0;
        
        uint8_t* buffer_a = NULL;
        uint8_t* buffer_b = NULL;
        size_t size_a;
        size_t size_b;
        
        struct load_command** cmds_a = NULL;
        struct load_command** cmds_b = NULL;
        size_t cmds_count_a;
        size_t cmds_count_b;
        
        struct section_pointer* sects_a = NULL;
        struct section_pointer* sects_b = NULL;
        size_t sects_count_a;
        size_t sects_count_b;
        
        step_result = read_file(input_file_a, &buffer_a, &size_a);
        if (step_result != 0) {
            printf("An error occured while reading file %s. Error code: %i.\n", input_file_a, step_result);
            result = MAIN_READ_ERROR;
            goto validate_exit;
        }
        
        step_result = read_file(input_file_b, &buffer_b, &size_b);
        if (step_result != 0) {
            printf("An error occured while reading file %s. Error code: %i.\n", input_file_b, step_result);
            result = MAIN_READ_ERROR;
            goto validate_exit;
        }
        
        step_result = read_lcs(buffer_a, size_a, &cmds_a, &cmds_count_a);
        if (step_result != 0) {
            printf("An error occured while reading load commands from file %s. Error code: %i.\n", input_file_a, step_result);
            result = MAIN_READ_LCS_ERROR;
            goto validate_exit;
        }
        
        step_result = read_lcs(buffer_b, size_b, &cmds_b, &cmds_count_b);
        if (step_result != 0) {
            printf("An error occured while reading load commands from file %s. Error code: %i.\n", input_file_b, step_result);
            result = MAIN_READ_LCS_ERROR;
            goto validate_exit;
        }
        
        step_result = read_sects(buffer_a, size_a, cmds_a, cmds_count_a, &sects_a, &sects_count_a);
        if (step_result != 0) {
            printf("An error occured while reading sections from file %s. Error code: %i.\n", input_file_a, step_result);
            result = MAIN_READ_SECTS_ERROR;
            goto validate_exit;
        }
        
        step_result = read_sects(buffer_b, size_b, cmds_b, cmds_count_b, &sects_b, &sects_count_b);
        if (step_result != 0) {
            printf("An error occured while reading sections from file %s. Error code: %i.\n", input_file_b, step_result);
            result = MAIN_READ_SECTS_ERROR;
            goto validate_exit;
        }
        
        step_result = strip_lcs(buffer_a, size_a, cmds_a, cmds_count_a);
        if (step_result != 0) {
            printf("An error occured while stripping load commands in file %s. Error code: %i.\n", input_file_a, step_result);
            result = MAIN_STRIP_LCS_ERROR;
            goto validate_exit;
        }
        
        step_result = strip_lcs(buffer_b, size_b, cmds_b, cmds_count_b);
        if (step_result != 0) {
            printf("An error occured while stripping load commands in file %s. Error code: %i.\n", input_file_b, step_result);
            result = MAIN_STRIP_LCS_ERROR;
            goto validate_exit;
        }
        
        step_result = strip_sects(buffer_a, size_a, sects_a, sects_count_a);
        if (step_result != 0) {
            printf("An error occured while stripping sections in file %s. Error code: %i.\n", input_file_a, step_result);
            result = MAIN_STRIP_SECTS_ERROR;
            goto validate_exit;
        }
        
        step_result = strip_sects(buffer_b, size_b, sects_b, sects_count_b);
        if (step_result != 0) {
            printf("An error occured while stripping sections in file %s. Error code: %i.\n", input_file_b, step_result);
            result = MAIN_STRIP_SECTS_ERROR;
            goto validate_exit;
        }
        
        if (size_a != size_b || memcmp(buffer_a, buffer_b, size_a) != 0) {
            printf("Files %s and %s are different.\n", input_file_a, input_file_b);
        } else {
            printf("Files %s and %s are identical.\n", input_file_a, input_file_b);
        }
        
    validate_exit:
        free(buffer_a);
        free(buffer_b);
        free(cmds_a);
        free(cmds_b);
        free(sects_a);
        
        return result;
        
    } else {
        print_usage();
        return MAIN_FORMAT_ERROR;
    }
}

void print_usage() {
    printf("Usage:\n");
    printf("  mach-o-utility --is-fat input_file\n");
    printf("  mach-o-utility --contains input_file seg_name sect_name\n");
    printf("  mach-o-utility --extract seg_name sect_name input_file output_file\n");
    printf("  mach-o-utility --validate input_file_a input_file_b\n");
}

int check_file_fat(const char* file_name, bool* is_fat) {
    size_t magicsize = sizeof(uint32_t);
    uint8_t* fbuffer = NULL;
    int result = 0;
    
    FILE* f = fopen(file_name, "r");
    if (f == NULL) {
        result = UNABLE_TO_READ_FILE;
        goto check_file_fat_exit;
    }
    
    fbuffer = malloc(magicsize);
    if (fbuffer == NULL) {
        result = UNABLE_TO_ALLOCATE_MEMORY;
        goto check_file_fat_exit;
    }
    
    size_t readmagics = fread(fbuffer, magicsize, 1, f);
    if (readmagics != 1) {
        result = UNABLE_TO_READ_FILE;
        goto check_file_fat_exit;
    }
    
    uint32_t magic = *(uint32_t*)fbuffer;
    *is_fat = (magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
    
check_file_fat_exit:
    free(fbuffer);
    
    // Close file only if it was opened before
    // Overwrite result only if prevous operations succeeded
    if (f != NULL && fclose(f) != 0 && result == 0)
        result = UNABLE_TO_CLOSE_FILE;
    
    return result;
}

int file_size(const char* file_name, size_t* size) {
    struct stat file_stat;
    if (stat(file_name, &file_stat) != 0)
        return UNABLE_TO_OBTAIN_FILE_SIZE;
    
    *size = file_stat.st_size;
    
    return 0;
}

int read_file(const char* file_name, uint8_t** buffer, size_t* size) {
    size_t fsize;
    
    int file_size_result = file_size(file_name, &fsize);
    if (file_size_result != 0)
        return file_size_result;
    
    if (fsize == 0)
        return FILE_IS_EMPTY;
    
    uint8_t* fbuffer = NULL;
    int result = 0;
    
    FILE* f = fopen(file_name, "r");
    if (f == NULL) {
        result = UNABLE_TO_OPEN_FILE;
        goto read_file_exit;
    }
    
    fbuffer = malloc(fsize);
    if (fbuffer == NULL) {
        result = UNABLE_TO_ALLOCATE_MEMORY;
        goto read_file_exit;
    }
    
    size_t readbytes = fread(fbuffer, sizeof(uint8_t), fsize, f);
    if (readbytes != fsize) {
        result = UNABLE_TO_READ_FILE;
        goto read_file_exit;
    }
    
    *buffer = fbuffer;
    *size = fsize;
    
read_file_exit:
    // Free buffer only if an error occured
    if (result != 0)
        free(fbuffer);
    
    // Close file only if it was opened before
    // Overwrite result only if prevous operations succeeded
    if (f != NULL && fclose(f) != 0 && result == 0)
        result = UNABLE_TO_CLOSE_FILE;
    
    return result;
}

int write_file(const char* file_name, uint8_t* buffer, size_t size) {
    if (size == 0)
        return FILE_IS_EMPTY;
    
    FILE* f = fopen(file_name, "w+");
    if (f == NULL)
        return UNABLE_TO_OPEN_FILE;
    
    int result = 0;
    
    size_t writtenbytes = fwrite(buffer, sizeof(uint8_t), size, f);
    
    // We need to close file `f` in all cases after it was opened
    // so we memorize result of fwrite and continue with fclose.
    if (writtenbytes != size)
        result = UNABLE_TO_WRITE_FILE;
    
    // Overwrite result only if prevous operations succeeded
    if (fclose(f) != 0 && result == 0)
        result = UNABLE_TO_CLOSE_FILE;
    
    return result;
}

int read_lcs(uint8_t* buffer, size_t size, struct load_command*** cmds, size_t* cmds_count) {
    swap32func swap32;
    swap64func swap64;
    
    int swap_result = obtain_swap(buffer, size, &swap32, &swap64);
    if (swap_result != 0)
        return swap_result;
    
    if (sizeof(struct mach_header_64) > size)
        return UNEXPECTED_EOF;
    
    struct mach_header_64* header = (struct mach_header_64*)buffer;
    uint32_t ncmds = swap32(header->ncmds);
    
    struct load_command** result = calloc(ncmds, sizeof(struct load_command*));
    if (result == NULL)
        return UNABLE_TO_ALLOCATE_MEMORY;
    
    struct load_command* current_command;
    uint32_t cmd_size;
    
    uint8_t* current_offset = (uint8_t*)(header + 1);
    uint8_t* file_end = buffer + size;
    
    for (int i = 0; i < ncmds; i++) {
        if (current_offset + sizeof(struct load_command) > file_end) {
            free(result);
            return UNEXPECTED_EOF;
        }
        
        current_command = (struct load_command*)current_offset;
        cmd_size = swap32(current_command->cmdsize);
        
        result[i] = current_command;
        
        current_offset += cmd_size;
    }
    
    *cmds = result;
    *cmds_count = ncmds;
    
    return 0;
}

int read_sects(uint8_t* buffer, size_t size, struct load_command** cmds, size_t cmds_count, struct section_pointer** sects, size_t* sects_count) {
    swap32func swap32;
    swap64func swap64;
    
    int swap_result = obtain_swap(buffer, size, &swap32, &swap64);
    if (swap_result != 0)
        return swap_result;
    
    struct load_command* current_cmd;
    uint8_t* cmd_offset;
    uint32_t cmd;
    
    struct segment_command_64* segment_command_64;
    struct segment_command* segment_command;
    uint32_t nsects;
    uint8_t* sect_offset;
    bool is_section_64;
    size_t sect_step;
    
    uint8_t* file_end = buffer + size;
    
    struct section_pointer* result = calloc(MIN_ALLOCATION_CAPACITY, sizeof(struct section_pointer));
    if (result == NULL)
        return UNABLE_TO_ALLOCATE_MEMORY;
    
    size_t allocated_count = MIN_ALLOCATION_CAPACITY;
    size_t actual_count = 0;
    
    struct section_64* section_64;
    struct section* section;
    
    struct section_pointer* temp_result;
    
    for (int i = 0; i < cmds_count; i++) {
        current_cmd = cmds[i];
        cmd_offset = (uint8_t*)current_cmd;
        cmd = swap32(current_cmd->cmd);
        
        switch (cmd) {
            case LC_SEGMENT_64:
                if (cmd_offset + sizeof(struct segment_command_64) > file_end) {
                    free(result);
                    return UNEXPECTED_EOF;
                }
                
                segment_command_64 = (struct segment_command_64*)cmd_offset;
                nsects = swap32(segment_command_64->nsects);
                sect_offset = (uint8_t*)(segment_command_64 + 1);
                is_section_64 = true;
                sect_step = sizeof(struct section_64);
                
                break;
                
            case LC_SEGMENT:
                if (cmd_offset + sizeof(struct segment_command) > file_end) {
                    free(result);
                    return UNEXPECTED_EOF;
                }
                
                segment_command = (struct segment_command*)cmd_offset;
                nsects = swap32(segment_command->nsects);
                sect_offset = (uint8_t*)(segment_command + 1);
                is_section_64 = false;
                sect_step = sizeof(struct section);
                
                break;
                
            default:
                continue;
        }
        
        if (allocated_count < actual_count + nsects) {
            while (allocated_count < actual_count + nsects)
                allocated_count *= 2;
            
            temp_result = result;
            result = realloc(result, sizeof(struct section_pointer) * allocated_count);
            
            if (result == NULL) {
                free(temp_result);
                return UNABLE_TO_ALLOCATE_MEMORY;
            }
        }
        
        for (int j = 0; j < nsects; j++) {
            if (sect_offset + sect_step > file_end) {
                free(result);
                return UNEXPECTED_EOF;
            }
            
            result[actual_count].pointer = sect_offset;
            result[actual_count].is_64 = is_section_64;
            
            if (is_section_64) {
                section_64 = (struct section_64*)sect_offset;
                result[actual_count].segname = section_64->segname;
                result[actual_count].sectname = section_64->sectname;
                result[actual_count].offset = swap32(section_64->offset);
                result[actual_count].size = swap64(section_64->size);
            } else {
                section = (struct section*)sect_offset;
                result[actual_count].segname = section->segname;
                result[actual_count].sectname = section->sectname;
                result[actual_count].offset = swap32(section->offset);
                result[actual_count].size = swap32(section->size);
            }
            
            sect_offset += sect_step;
            actual_count++;
        }
    }
    
    if (allocated_count > actual_count) {
        temp_result = result;
        result = realloc(result, sizeof(struct section_pointer) * actual_count);
        
        if (result == NULL) {
            free(temp_result);
            return UNABLE_TO_ALLOCATE_MEMORY;
        }
    }
    
    *sects = result;
    *sects_count = actual_count;
    
    return 0;
}

int strip_lcs(uint8_t* buffer, size_t size, struct load_command** cmds, size_t cmds_count) {
    swap32func swap32;
    swap64func swap64;
    
    int swap_result = obtain_swap(buffer, size, &swap32, &swap64);
    if (swap_result != 0)
        return swap_result;
    
    uint8_t* current_offset;
    uint32_t cmd;
    
    uint8_t* file_end = buffer + size;
    
    for (int i = 0; i < cmds_count; i++) {
        current_offset = (uint8_t*)cmds[i];
        cmd = swap32(cmds[i]->cmd);
        switch (cmd) {
            case LC_UUID:
                if (current_offset + sizeof(struct uuid_command) > file_end)
                    return UNEXPECTED_EOF;
                
                memset(current_offset + offsetof(struct uuid_command, uuid), 0, 16);
                break;
            case LC_ID_DYLIB:
                if (current_offset + sizeof(struct dylib_command) > file_end)
                    return UNEXPECTED_EOF;
                
                memset(current_offset + offsetof(struct dylib_command, dylib) + offsetof(struct dylib, timestamp), 0, 4);
                break;
        }
    }
    
    return 0;
}

int strip_sects(uint8_t* buffer, size_t size, struct section_pointer* sects, size_t sects_count) {
    struct section_pointer sect_pointer;
    uint8_t* file_end = buffer + size;
    
    for (int i = 0; i < sects_count; i++) {
        sect_pointer = sects[i];
        
        if (buffer + sect_pointer.offset + sect_pointer.size > file_end)
            return UNEXPECTED_EOF;
        
        if (strcmp("__LLVM", sect_pointer.segname) == 0 && strcmp("__swift_modhash", sect_pointer.sectname) == 0) {
            memset(buffer + sect_pointer.offset, 0, sect_pointer.size);
        }
    }
    
    return 0;
}

int extract_sect(uint8_t* buffer, size_t size, const char* segname, const char* sectname, struct section_pointer* sects, size_t sects_count, uint32_t* sectoffset, uint64_t* sectsize) {
    struct section_pointer sect_pointer;
    uint8_t* file_end = buffer + size;
    
    for (int i = 0; i < sects_count; i++) {
        sect_pointer = sects[i];
        
        if (buffer + sect_pointer.offset + sect_pointer.size > file_end)
            return UNEXPECTED_EOF;
        
        if (strcmp(segname, sect_pointer.segname) == 0 && strcmp(sectname, sect_pointer.sectname) == 0) {
            *sectoffset = sect_pointer.offset;
            *sectsize = sect_pointer.size;
            return 0;
        }
    }
    
    return SECTION_IS_NOT_FOUND;
}

int obtain_swap(uint8_t* buffer, size_t size, swap32func* swap32, swap64func* swap64) {
    if (sizeof(uint32_t) > size)
        return UNEXPECTED_EOF;
    
    uint32_t magic = *(uint32_t*)buffer;
    switch (magic) {
        case MH_MAGIC_64:
            *swap32 = swap_little_to_host;
            *swap64 = swap_little_to_host_64;
            break;
        case MH_CIGAM_64:
            *swap32 = swap_big_to_host;
            *swap64 = swap_big_to_host_64;
            break;
        case MH_MAGIC:
        case MH_CIGAM:
            return FILE_IS_NOT_64_ORIENTED;
        default:
            return FILE_IS_NOT_MACH_O;
    }
    
    return 0;
}

uint32_t swap_big_to_host(uint32_t value) {
    return OSSwapBigToHostInt32(value);
}

uint32_t swap_little_to_host(uint32_t value) {
    return OSSwapLittleToHostInt32(value);
}

uint64_t swap_big_to_host_64(uint64_t value) {
    return OSSwapBigToHostInt64(value);
}

uint64_t swap_little_to_host_64(uint64_t value) {
    return OSSwapLittleToHostInt64(value);
}
