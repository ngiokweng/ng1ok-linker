//
// Created by user on 2024/6/15.
//
#pragma once

#include <stdlib.h>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "log.h"
#include <jni.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include "soinfo.h"

//#define __LP64__  1
#define PROT_READ 0x1
#define MAP_PRIVATE 0x02
#define PR_SET_VMA   0x53564d41
#define PR_SET_VMA_ANON_NAME    0
#define FLAG_LINKER           0x00000010 // The linker itself
#define FLAG_GNU_HASH         0x00000040 // uses gnu hash
#define SUPPORTED_DT_FLAGS_1 (DF_1_NOW | DF_1_GLOBAL | DF_1_NODELETE | DF_1_PIE)
#define R_GENERIC_NONE 0
#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE
#define R_AARCH64_TLS_TPREL64           1030
#define R_AARCH64_TLS_DTPREL32          1031



#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
#define powerof2(x) ((((x)-1)&(x))==0)
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what
#else
#define ELFW(what) ELF32_ ## what
#endif

// Android uses RELA for LP64.
// from: https://blog.xhyeax.com/2022/06/08/android-arm64-got-hook-rela-plt/
//#if defined(__LP64__)
//#define USE_RELA 1
//#endif


class soinfo;

constexpr off64_t kPageMask = ~static_cast<off64_t>(PAGE_SIZE-1);
typedef void (*linker_ctor_function_t)(int, char**, char**);
typedef void (*linker_dtor_function_t)();


class plain_reloc_iterator {
#if defined(USE_RELA)
    typedef ElfW(Rela) rel_t;
#else
    typedef ElfW(Rel) rel_t;
#endif
public:
    plain_reloc_iterator(rel_t* rel_array, size_t count)
            : begin_(rel_array), end_(begin_ + count), current_(begin_) {}

    bool has_next() {
        return current_ < end_;
    }

    rel_t* next() {
        return current_++;
    }
private:
    rel_t* const begin_;
    rel_t* const end_;
    rel_t* current_;

};


class sleb128_decoder {
public:
    sleb128_decoder(const uint8_t* buffer, size_t count)
            : current_(buffer), end_(buffer+count) { }

    size_t pop_front() {
        size_t value = 0;
        static const size_t size = CHAR_BIT * sizeof(value);

        size_t shift = 0;
        uint8_t byte;

        do {
            if (current_ >= end_) {
                LOGE("sleb128_decoder ran out of bounds");
            }
            byte = *current_++;
            value |= (static_cast<size_t>(byte & 127) << shift);
            shift += 7;
        } while (byte & 128);

        if (shift < size && (byte & 64)) {
            value |= -(static_cast<size_t>(1) << shift);
        }

        return value;
    }

private:
    const uint8_t* current_;
    const uint8_t* const end_;
};


const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;
template <typename decoder_t>
class packed_reloc_iterator {
#if defined(USE_RELA)
    typedef ElfW(Rela) rel_t;
#else
    typedef ElfW(Rel) rel_t;
#endif
public:
    explicit packed_reloc_iterator(decoder_t&& decoder)
            : decoder_(decoder) {
        // initialize fields
        memset(&reloc_, 0, sizeof(reloc_));
        relocation_count_ = decoder_.pop_front();
        reloc_.r_offset = decoder_.pop_front();
        relocation_index_ = 0;
        relocation_group_index_ = 0;
        group_size_ = 0;
    }

    bool has_next() const {
        return relocation_index_ < relocation_count_;
    }

    rel_t* next() {
        if (relocation_group_index_ == group_size_) {
            if (!read_group_fields()) {
                // Iterator is inconsistent state; it should not be called again
                // but in case it is let's make sure has_next() returns false.
                relocation_index_ = relocation_count_ = 0;
                return nullptr;
            }
        }

        if (is_relocation_grouped_by_offset_delta()) {
            reloc_.r_offset += group_r_offset_delta_;
        } else {
            reloc_.r_offset += decoder_.pop_front();
        }

        if (!is_relocation_grouped_by_info()) {
            reloc_.r_info = decoder_.pop_front();
        }

#if defined(USE_RELA)
        if (is_relocation_group_has_addend() &&
        !is_relocation_grouped_by_addend()) {
      reloc_.r_addend += decoder_.pop_front();
    }
#endif

        relocation_index_++;
        relocation_group_index_++;

        return &reloc_;
    }
private:
    bool read_group_fields() {
        group_size_ = decoder_.pop_front();
        group_flags_ = decoder_.pop_front();

        if (is_relocation_grouped_by_offset_delta()) {
            group_r_offset_delta_ = decoder_.pop_front();
        }

        if (is_relocation_grouped_by_info()) {
            reloc_.r_info = decoder_.pop_front();
        }

        if (is_relocation_group_has_addend() &&
            is_relocation_grouped_by_addend()) {
#if !defined(USE_RELA)
            // This platform does not support rela, and yet we have it encoded in android_rel section.
            LOGE("unexpected r_addend in android.rel section");
            return false;
#else
            reloc_.r_addend += decoder_.pop_front();
    } else if (!is_relocation_group_has_addend()) {
      reloc_.r_addend = 0;
#endif
        }

        relocation_group_index_ = 0;
        return true;
    }

    bool is_relocation_grouped_by_info() {
        return (group_flags_ & RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
    }

    bool is_relocation_grouped_by_offset_delta() {
        return (group_flags_ & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
    }

    bool is_relocation_grouped_by_addend() {
        return (group_flags_ & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
    }

    bool is_relocation_group_has_addend() {
        return (group_flags_ & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;
    }

    decoder_t decoder_;
    size_t relocation_count_;
    size_t group_size_;
    size_t group_flags_;
    size_t group_r_offset_delta_;
    size_t relocation_index_;
    size_t relocation_group_index_;
    rel_t reloc_;
};


class Utils {
public:
    static size_t page_offset(off64_t offset) ;

    static off64_t page_start(off64_t offset) ;

    static bool safe_add(off64_t* out, off64_t a, size_t b);

    static void* getMapData(int fd, off64_t base_offset, size_t elf_offset, size_t size);

    static void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
            ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
    ElfW(Word)* dynamic_flags) ;

    static soinfo* get_soinfo(const char* so_name);


    static ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr);

    static ElfW(Addr) get_addend(ElfW(Rela)* rela, ElfW(Addr) reloc_addr __unused);

    static ElfW(Addr) get_export_func(char* path, char* func_name);

    static int phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                             ElfW(Addr) load_bias, int prot_flags);
};




class MyLoader {
private:
    int fd_;
    off64_t file_offset_;
    off64_t file_size_;
    ElfW(Ehdr) header_;
    size_t phdr_num_;
    const ElfW(Phdr)* phdr_table_;
    size_t shdr_num_;
    const ElfW(Shdr)* shdr_table_;
    const ElfW(Dyn)* dynamic_;
    const char* strtab_;
    size_t strtab_size_;
    std::string name_;
    void* load_start_;
    size_t load_size_;
    ElfW(Addr) load_bias_;
    void* start_addr_;
    const ElfW(Phdr)* loaded_phdr_;
    soinfo* si_;

public:
    MyLoader(): fd_(-1), file_offset_(0), file_size_(0), phdr_num_(0),
                phdr_table_(nullptr), shdr_table_(nullptr), shdr_num_(0), dynamic_(nullptr), strtab_(nullptr),
                strtab_size_(0), load_start_(nullptr), load_size_(0) {
    }
    size_t phdr_count() const { return phdr_num_; }
    ElfW(Addr) load_start() const { return reinterpret_cast<ElfW(Addr)>(load_start_); }
    size_t load_size() const { return load_size_; }
    ElfW(Addr) load_bias() const { return load_bias_; }
    const ElfW(Phdr)* loaded_phdr() const { return loaded_phdr_; }

public:

    bool Read(const char* name, int fd, off64_t file_offset, off64_t file_size);

    bool ReadElfHeader();

    bool ReadProgramHeaders();


    bool Load();

    bool ReserveAddressSpace();

    size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
            ElfW(Addr)* out_min_vaddr);

    bool LoadSegments();

    bool FindPhdr();

    bool CheckPhdr(ElfW(Addr) loaded);

    const char* get_string(ElfW(Word) index) const;

    void run(const char* path);


};


