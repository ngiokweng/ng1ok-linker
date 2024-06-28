#pragma once

#include <string>
#include <vector>
#include <android/dlext.h>

#if defined(__aarch64__) || defined(__x86_64__)
#define USE_RELA 1
#endif

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&) = delete;      \
  void operator=(const TypeName&) = delete

#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName() = delete;                           \
  DISALLOW_COPY_AND_ASSIGN(TypeName)

typedef void (*linker_dtor_function_t)();
typedef void (*linker_ctor_function_t)(int, char**, char**);


template<typename T>
struct LinkedListEntry {
    LinkedListEntry<T>* next;
    T* element;
};

// ForwardInputIterator
template<typename T>
class LinkedListIterator {
public:
    LinkedListIterator() : entry_(nullptr) {}
    LinkedListIterator(const LinkedListIterator<T>& that) : entry_(that.entry_) {}
    explicit LinkedListIterator(LinkedListEntry<T>* entry) : entry_(entry) {}

    LinkedListIterator<T>& operator=(const LinkedListIterator<T>& that) {
        entry_ = that.entry_;
        return *this;
    }

    LinkedListIterator<T>& operator++() {
        entry_ = entry_->next;
        return *this;
    }

    T* const operator*() {
        return entry_->element;
    }

    bool operator==(const LinkedListIterator<T>& that) const {
        return entry_ == that.entry_;
    }

    bool operator!=(const LinkedListIterator<T>& that) const {
        return entry_ != that.entry_;
    }

private:
    LinkedListEntry<T> *entry_;
};

/*
 * Represents linked list of objects of type T
 */
template<typename T, typename Allocator>
class LinkedList {
public:
    typedef LinkedListIterator<T> iterator;
    typedef T* value_type;

    LinkedList() : head_(nullptr), tail_(nullptr) {}
    ~LinkedList() {
        clear();
    }

    LinkedList(LinkedList&& that) {
        this->head_ = that.head_;
        this->tail_ = that.tail_;
        that.head_ = that.tail_ = nullptr;
    }

    void push_front(T* const element) {
        LinkedListEntry<T>* new_entry = Allocator::alloc();
        new_entry->next = head_;
        new_entry->element = element;
        head_ = new_entry;
        if (tail_ == nullptr) {
            tail_ = new_entry;
        }
    }

    void push_back(T* const element) {
        LinkedListEntry<T>* new_entry = Allocator::alloc();
        new_entry->next = nullptr;
        new_entry->element = element;
        if (tail_ == nullptr) {
            tail_ = head_ = new_entry;
        } else {
            tail_->next = new_entry;
            tail_ = new_entry;
        }
    }

    T* pop_front() {
        if (head_ == nullptr) {
            return nullptr;
        }

        LinkedListEntry<T>* entry = head_;
        T* element = entry->element;
        head_ = entry->next;
        Allocator::free(entry);

        if (head_ == nullptr) {
            tail_ = nullptr;
        }

        return element;
    }

    T* front() const {
        if (head_ == nullptr) {
            return nullptr;
        }

        return head_->element;
    }

    void clear() {
        while (head_ != nullptr) {
            LinkedListEntry<T>* p = head_;
            head_ = head_->next;
            Allocator::free(p);
        }

        tail_ = nullptr;
    }

    bool empty() {
        return (head_ == nullptr);
    }

    template<typename F>
    void for_each(F action) const {
        visit([&] (T* si) {
            action(si);
            return true;
        });
    }

    template<typename F>
    bool visit(F action) const {
        for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
            if (!action(e->element)) {
                return false;
            }
        }
        return true;
    }

    template<typename F>
    void remove_if(F predicate) {
        for (LinkedListEntry<T>* e = head_, *p = nullptr; e != nullptr;) {
            if (predicate(e->element)) {
                LinkedListEntry<T>* next = e->next;
                if (p == nullptr) {
                    head_ = next;
                } else {
                    p->next = next;
                }

                if (tail_ == e) {
                    tail_ = p;
                }

                Allocator::free(e);

                e = next;
            } else {
                p = e;
                e = e->next;
            }
        }
    }

    void remove(T* element) {
        remove_if([&](T* e) {
            return e == element;
        });
    }

    template<typename F>
    T* find_if(F predicate) const {
        for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
            if (predicate(e->element)) {
                return e->element;
            }
        }

        return nullptr;
    }

    iterator begin() const {
        return iterator(head_);
    }

    iterator end() const {
        return iterator(nullptr);
    }

    iterator find(T* value) const {
        for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
            if (e->element == value) {
                return iterator(e);
            }
        }

        return end();
    }

    size_t copy_to_array(T* array[], size_t array_length) const {
        size_t sz = 0;
        for (LinkedListEntry<T>* e = head_; sz < array_length && e != nullptr; e = e->next) {
            array[sz++] = e->element;
        }

        return sz;
    }

    bool contains(const T* el) const {
        for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
            if (e->element == el) {
                return true;
            }
        }
        return false;
    }

    static LinkedList make_list(T* const element) {
        LinkedList<T, Allocator> one_element_list;
        one_element_list.push_back(element);
        return one_element_list;
    }

private:
    LinkedListEntry<T>* head_;
    LinkedListEntry<T>* tail_;
    DISALLOW_COPY_AND_ASSIGN(LinkedList);
};


struct soinfo;

class SoinfoListAllocator {
public:
    static LinkedListEntry<soinfo>* alloc();
    static void free(LinkedListEntry<soinfo>* entry);

private:
    // unconstructable
    DISALLOW_IMPLICIT_CONSTRUCTORS(SoinfoListAllocator);
};

class NamespaceListAllocator {
public:
    static LinkedListEntry<android_namespace_t>* alloc();
    static void free(LinkedListEntry<android_namespace_t>* entry);

private:
    // unconstructable
    DISALLOW_IMPLICIT_CONSTRUCTORS(NamespaceListAllocator);
};

typedef LinkedList<soinfo, SoinfoListAllocator> soinfo_list_t;
typedef LinkedList<android_namespace_t, NamespaceListAllocator> android_namespace_list_t;


class SymbolName {
public:
    explicit SymbolName(const char* name)
            : name_(name), has_elf_hash_(false), has_gnu_hash_(false),
              elf_hash_(0), gnu_hash_(0) { }

    const char* get_name() {
        return name_;
    }

    uint32_t elf_hash();
    uint32_t gnu_hash();

private:
    const char* name_;
    bool has_elf_hash_;
    bool has_gnu_hash_;
    uint32_t elf_hash_;
    uint32_t gnu_hash_;

    DISALLOW_IMPLICIT_CONSTRUCTORS(SymbolName);
};


struct soinfo {
#if defined(__work_around_b_24465209__)
    private:
  char old_name_[SOINFO_NAME_LEN];
#endif
public:
    const ElfW(Phdr)* phdr;
    size_t phnum;
#if defined(__work_around_b_24465209__)
    ElfW(Addr) unused0; // DO NOT USE, maintained for compatibility.
#endif
    ElfW(Addr) base;
    size_t size;

#if defined(__work_around_b_24465209__)
    uint32_t unused1;  // DO NOT USE, maintained for compatibility.
#endif

    ElfW(Dyn)* dynamic;

#if defined(__work_around_b_24465209__)
    uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility
#endif

    soinfo* next;
public:
    uint32_t flags_;

    const char* strtab_;
    ElfW(Sym)* symtab_;

    size_t nbucket_;
    size_t nchain_;
    uint32_t* bucket_;
    uint32_t* chain_;

#if defined(__mips__) || !defined(__LP64__)
    // This is only used by mips and mips64, but needs to be here for
    // all 32-bit architectures to preserve binary compatibility.
    ElfW(Addr)** plt_got_;
#endif

#if defined(USE_RELA)
    ElfW(Rela)* plt_rela_;
  size_t plt_rela_count_;

  ElfW(Rela)* rela_;
  size_t rela_count_;
#else
    ElfW(Rel)* plt_rel_;
    size_t plt_rel_count_;

    ElfW(Rel)* rel_;
    size_t rel_count_;
#endif

    linker_ctor_function_t* preinit_array_;
    size_t preinit_array_count_;

    linker_ctor_function_t* init_array_;
    size_t init_array_count_;
    linker_dtor_function_t* fini_array_;
    size_t fini_array_count_;

    linker_ctor_function_t init_func_;
    linker_dtor_function_t fini_func_;

#if defined(__arm__)
    public:
  // ARM EABI section used for stack unwinding.
  uint32_t* ARM_exidx;
  size_t ARM_exidx_count;
 private:
#elif defined(__mips__)
    uint32_t mips_symtabno_;
  uint32_t mips_local_gotno_;
  uint32_t mips_gotsym_;
  bool mips_relocate_got(const VersionTracker& version_tracker,
                         const soinfo_list_t& global_group,
                         const soinfo_list_t& local_group);
#if !defined(__LP64__)
  bool mips_check_and_adjust_fp_modes();
#endif
#endif
    size_t ref_count_;
public:
    link_map link_map_head;

    bool constructors_called;

    // When you read a virtual address from the ELF file, add this
    // value to get the corresponding address in the process' address space.
    ElfW(Addr) load_bias;

#if !defined(__LP64__)
    bool has_text_relocations;
#endif
    bool has_DT_SYMBOLIC;


    bool inline has_min_version(uint32_t min_version __unused) const {
#if defined(__work_around_b_24465209__)
        return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
#else
        return true;
#endif
    }

    bool is_linked() const;
    bool is_linker() const;
    bool is_main_executable() const;

    void set_linked();
    void set_linker_flag();
    void set_main_executable();
    void set_nodelete();

    void increment_ref_count();
    size_t decrement_ref_count();

    soinfo* get_local_group_root() const;

    void set_soname(const char* soname);
    const char* get_soname() const;
    const char* get_realpath() const;
    const ElfW(Versym)* get_versym(size_t n) const;
    ElfW(Addr) get_verneed_ptr() const;
    size_t get_verneed_cnt() const;
    ElfW(Addr) get_verdef_ptr() const;
    size_t get_verdef_cnt() const;

    uint32_t get_target_sdk_version() const;

    void set_dt_runpath(const char *);
    const std::vector<std::string>& get_dt_runpath() const;
    android_namespace_t* get_primary_namespace();
    void add_secondary_namespace(android_namespace_t* secondary_ns);
    android_namespace_list_t& get_secondary_namespaces();

    void set_mapped_by_caller(bool reserved_map);
    bool is_mapped_by_caller() const;

    uintptr_t get_handle() const;
    void generate_handle();
    void* to_handle();


public:
    // This part of the structure is only available
    // when FLAG_NEW_SOINFO is set in this->flags.
    uint32_t version_;

    // version >= 0
    dev_t st_dev_;
    ino_t st_ino_;

    // dependency graph
    soinfo_list_t children_;
    soinfo_list_t parents_;

    // version >= 1
    off64_t file_offset_;
    uint32_t rtld_flags_;
    uint32_t dt_flags_1_;
    size_t strtab_size_;

    // version >= 2

    size_t gnu_nbucket_;
    uint32_t* gnu_bucket_;
    uint32_t* gnu_chain_;
    uint32_t gnu_maskwords_;
    uint32_t gnu_shift2_;
    ElfW(Addr)* gnu_bloom_filter_;

    soinfo* local_group_root_;

    uint8_t* android_relocs_;
    size_t android_relocs_size_;

    const char* soname_;
    std::string realpath_;

    const ElfW(Versym)* versym_;

    ElfW(Addr) verdef_ptr_;
    size_t verdef_cnt_;

    ElfW(Addr) verneed_ptr_;
    size_t verneed_cnt_;

    uint32_t target_sdk_version_;

    // version >= 3
    std::vector<std::string> dt_runpath_;
    void* primary_namespace_;
    android_namespace_list_t secondary_namespaces_;
    uintptr_t handle_;

    friend soinfo* get_libdl_info(const char* linker_path, const link_map& linker_map);


public:
    const char* get_string(ElfW(Word) index) const ;
    void set_dt_flags_1(uint32_t dt_flags_1) ;


    bool prelink_image();
    void fortest() {
        LOGD("gnu_bloom_filter_ = %lx", gnu_bloom_filter_);
    };

    bool link_image();

    template<typename ElfRelIteratorT>

    bool relocate(ElfRelIteratorT&& rel_iterator);

    bool find_symbol_by_name(SymbolName& symbol_name, const ElfW(Sym)** symbol) const;

    bool is_gnu_hash() const;

    bool elf_lookup(SymbolName& symbol_name, uint32_t* symbol_index) const;

    bool gnu_lookup(SymbolName& symbol_name, uint32_t* symbol_index) const;

    ElfW(Addr) resolve_symbol_address(const ElfW(Sym)* s) const;

    void call_constructors();

    bool protect_relro();
};
