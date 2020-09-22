import { Encoder, stringToUtf8 } from './encoder.js'
import * as fs from 'fs'

const MH_MAGIC = 0xfeedface /* the mach magic number */
const MH_MAGIC_64 = 0xfeedfacf /* the 64-bit mach magic number */
const CPU_ARCH_MASK = 0xff000000      /* mask for architecture bits */
const CPU_ARCH_ABI64 = 0x01000000      /* 64 bit ABI */
const CPU_ARCH_ABI64_32 = 0x02000000      /* ABI for 64-bit hardware with 32-bit types; LP32 */
const CPU_TYPE_ANY = -1
const CPU_TYPE_X86 = 7
const CPU_TYPE_X86_64 = (CPU_TYPE_X86 | CPU_ARCH_ABI64)
const CPU_SUBTYPE_MULTIPLE = -1
const CPU_SUBTYPE_X86_ALL = 3
const CPU_SUBTYPE_X86_64_ALL = 3
const CPU_SUBTYPE_MASK = 0xff000000      /* mask for feature flags */
const CPU_SUBTYPE_LIB64 = 0x80000000      /* 64 bit libraries */
const MH_DYLIB = 0x6 /* dynamically bound shared library */


/* Constants for the flags field of the mach_header */
const MH_NOUNDEFS     = 0x1             /* the object file has no undefined
                                           references */
const MH_INCRLINK     = 0x2             /* the object file is the output of an
                                           incremental link against a base file
                                           and can't be link edited again */
const MH_DYLDLINK     = 0x4             /* the object file is input for the
                                           dynamic linker and can't be staticly
                                           link edited again */
const MH_BINDATLOAD   = 0x8             /* the object file's undefined
                                           references are bound by the dynamic
                                           linker when loaded. */
const MH_PREBOUND     = 0x10            /* the file has its dynamic undefined
                                           references prebound. */
const MH_SPLIT_SEGS   = 0x20            /* the file has its read-only and
                                           read-write segments split */
const MH_LAZY_INIT    = 0x40            /* the shared library init routine is
                                           to be run lazily via catching memory
                                           faults to its writeable segments
                                           (obsolete) */
const MH_TWOLEVEL     = 0x80            /* the image is using two-level name
                                           space bindings */
const MH_FORCE_FLAT   = 0x100           /* the executable is forcing all images
                                           to use flat name space bindings */
const MH_NOMULTIDEFS  = 0x200           /* this umbrella guarantees no multiple
                                           defintions of symbols in its
                                           sub-images so the two-level namespace
                                           hints can always be used. */
const MH_NOFIXPREBINDING = 0x400        /* do not have dyld notify the
                                           prebinding agent about this
                                           executable */
const MH_PREBINDABLE  = 0x800           /* the binary is not prebound but can
                                           have its prebinding redone. only used
                                           when MH_PREBOUND is not set. */
const MH_ALLMODSBOUND = 0x1000          /* indicates that this binary binds to
                                           all two-level namespace modules of
                                           its dependent libraries. only used
                                           when MH_PREBINDABLE and MH_TWOLEVEL
                                           are both set. */ 
const MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000/* safe to divide up the sections into
                                            sub-sections via symbols for dead
                                            code stripping */
const MH_CANONICAL    = 0x4000          /* the binary has been canonicalized
                                           via the unprebind operation */
const MH_WEAK_DEFINES = 0x8000          /* the final linked image contains
                                           external weak symbols */
const MH_BINDS_TO_WEAK = 0x10000        /* the final linked image uses
                                           weak symbols */

const MH_ALLOW_STACK_EXECUTION = 0x20000/* When this bit is set, all stacks 
                                           in the task will be given stack
                                           execution privilege.  Only used in
                                           MH_EXECUTE filetypes. */
const MH_ROOT_SAFE = 0x40000           /* When this bit is set, the binary 
                                          declares it is safe for use in
                                          processes with uid zero */
                                         
const MH_SETUID_SAFE = 0x80000         /* When this bit is set, the binary 
                                          declares it is safe for use in
                                          processes when issetugid() is true */

const MH_NO_REEXPORTED_DYLIBS = 0x100000 /* When this bit is set on a dylib, 
                                          the static linker does not need to
                                          examine dependent dylibs to see
                                          if any are re-exported */
const MH_PIE = 0x200000                 /* When this bit is set, the OS will
                                           load the main executable at a
                                           random address.  Only used in
                                           MH_EXECUTE filetypes. */
const MH_DEAD_STRIPPABLE_DYLIB = 0x400000 /* Only for use on dylibs.  When
                                             linking against a dylib that
                                             has this bit set, the static linker
                                             will automatically not create a
                                             LC_LOAD_DYLIB load command to the
                                             dylib if no symbols are being
                                             referenced from the dylib. */
const MH_HAS_TLV_DESCRIPTORS = 0x800000 /* Contains a section of type 
                                            S_THREAD_LOCAL_VARIABLES */

const MH_NO_HEAP_EXECUTION = 0x1000000  /* When this bit is set, the OS will
                                           run the main executable with
                                           a non-executable heap even on
                                           platforms (e.g. i386) that don't
                                           require it. Only used in MH_EXECUTE
                                           filetypes. */

const MH_APP_EXTENSION_SAFE = 0x02000000 /* The code was linked for use in an
                                            application extension. */

const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000 /* The external symbols
                                           listed in the nlist symbol table do
                                           not include all the symbols listed in
                                           the dyld info. */

const MH_SIM_SUPPORT = 0x08000000       /* Allow LC_MIN_VERSION_MACOS and
                                           LC_BUILD_VERSION load commands with
                                           the platforms macOS, macCatalyst,
                                           iOSSimulator, tvOSSimulator and
                                           watchOSSimulator. */

const MH_DYLIB_IN_CACHE = 0x80000000    /* Only for use on dylibs. When this bit
                                           is set, the dylib is part of the dyld
                                           shared cache, rather than loose in
                                           the filesystem. */

function writeMacho64Header(e, {cpuType, cpuSubtype, fileType, flags, ncmds, sizeofcmds}) {
  //  struct mach_header_64 {
  //    uint32_t        magic;          /* mach magic number identifier */
  e.writeUInt32LE(MH_MAGIC_64)
  //    cpu_type_t      cputype;        /* cpu specifier */
  e.writeInt32LE(cpuType)
  //    cpu_subtype_t   cpusubtype;     /* machine specifier */
  e.writeInt32LE(cpuSubtype)
  //    uint32_t        filetype;       /* type of file */
  e.writeUInt32LE(fileType)
  //    uint32_t        ncmds;          /* number of load commands */
  e.writeUInt32LE(ncmds)
  //    uint32_t        sizeofcmds;     /* the size of all the load commands */
  e.writeUInt32LE(sizeofcmds)
  //    uint32_t        flags;          /* flags */
  e.writeUInt32LE(flags)
  //    uint32_t        reserved;       /* reserved */
  e.writeUInt32LE(0)
  //  };
}

function writeMacho64File(e, opts, cmds) {
  writeMacho64Header(e, {...opts, ncmds: cmds.length, sizeofcmds: cmds.reduce((m, o) => m + o.byteLength, 0)})
  for (const cmd of cmds) {
    e.append(cmd)
  }
}

function writeLoadCommand(e, cmdType, buf) {
  e.writeUInt32LE(cmdType)
  // round up to nearest multiple of 8
  const cmdsize = (buf.byteLength + 7) >> 3 << 3
  e.writeUInt32LE(8 + cmdsize)
  e.append(buf)
  const padding = cmdsize - buf.byteLength
  for (let i = 0; i < padding; i++) {
    e.writeByte(0)
  }
}

function writeLoadCommand_ID_DYLIB(e, name, {timestamp = 0, currentVersion = 0, compatibilityVersion = 0} = {}) {
  const cmd = new Encoder
  // struct dylib_command {
  //    uint32_t        cmd;            /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
  //                                       LC_REEXPORT_DYLIB */
  //    uint32_t        cmdsize;        /* includes pathname string */
  //    struct dylib    dylib;          /* the library identification */
  // };
  //
  // /*
  //  * Dynamicly linked shared libraries are identified by two things.  The
  //  * pathname (the name of the library as found for execution), and the
  //  * compatibility version number.  The pathname must match and the compatibility
  //  * number in the user of the library must be greater than or equal to the
  //  * library being used.  The time stamp is used to record the time a library was
  //  * built and copied into user so it can be use to determined if the library used
  //  * at runtime is exactly the same as used to built the program.
  //  */
  // struct dylib {
  //     union lc_str  name;                    /* library's path name */
  cmd.writeUInt32LE(24)
  //     uint32_t timestamp;                    /* library's build time stamp */
  cmd.writeUInt32LE(timestamp)
  //     uint32_t current_version;              /* library's current version number */
  cmd.writeUInt32LE(currentVersion)
  //     uint32_t compatibility_version;        /* library's compatibility vers number*/
  cmd.writeUInt32LE(compatibilityVersion)
  // };
  cmd.writeUtf8(name)
  const LC_ID_DYLIB = 0xd /* dynamically linked shared lib ident */
  writeLoadCommand(e, LC_ID_DYLIB, cmd.buffer)
}

function LC_ID_DYLIB(name) {
  const e = new Encoder
  writeLoadCommand_ID_DYLIB(e, name)
  return e.buffer
}

function writeLoadCommand_SEGMENT_64(e, {segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sections, flags}) {
  const cmd = new Encoder
  // /*
  //  * The 64-bit segment load command indicates that a part of this file is to be
  //  * mapped into a 64-bit task's address space.  If the 64-bit segment has
  //  * sections then section_64 structures directly follow the 64-bit segment
  //  * command and their size is reflected in cmdsize.
  //  */
  // struct segment_command_64 { /* for 64-bit architectures */
  //    uint32_t        cmd;            /* LC_SEGMENT_64 */
  //    uint32_t        cmdsize;        /* includes sizeof section_64 structs */
  //    char            segname[16];    /* segment name */
  cmd.writeUtf8(segname)
  while (cmd.offset < 16) cmd.writeByte(0)
  //    uint64_t        vmaddr;         /* memory address of this segment */
  cmd.writeBigUInt64LE(vmaddr)
  //    uint64_t        vmsize;         /* memory size of this segment */
  cmd.writeBigUInt64LE(vmsize)
  //    uint64_t        fileoff;        /* file offset of this segment */
  cmd.writeBigUInt64LE(fileoff)
  //    uint64_t        filesize;       /* amount to map from the file */
  cmd.writeBigUInt64LE(filesize)
  //    vm_prot_t       maxprot;        /* maximum VM protection */
  cmd.writeUInt32LE(maxprot)
  //    vm_prot_t       initprot;       /* initial VM protection */
  cmd.writeUInt32LE(initprot)
  //    uint32_t        nsects;         /* number of sections in segment */
  cmd.writeUInt32LE(sections.length)
  //    uint32_t        flags;          /* flags */
  cmd.writeUInt32LE(flags)
  // };

  for (const section of sections) {
    cmd.append(section)
  }

  const LC_SEGMENT_64 = 0x19
  writeLoadCommand(e, LC_SEGMENT_64, cmd.buffer)
}

function LC_SEGMENT_64(opts) {
  const e = new Encoder
  writeLoadCommand_SEGMENT_64(e, opts)
  return e.buffer
}

function writeNlistEntry(e, {strx, type, sect, desc, value}) {
  // /*
  //  * This is the symbol table entry structure for 64-bit architectures.
  //  */
  // struct nlist_64 {
  //     union {
  //         uint32_t  n_strx; /* index into the string table */
  //     } n_un;
  e.writeUInt32LE(strx)
  //     uint8_t n_type;        /* type flag, see below */
  e.writeByte(type)
  //     uint8_t n_sect;        /* section number or NO_SECT */
  e.writeByte(sect)
  //     uint16_t n_desc;       /* see <mach-o/stab.h> */
  e.writeUInt16LE(desc)
  //     uint64_t n_value;      /* value of this symbol (or stab offset) */
  e.writeBigUInt64LE(value)
  // };
}

function writeStringTable(e, strings) {
  for (const string of strings) {
    e.writeUtf8(string)
    e.writeByte(0)
  }
}

function writeLoadCommand_SYMTAB(e, {symoff, nsyms, stroff, strsize}) {
  const cmd = new Encoder
  // /*
  //  * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
  //  * "stab" style symbol table information as described in the header files
  //  * <nlist.h> and <stab.h>.
  //  */
  // struct symtab_command {
  //    uint32_t        cmd;            /* LC_SYMTAB */
  //    uint32_t        cmdsize;        /* sizeof(struct symtab_command) */
  //    uint32_t        symoff;         /* symbol table offset */
  cmd.writeUInt32LE(symoff)
  //    uint32_t        nsyms;          /* number of symbol table entries */
  cmd.writeUInt32LE(nsyms)
  //    uint32_t        stroff;         /* string table offset */
  cmd.writeUInt32LE(stroff)
  //    uint32_t        strsize;        /* string table size in bytes */
  cmd.writeUInt32LE(strsize)
  // };
  const LC_SYMTAB = 0x2 /* link-edit stab symbol table info */
  writeLoadCommand(e, LC_SYMTAB, cmd.buffer)
}

function LC_SYMTAB(opts) {
  const e = new Encoder
  writeLoadCommand_SYMTAB(e, opts)
  return e.buffer
}

function writeLoadCommand_DYSYMTAB(e, {ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym, tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsymoff, nindirectsyms, extreloff, nextrel, locreloff, nlocrel}) {
  const cmd = new Encoder
  // struct dysymtab_command {
  //     uint32_t cmd;  /* LC_DYSYMTAB */
  //     uint32_t cmdsize;      /* sizeof(struct dysymtab_command) */
  // 
  //     /*
  //      * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
  //      * are grouped into the following three groups:
  //      *    local symbols (further grouped by the module they are from)
  //      *    defined external symbols (further grouped by the module they are from)
  //      *    undefined symbols
  //      *
  //      * The local symbols are used only for debugging.  The dynamic binding
  //      * process may have to use them to indicate to the debugger the local
  //      * symbols for a module that is being bound.
  //      *
  //      * The last two groups are used by the dynamic binding process to do the
  //      * binding (indirectly through the module table and the reference symbol
  //      * table when this is a dynamically linked shared library file).
  //      */
  //     uint32_t ilocalsym;    /* index to local symbols */
  cmd.writeUInt32LE(ilocalsym)
  //     uint32_t nlocalsym;    /* number of local symbols */
  cmd.writeUInt32LE(nlocalsym)
  // 
  //     uint32_t iextdefsym;/* index to externally defined symbols */
  cmd.writeUInt32LE(iextdefsym)
  //     uint32_t nextdefsym;/* number of externally defined symbols */
  cmd.writeUInt32LE(nextdefsym)
  // 
  //     uint32_t iundefsym;    /* index to undefined symbols */
  cmd.writeUInt32LE(iundefsym)
  //     uint32_t nundefsym;    /* number of undefined symbols */
  cmd.writeUInt32LE(nundefsym)
  // 
  //     /*
  //      * For the for the dynamic binding process to find which module a symbol
  //      * is defined in the table of contents is used (analogous to the ranlib
  //      * structure in an archive) which maps defined external symbols to modules
  //      * they are defined in.  This exists only in a dynamically linked shared
  //      * library file.  For executable and object modules the defined external
  //      * symbols are sorted by name and is use as the table of contents.
  //      */
  //     uint32_t tocoff;       /* file offset to table of contents */
  cmd.writeUInt32LE(tocoff)
  //     uint32_t ntoc; /* number of entries in table of contents */
  cmd.writeUInt32LE(ntoc)
  // 
  //     /*
  //      * To support dynamic binding of "modules" (whole object files) the symbol
  //      * table must reflect the modules that the file was created from.  This is
  //      * done by having a module table that has indexes and counts into the merged
  //      * tables for each module.  The module structure that these two entries
  //      * refer to is described below.  This exists only in a dynamically linked
  //      * shared library file.  For executable and object modules the file only
  //      * contains one module so everything in the file belongs to the module.
  //      */
  //     uint32_t modtaboff;    /* file offset to module table */
  cmd.writeUInt32LE(modtaboff)
  //     uint32_t nmodtab;      /* number of module table entries */
  cmd.writeUInt32LE(nmodtab)
  // 
  //     /*
  //      * To support dynamic module binding the module structure for each module
  //      * indicates the external references (defined and undefined) each module
  //      * makes.  For each module there is an offset and a count into the
  //      * reference symbol table for the symbols that the module references.
  //      * This exists only in a dynamically linked shared library file.  For
  //      * executable and object modules the defined external symbols and the
  //      * undefined external symbols indicates the external references.
  //      */
  //     uint32_t extrefsymoff; /* offset to referenced symbol table */
  cmd.writeUInt32LE(extrefsymoff)
  //     uint32_t nextrefsyms;  /* number of referenced symbol table entries */
  cmd.writeUInt32LE(nextrefsyms)
  // 
  //     /*
  //      * The sections that contain "symbol pointers" and "routine stubs" have
  //      * indexes and (implied counts based on the size of the section and fixed
  //      * size of the entry) into the "indirect symbol" table for each pointer
  //      * and stub.  For every section of these two types the index into the
  //      * indirect symbol table is stored in the section header in the field
  //      * reserved1.  An indirect symbol table entry is simply a 32bit index into
  //      * the symbol table to the symbol that the pointer or stub is referring to.
  //      * The indirect symbol table is ordered to match the entries in the section.
  //      */
  //     uint32_t indirectsymoff; /* file offset to the indirect symbol table */
  cmd.writeUInt32LE(indirectsymoff)
  //     uint32_t nindirectsyms;  /* number of indirect symbol table entries */
  cmd.writeUInt32LE(nindirectsyms)
  // 
  //     /*
  //      * To support relocating an individual module in a library file quickly the
  //      * external relocation entries for each module in the library need to be
  //      * accessed efficiently.  Since the relocation entries can't be accessed
  //      * through the section headers for a library file they are separated into
  //      * groups of local and external entries further grouped by module.  In this
  //      * case the presents of this load command who's extreloff, nextrel,
  //      * locreloff and nlocrel fields are non-zero indicates that the relocation
  //      * entries of non-merged sections are not referenced through the section
  //      * structures (and the reloff and nreloc fields in the section headers are
  //      * set to zero).
  //      *
  //      * Since the relocation entries are not accessed through the section headers
  //      * this requires the r_address field to be something other than a section
  //      * offset to identify the item to be relocated.  In this case r_address is
  //      * set to the offset from the vmaddr of the first LC_SEGMENT command.
  //      * For MH_SPLIT_SEGS images r_address is set to the the offset from the
  //      * vmaddr of the first read-write LC_SEGMENT command.
  //      *
  //      * The relocation entries are grouped by module and the module table
  //      * entries have indexes and counts into them for the group of external
  //      * relocation entries for that the module.
  //      *
  //      * For sections that are merged across modules there must not be any
  //      * remaining external relocation entries for them (for merged sections
  //      * remaining relocation entries must be local).
  //      */
  //     uint32_t extreloff;    /* offset to external relocation entries */
  cmd.writeUInt32LE(extreloff)
  //     uint32_t nextrel;      /* number of external relocation entries */
  cmd.writeUInt32LE(nextrel)
  // 
  //     /*
  //      * All the local relocation entries are grouped together (they are not
  //      * grouped by their module since they are only used if the object is moved
  //      * from it staticly link edited address).
  //      */
  //     uint32_t locreloff;    /* offset to local relocation entries */
  cmd.writeUInt32LE(locreloff)
  //     uint32_t nlocrel;      /* number of local relocation entries */
  cmd.writeUInt32LE(nlocrel)
  // 
  // };
  const LC_DYSYMTAB = 0xb /* dynamic link-edit symbol table info */
  writeLoadCommand(e, LC_DYSYMTAB, cmd.buffer)
}

function LC_DYSYMTAB(opts) {
  const e = new Encoder
  writeLoadCommand_DYSYMTAB(e, opts)
  return e.buffer
}

function writeLoadCommand_DYLD_INFO(e, {rebaseOff, rebaseSize, bindOff, bindSize, weakBindOff, weakBindSize, lazyBindOff, lazyBindSize, exportOff, exportSize}) {
  const cmd = new Encoder
  // /*
  //  * The dyld_info_command contains the file offsets and sizes of 
  //  * the new compressed form of the information dyld needs to 
  //  * load the image.  This information is used by dyld on Mac OS X
  //  * 10.6 and later.  All information pointed to by this command
  //  * is encoded using byte streams, so no endian swapping is needed
  //  * to interpret it. 
  //  */
  // struct dyld_info_command {
  //    uint32_t   cmd;         /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
  //    uint32_t   cmdsize;             /* sizeof(struct dyld_info_command) */
  // 
  //     /*
  //      * Dyld rebases an image whenever dyld loads it at an address different
  //      * from its preferred address.  The rebase information is a stream
  //      * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
  //      * Conceptually the rebase information is a table of tuples:
  //      *    <seg-index, seg-offset, type>
  //      * The opcodes are a compressed way to encode the table by only
  //      * encoding when a column changes.  In addition simple patterns
  //      * like "every n'th offset for m times" can be encoded in a few
  //      * bytes.
  //      */
  //     uint32_t   rebase_off; /* file offset to rebase info  */
  //     uint32_t   rebase_size;        /* size of rebase info   */
  cmd.writeUInt32LE(rebaseOff)
  cmd.writeUInt32LE(rebaseSize)
  //     
  //     /*
  //      * Dyld binds an image during the loading process, if the image
  //      * requires any pointers to be initialized to symbols in other images.  
  //      * The bind information is a stream of byte sized 
  //      * opcodes whose symbolic names start with BIND_OPCODE_.
  //      * Conceptually the bind information is a table of tuples:
  //      *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
  //      * The opcodes are a compressed way to encode the table by only
  //      * encoding when a column changes.  In addition simple patterns
  //      * like for runs of pointers initialzed to the same value can be 
  //      * encoded in a few bytes.
  //      */
  //     uint32_t   bind_off;   /* file offset to binding info   */
  //     uint32_t   bind_size;  /* size of binding info  */
  cmd.writeUInt32LE(bindOff)
  cmd.writeUInt32LE(bindSize)
  //         
  //     /*
  //      * Some C++ programs require dyld to unique symbols so that all
  //      * images in the process use the same copy of some code/data.
  //      * This step is done after binding. The content of the weak_bind
  //      * info is an opcode stream like the bind_info.  But it is sorted
  //      * alphabetically by symbol name.  This enable dyld to walk 
  //      * all images with weak binding information in order and look
  //      * for collisions.  If there are no collisions, dyld does
  //      * no updating.  That means that some fixups are also encoded
  //      * in the bind_info.  For instance, all calls to "operator new"
  //      * are first bound to libstdc++.dylib using the information
  //      * in bind_info.  Then if some image overrides operator new
  //      * that is detected when the weak_bind information is processed
  //      * and the call to operator new is then rebound.
  //      */
  //     uint32_t   weak_bind_off;      /* file offset to weak binding info   */
  //     uint32_t   weak_bind_size;  /* size of weak binding info  */
  cmd.writeUInt32LE(weakBindOff)
  cmd.writeUInt32LE(weakBindSize)
  //     
  //     /*
  //      * Some uses of external symbols do not need to be bound immediately.
  //      * Instead they can be lazily bound on first use.  The lazy_bind
  //      * are contains a stream of BIND opcodes to bind all lazy symbols.
  //      * Normal use is that dyld ignores the lazy_bind section when
  //      * loading an image.  Instead the static linker arranged for the
  //      * lazy pointer to initially point to a helper function which 
  //      * pushes the offset into the lazy_bind area for the symbol
  //      * needing to be bound, then jumps to dyld which simply adds
  //      * the offset to lazy_bind_off to get the information on what 
  //      * to bind.  
  //      */
  //     uint32_t   lazy_bind_off;      /* file offset to lazy binding info */
  //     uint32_t   lazy_bind_size;  /* size of lazy binding infs */
  cmd.writeUInt32LE(lazyBindOff)
  cmd.writeUInt32LE(lazyBindSize)
  //     
  //     /*
  //      * The symbols exported by a dylib are encoded in a trie.  This
  //      * is a compact representation that factors out common prefixes.
  //      * It also reduces LINKEDIT pages in RAM because it encodes all  
  //      * information (name, address, flags) in one small, contiguous range.
  //      * The export area is a stream of nodes.  The first node sequentially
  //      * is the start node for the trie.  
  //      *
  //      * Nodes for a symbol start with a uleb128 that is the length of
  //      * the exported symbol information for the string so far.
  //      * If there is no exported symbol, the node starts with a zero byte. 
  //      * If there is exported info, it follows the length.  
  //      *
  //      * First is a uleb128 containing flags. Normally, it is followed by
  //      * a uleb128 encoded offset which is location of the content named
  //      * by the symbol from the mach_header for the image.  If the flags
  //      * is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
  //      * a uleb128 encoded library ordinal, then a zero terminated
  //      * UTF8 string.  If the string is zero length, then the symbol
  //      * is re-export from the specified dylib with the same name.
  //      * If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
  //      * the flags is two uleb128s: the stub offset and the resolver offset.
  //      * The stub is used by non-lazy pointers.  The resolver is used
  //      * by lazy pointers and must be called to get the actual address to use.
  //      *
  //      * After the optional exported symbol information is a byte of
  //      * how many edges (0-255) that this node has leaving it, 
  //      * followed by each edge.
  //      * Each edge is a zero terminated UTF8 of the addition chars
  //      * in the symbol, followed by a uleb128 offset for the node that
  //      * edge points to.
  //      *  
  //      */
  //     uint32_t   export_off; /* file offset to lazy binding info */
  //     uint32_t   export_size;        /* size of lazy binding infs */
  cmd.writeUInt32LE(exportOff)
  cmd.writeUInt32LE(exportSize)
  // };
  const LC_DYLD_INFO = 0xb /* dynamic link-edit symbol table info */
  const LC_REQ_DYLD = 0x80000000
  const LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD /* compressed dyld information only */
  writeLoadCommand(e, LC_DYLD_INFO_ONLY, cmd.buffer)
}

function LC_DYLD_INFO_ONLY(opts) {
  const e = new Encoder
  writeLoadCommand_DYLD_INFO(e, opts)
  return e.buffer
}

function writeULeb128(e, v) {
  while (v) {
    const b = v & 127
    v >>>= 7
    e.writeByte(b | (v ? 0x80 : 0))
  }
}
function uleb128Size(v) {
  let size = 0
  while (v) {
    v >>>= 7
    size++
  }
  return size
}

function writeSingleNodeTrie(e, {symbol, address}) {
  const node = new Encoder

  node.writeByte(0x00) // no terminal information in first node
  node.writeByte(0x01) // there's 1 branch leaving this node
  node.writeUtf8(symbol)
  node.writeByte(0x00) // NUL-terminated
  writeULeb128(node, node.offset + uleb128Size(node.offset + 1))

  // child node
  writeULeb128(node, 1 + uleb128Size(address)) // size of exported information
  const EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0
  node.writeByte(EXPORT_SYMBOL_FLAGS_KIND_REGULAR) // symbol flags
  writeULeb128(node, address)

  e.append(node.buffer)
}


const e = new Encoder

const [,, out, symbol, data] = process.argv
if (!out || !symbol || !data) {
  console.error(`usage: $0 <out.dylib> <symbol> <data>`)
  process.exit(1)
}

const textToBeEncoded = data
const textBuf = stringToUtf8(textToBeEncoded)
const symbolAddr = 0x1000 // beginning of the 2nd page
const symbolSize = textBuf.byteLength
const linkeditAddr = Math.floor((symbolAddr + symbolSize + 0xfff) / 0x1000) * 0x1000

const symbolTable = new Encoder
writeSingleNodeTrie(symbolTable, {symbol, address: symbolAddr})

const linkeditSize = symbolTable.buffer.byteLength

writeMacho64File(e,
  {
    cpuType: CPU_TYPE_X86_64,
    cpuSubtype: CPU_SUBTYPE_X86_64_ALL,
    fileType: MH_DYLIB,
    flags: MH_NOUNDEFS,
  },
  [
    LC_ID_DYLIB(out),
    LC_SEGMENT_64({
      segname: '__TEXT',
      vmaddr: 0n,
      vmsize: BigInt(linkeditAddr),
      fileoff: 0n,
      filesize: BigInt(linkeditAddr),
      maxprot: 5,
      initprot: 5, // TODO
      flags: 0,
      sections: [],
    }),
    LC_SEGMENT_64({
      segname: '__LINKEDIT',
      vmaddr: BigInt(linkeditAddr),
      vmsize: 0x1000n,
      fileoff: BigInt(linkeditAddr),
      filesize: BigInt(linkeditSize),
      maxprot: 1,
      initprot: 1,
      flags: 0,
      sections: [],
    }),
    LC_DYLD_INFO_ONLY({
      exportOff: linkeditAddr,
      exportSize: symbolTable.buffer.byteLength, // TODO
    }),
    LC_SYMTAB({
    }),
    LC_DYSYMTAB({
    }),
  ]
)

// Fill up the first page with 0s.
// https://github.com/apple-opensource-mirror/dyld/blob/609d6a3837257f70e4e2b10d6a342ed26c5a7077/src/dyld.cpp#L3097
while (e.offset < 4096) e.writeByte(0)
// Now write our data.
e.append(textBuf)
// Align to the next page
while (e.offset < linkeditAddr) e.writeByte(0)
// Write the symbol table
writeSingleNodeTrie(e, {symbol, address: symbolAddr})

fs.writeFileSync(out, e.buffer)
console.log(`Generated '${out}'.`)
