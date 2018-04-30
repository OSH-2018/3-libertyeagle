#define FUSE_USE_VERSION 26

#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <math.h>

#define BLOCK_NR 64 * 1024
#define BLOCK_SIZE 8
#define BLOCK_ALLOCATED 1
#define BLOCK_FREE 0
#define MAX_CONCATENATED 64 * 1024 * 8

typedef unsigned long memfs_addr;
typedef unsigned long memfs_size_t;

struct content_list {
    memfs_addr this_content;
    memfs_addr next;
};

struct filenode {
    memfs_addr filename;
    memfs_addr c_list;
    memfs_addr st;
    memfs_addr next;
};

static void *mem[BLOCK_NR];
static memfs_addr list_head;
static memfs_addr filelist_root;

static memfs_addr hdrp(memfs_addr bp);
static memfs_addr ftrp(memfs_addr bp);
static memfs_addr next_blkp(memfs_addr bp);
static memfs_addr prev_blkp(memfs_addr bp);
static memfs_size_t get_size(memfs_addr address);
static int get_alloc(memfs_addr address);
static void put(memfs_addr address, unsigned long val);
static void map_mm(memfs_addr address);
static void unmap_mm(memfs_addr address);
static void memfs_mm_init(void);
static void memfs_mm_free(memfs_addr bp);
static void memfs_mm_coalesce(memfs_addr bp);
static memfs_size_t max_free_block_size(void);
static memfs_addr memfs_mm_alloc(memfs_size_t asize);
static void create_filenode(const char *filename, const struct stat *st);
static memfs_addr get_filenode_addr(const char *filename);
static int memfs_getattr(const char *path, struct stat *stbuf);
static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int memfs_mknod(const char *path, mode_t mode, dev_t dev);
static int memfs_open(const char *path, struct fuse_file_info *fi);
static int memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int memfs_truncate(const char *path, off_t size);
static int memfs_unlink(const char *path);
static void *memfs_init(struct fuse_conn_info *conn);

static unsigned long pack(unsigned long size, unsigned long alloc) {
    return (size << 1) | alloc;
}

static memfs_addr hdrp(memfs_addr bp) {
    return bp - 1;
}

static memfs_addr ftrp(memfs_addr bp) {
    return bp + get_size(hdrp(bp)) - 2;
}

static memfs_addr next_blkp(memfs_addr bp) {
    return bp + get_size(bp - 1);
}

static memfs_addr prev_blkp(memfs_addr bp) {
    return bp - get_size(bp - 2);
}

static memfs_size_t get_size(memfs_addr address) {
    assert(mem[address] != NULL);
    return (*((unsigned long *)mem[address]) & ~0x1) >> 1;
}

static int get_alloc(memfs_addr address) {
    assert(mem[address] != NULL);
    return *((unsigned long *)mem[address]) & 0x1;
}

static void put(memfs_addr address, unsigned long val) {
    assert(mem[address] != NULL);
    *((unsigned long *)mem[address]) = val;
}

static void map_mm(memfs_addr address) {
    assert(mem[address] == NULL);
    if ((mem[address] = mmap(NULL, BLOCK_SIZE,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))
        == MAP_FAILED) {
            perror("mmap failed.");
            return;
    }
    memset(mem[address], 0, BLOCK_SIZE);
}

static void unmap_mm(memfs_addr address) {
    assert(mem[address] != NULL);
    if (munmap(mem[address], BLOCK_SIZE) < 0) {
        perror("munmap failed.");
        return;
    }
    mem[address] = NULL;
}

static void memfs_mm_init(void) {
    map_mm(0);
    map_mm(1);
    put(0, pack(2, BLOCK_ALLOCATED));  // prologue block
    put(1, pack(2, BLOCK_ALLOCATED));
    list_head = 1;
    map_mm(2);
    map_mm(BLOCK_NR - 2);
    put(2, pack(BLOCK_NR - 3, BLOCK_FREE)); // initial free block
    put(BLOCK_NR - 2, pack(BLOCK_NR - 3, BLOCK_FREE));
    map_mm(BLOCK_NR - 1);
    put(BLOCK_NR - 1, pack(0, BLOCK_ALLOCATED));    // epilogue block
}

static void memfs_mm_free(memfs_addr bp) {
    // size_t in our memfs address space is `unsigned long`
    memfs_size_t size = get_size(hdrp(bp));
    put(hdrp(bp), pack(size, BLOCK_FREE));
    put(ftrp(bp), pack(size, BLOCK_FREE));
    
    memfs_addr footer = ftrp(bp);
    memfs_addr i;
    for (i = bp; i < footer; ++i) unmap_mm(i);

    memfs_mm_coalesce(bp);
}

static void memfs_mm_coalesce(memfs_addr bp) {
    int prev_alloc = get_alloc(ftrp(prev_blkp(bp)));
    int next_alloc = get_alloc(hdrp(next_blkp(bp)));
    memfs_size_t size = get_size(hdrp(bp));

    if (prev_alloc == BLOCK_ALLOCATED && next_alloc == BLOCK_ALLOCATED) {
        
    }
    else if (prev_alloc == BLOCK_ALLOCATED && next_alloc == BLOCK_FREE) {
        size += get_size(hdrp(next_blkp(bp)));
        unmap_mm(ftrp(bp));
        unmap_mm(hdrp(next_blkp(bp)));
        put(hdrp(bp), pack(size, BLOCK_FREE));
        put(ftrp(bp), pack(size, BLOCK_FREE));
    }
    else if (prev_alloc == BLOCK_FREE && next_alloc == BLOCK_ALLOCATED) {
        size += get_size(hdrp(prev_blkp(bp)));
        put(ftrp(bp), pack(size, BLOCK_FREE));
        put(hdrp(prev_blkp(bp)), pack(size, BLOCK_FREE));
        unmap_mm(ftrp(bp));
        unmap_mm(bp - 2);
    }
    else {
        size += get_size(hdrp(prev_blkp(bp))) + get_size(ftrp(next_blkp(bp)));
        put(hdrp(prev_blkp(bp)), pack(size, BLOCK_FREE));
        put(ftrp(next_blkp(bp)), pack(size, BLOCK_FREE));
        unmap_mm(ftrp(bp) + 1);
        unmap_mm(ftrp(bp));
        unmap_mm(hdrp(bp) - 1);
        unmap_mm(hdrp(bp));
    }
}

static memfs_size_t max_free_block_size(void) {
    memfs_addr bp;
    memfs_size_t max_size = 0;
    for (bp = list_head; get_size(hdrp(bp)) > 0; bp = next_blkp(bp)) {
        if (get_alloc(hdrp(bp)) == BLOCK_FREE && (get_size(hdrp(bp)) > max_size)) {
            max_size = get_size(hdrp(bp));
        }
    }
    return max_size;
}

static memfs_addr memfs_mm_alloc(memfs_size_t asize) {
    memfs_addr bp;
    memfs_addr match = -1;
    asize = asize + 2;  // including header and footer;
    for (bp = list_head; get_size(hdrp(bp)) > 0; bp = next_blkp(bp)) {
        if (get_alloc(hdrp(bp)) == BLOCK_FREE && (asize <= get_size(hdrp(bp)))) {
            match = bp;
            break;
        }
    }

    if (match == -1) {
        fprintf(stderr, "no memory in memfs available.\n");
    }

    memfs_size_t csize = get_size(hdrp(match));
    memfs_addr i;
    if (csize - asize >= 3) {
        put(hdrp(match), pack(asize, BLOCK_ALLOCATED));
        for (i = match; i < ftrp(match); ++i)
            if (mem[i] == NULL) map_mm(i);
        if (mem[ftrp(match)] == NULL) map_mm(ftrp(match));
        put(ftrp(match), pack(asize, BLOCK_ALLOCATED));
        if (mem[hdrp(next_blkp(match))] == NULL) map_mm(hdrp(next_blkp(match)));
        put(hdrp(next_blkp(match)), pack(csize - asize, BLOCK_FREE));
        put(ftrp(next_blkp(match)), pack(csize - asize, BLOCK_FREE));
    }
    else {
        put(hdrp(match), pack(csize, BLOCK_ALLOCATED));
        for (i = match; i < ftrp(match); ++i)
            if (mem[i] == NULL) map_mm(i);
        put(ftrp(match), pack(csize, BLOCK_ALLOCATED));
    }
    return match;
}

static void create_filenode(const char *filename, const struct stat *st) {
    memfs_addr new_filenode_memfs_addr = memfs_mm_alloc(ceil((double) sizeof(struct filenode) / 8));
    struct filenode *new_filenode_mapped = (struct filenode *) mem[new_filenode_memfs_addr];
    new_filenode_mapped->filename = memfs_mm_alloc(ceil(((double) strlen(filename) + 1) / 8));
    char *filename_p = (char *) mem[new_filenode_mapped->filename];
    memcpy(filename_p, filename, strlen(filename) + 1);
    new_filenode_mapped->c_list = -1;
    new_filenode_mapped->next = filelist_root;
    new_filenode_mapped->st = memfs_mm_alloc(ceil((double) sizeof(struct stat) / 8));
    struct stat *st_p = mem[new_filenode_mapped->st];
    memcpy(st_p, st, sizeof(struct stat));
    filelist_root = new_filenode_memfs_addr;
}

static memfs_addr get_filenode_addr(const char *filename) {
    memfs_addr node_addr = filelist_root;
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    while (filenode_p) {
        char *filename_p = (char *) mem[filenode_p->filename];
        if (strcmp(filename_p, filename) != 0) {
            node_addr = filenode_p->next;
            if (node_addr != -1) filenode_p = (struct filenode *) mem[node_addr];
            else filenode_p = NULL;
        }
        else return node_addr;
    }
    return -1;
}

static int memfs_getattr(const char *path, struct stat *stbuf) {
    int res = 0;

    memset(stbuf, 0 ,sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else {
        memfs_addr node_addr = get_filenode_addr(path + 1);
        if (node_addr != -1) {
            struct filenode *filenode_p = (struct filenode *) mem[node_addr];
            memcpy(stbuf, (struct stat *) mem[filenode_p->st], sizeof(struct stat));
        }
        else {
            res = -ENOENT;
        }
    }
    return res;
}

static int memfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    memfs_addr node_addr = filelist_root;
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    while (filenode_p) {
        filler(buf, (char *) mem[filenode_p->filename], (struct stat *) mem[filenode_p->st], 0);
        node_addr = filenode_p->next;
        if (node_addr == -1) filenode_p = mem[node_addr];
        else filenode_p = NULL;
    }
    return 0;
}

static int memfs_mknod(const char *path, mode_t mode, dev_t dev) {
    struct stat st;
    st.st_mode = S_IFREG | 0644;
    st.st_uid = fuse_get_context()->uid;
    st.st_gid = fuse_get_context()->gid;
    st.st_nlink = 1;
    st.st_size = 0;
    create_filenode(path + 1, &st);
    return 0;
}

static int memfs_open(const char *path, struct fuse_file_info *fi) {
    return 0;
}

static int memfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    memfs_addr node_addr = get_filenode_addr(path + 1);
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    struct stat *st_p = (struct stat *) mem[filenode_p->st];
    st_p->st_size = offset + size;   // update file size;
    
    if (filenode_p->c_list == -1) { // no content already written
        memfs_addr c_list_head;
        memfs_addr c_list_addr = c_list_head;
        memfs_addr c_list_last = -1;
        size_t size_left = size;
        size_t size_written = 0;
        while (size_left > 0) {
            memfs_addr c_list_addr = memfs_mm_alloc(ceil((double) sizeof(struct content_list) / 8));
            if (c_list_last == -1)
                c_list_head = c_list_addr;
            else 
                ((struct content_list *) mem[c_list_last])->next = c_list_addr;

            memfs_size_t memfs_size_needed = ceil((double) size_left / 8);

            if (memfs_size_needed > max_free_block_size() - 2) {
                memfs_size_t allocated_size = max_free_block_size() - 2;
                memfs_addr content_addr = memfs_mm_alloc(allocated_size);
                ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
                char *content_writer = (char *) mem[content_addr];
                memcpy(content_writer, buf + size_written, BLOCK_SIZE * allocated_size);
                size_left -= BLOCK_SIZE * allocated_size;
                size_written += BLOCK_SIZE * allocated_size;
            }
            else {
                memfs_addr content_addr = memfs_mm_alloc(memfs_size_needed);
                ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
                char *content_writer = (char *) mem[content_addr];
                memcpy(content_writer, buf + size_written, size_left);
                size_written += size_left;
                size_left = 0;
            }
            ((struct content_list *) mem[c_list_addr])->next = -1;
            c_list_last = c_list_addr;
        }
        filenode_p->c_list = c_list_head;
    }
    else {
        size_t content_already_read = 0;
        char *content_concatenated = mmap(NULL, MAX_CONCATENATED,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memfs_addr c_list_addr = filenode_p->c_list;
        struct content_list *c_list_p = mem[c_list_addr];
        while (c_list_p) {
            memfs_addr content_addr = c_list_p->this_content;
            char *content_reader = (char *) mem[content_addr];
            memcpy(content_concatenated + content_already_read, content_reader, BLOCK_SIZE * (get_size(hdrp(content_addr)) - 2));
            memfs_mm_free(content_addr);
            content_already_read += BLOCK_SIZE * (get_size(hdrp(content_addr)));
            memfs_addr temp = c_list_p->next;
            memfs_mm_free(c_list_addr);
            c_list_addr = temp;
            if (c_list_addr != -1) c_list_p = (struct content_list *) mem[c_list_addr];
            else c_list_p = NULL;
        }
        filenode_p->c_list = -1;

        memcpy(content_concatenated + offset, buf, size);
        
        size_t size_left = offset + size;
        size_t size_written = 0;
        memfs_addr c_list_head;
        c_list_addr = c_list_head;
        memfs_addr c_list_last = -1;
        while (size_left > 0) {
            memfs_addr c_list_addr = memfs_mm_alloc(ceil((double) sizeof(struct content_list) / 8));
            if (c_list_last == -1)
                c_list_head = c_list_addr;
            else 
                ((struct content_list *) mem[c_list_last])->next = c_list_addr;

            memfs_size_t memfs_size_needed = ceil((double) size_left / 8);

            if (memfs_size_needed > max_free_block_size() - 2) {
                memfs_size_t allocated_size = max_free_block_size() - 2;
                memfs_addr content_addr = memfs_mm_alloc(allocated_size);
                ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
                char *content_writer = (char *) mem[content_addr];
                memcpy(content_writer, content_concatenated + size_written, BLOCK_SIZE * allocated_size);
                size_left -= BLOCK_SIZE * allocated_size;
                size_written += BLOCK_SIZE * allocated_size;
            }
            else {
                memfs_addr content_addr = memfs_mm_alloc(memfs_size_needed);
                ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
                char *content_writer = (char *) mem[content_addr];
                memcpy(content_writer, content_concatenated + size_written, size_left);
                size_written += size_left;
                size_left = 0;
            }
            ((struct content_list *) mem[c_list_addr])->next = -1;
            c_list_last = c_list_addr;
        }
        munmap(content_concatenated, MAX_CONCATENATED);
        filenode_p->c_list = c_list_head;
    }
    return size;
}

static int memfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    memfs_addr node_addr = get_filenode_addr(path + 1);
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    struct stat *st_p = (struct stat *) mem[filenode_p->st]; 
    size_t size_read = (offset + size > st_p->st_size) ? st_p->st_size - offset : size;

    size_t content_already_read = 0;
    char *content_concatenated = mmap(NULL, MAX_CONCATENATED,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memfs_addr c_list_addr = filenode_p->c_list;
    struct content_list *c_list_p = (c_list_addr -= -1) ? NULL : mem[c_list_addr];
    while (c_list_p) {
        memfs_addr content_addr = c_list_p->this_content;
        char *content_reader = (char *) mem[content_addr];
        memcpy(content_concatenated + content_already_read, content_reader, BLOCK_SIZE * (get_size(hdrp(content_addr)) - 2));
        content_already_read += BLOCK_SIZE * (get_size(hdrp(content_addr)));
        c_list_addr = c_list_p->next;
        if (c_list_addr != -1) c_list_p = (struct content_list *) mem[c_list_addr];
        else c_list_p = NULL;
    }

    memcpy(buf, content_concatenated + offset, size_read);
    
    munmap(content_concatenated, MAX_CONCATENATED);
    return size_read;
}

static int memfs_truncate(const char *path, off_t size) {
    memfs_addr node_addr = get_filenode_addr(path + 1);
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    struct stat *st_p = (struct stat *) mem[filenode_p->st];
    st_p->st_size = size;   // update file size;   

    if (size == 0) {
	    filenode_p->c_list = -1;
	    return 0;
    }

    size_t content_already_read = 0;
    char *content_concatenated = mmap(NULL, MAX_CONCATENATED,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memfs_addr c_list_addr = filenode_p->c_list;
    struct content_list *c_list_p = (c_list_addr -= -1) ? NULL : mem[c_list_addr];
    while (c_list_p) {
    memfs_addr content_addr = c_list_p->this_content;
        char *content_reader = (char *) mem[content_addr];
        memcpy(content_concatenated + content_already_read, content_reader, BLOCK_SIZE * (get_size(hdrp(content_addr)) - 2));
        memfs_mm_free(content_addr);
        content_already_read += BLOCK_SIZE * (get_size(hdrp(content_addr)));
        memfs_addr temp = c_list_p->next;
        memfs_mm_free(c_list_addr);
        c_list_addr = temp;
        if (c_list_addr != -1) c_list_p = (struct content_list *) mem[c_list_addr];
        else c_list_p = NULL;
    }
    filenode_p->c_list = -1;
    
    size_t size_left = size;
    size_t size_written = 0;
    memfs_addr c_list_head;
    c_list_addr = c_list_head;
    memfs_addr c_list_last = -1;
    while (size_left > 0) {
        memfs_addr c_list_addr = memfs_mm_alloc((double) ceil((double) sizeof(struct content_list) / 8));
        if (c_list_last == -1)
            c_list_head = c_list_addr;
        else 
            ((struct content_list *) mem[c_list_last])->next = c_list_addr;

        memfs_size_t memfs_size_needed = ceil((double) size_left / 8);

        if (memfs_size_needed > max_free_block_size() - 2) {
            memfs_size_t allocated_size = max_free_block_size() - 2;
            memfs_addr content_addr = memfs_mm_alloc(allocated_size);
            ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
            char *content_writer = (char *) mem[content_addr];
            memcpy(content_writer, content_concatenated + size_written, BLOCK_SIZE * allocated_size);
            size_left -= BLOCK_SIZE * allocated_size;
            size_written += BLOCK_SIZE * allocated_size;
        }
        else {
            memfs_addr content_addr = memfs_mm_alloc(memfs_size_needed);
            ((struct content_list *) mem[c_list_addr])->this_content = content_addr;
            char *content_writer = (char *) mem[content_addr];
            memcpy(content_writer, content_concatenated + size_written, size_left);
            size_written += size_left;
            size_left = 0;
        }
        ((struct content_list *) mem[c_list_addr])->next = -1;
        c_list_last = c_list_addr;
    }
    munmap(content_concatenated, MAX_CONCATENATED);
    filenode_p->c_list = c_list_head;
    return 0;
}

static int memfs_unlink(const char *path) {
    memfs_addr node_addr = filelist_root;
    memfs_addr prev_addr = -1;
    struct filenode *filenode_p = (node_addr == -1) ? NULL : (struct filenode *) mem[node_addr];
    while (filenode_p) {
        char *filename_p = (char *) mem[filenode_p->filename];
        if (strcmp(filename_p, path + 1) != 0) {
            prev_addr = node_addr;
            node_addr = filenode_p->next;
            if (node_addr != -1) filenode_p = (struct filenode *) mem[node_addr];
            else filenode_p = NULL;
        }
        else break;
    }
   
    memfs_mm_free(filenode_p->filename);
    memfs_mm_free(filenode_p->st);

    memfs_addr c_list_addr = filenode_p->c_list;
    while (c_list_addr != -1) {
        struct content_list *c_list_p = (struct content_list *) mem[c_list_addr];
        memfs_mm_free(c_list_p->this_content);
        memfs_addr temp = c_list_p->next;
        memfs_mm_free(c_list_addr);
        c_list_addr = temp;
    }

    if (prev_addr == -1) filelist_root = filenode_p->next;
    else ((struct filenode *) mem[prev_addr])->next = filenode_p->next;

    memfs_mm_free(node_addr);
    return 0;
}

static void *memfs_init(struct fuse_conn_info *conn) {
    int i;
    for (i = 0; i< BLOCK_NR; ++i)
        mem[i] = NULL;

    memfs_mm_init();
    filelist_root = -1;
    return NULL;
}

static const struct fuse_operations op = {
    .init = memfs_init,
    .getattr = memfs_getattr,
    .readdir = memfs_readdir,
    .mknod = memfs_mknod,
    .open = memfs_open,
    .write = memfs_write,
    .truncate = memfs_truncate,
    .read = memfs_read,
    .unlink = memfs_unlink,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &op, NULL);
}