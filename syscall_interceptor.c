#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

unsigned long **sys_call_table;

asmlinkage long (*original_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*original_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*original_write)(unsigned int fd, const char __user *buf, size_t count);

asmlinkage long new_open(const char __user *filename, int flags, umode_t mode) {
    char kernel_filename[256];
    long ret;

    if (strncpy_from_user(kernel_filename, filename, sizeof(kernel_filename)) < 0) {
        return -EFAULT;
    }

    printk(KERN_INFO "syscall_interceptor: open(\"%s\", %d, %d)\n", kernel_filename, flags, mode);

    ret = original_open(filename, flags, mode);
    return ret;
}

asmlinkage long new_read(unsigned int fd, char __user *buf, size_t count) {
    long ret;

    printk(KERN_INFO "syscall_interceptor: read(%d, %p, %zu)\n", fd, buf, count);

    ret = original_read(fd, buf, count);
    return ret;
}

asmlinkage long new_write(unsigned int fd, const char __user *buf, size_t count) {
    long ret;

    printk(KERN_INFO "syscall_interceptor: write(%d, %p, %zu)\n", fd, buf, count);

    ret = original_write(fd, buf, count);
    return ret;
}

static unsigned long **find_sys_call_table(void) {
    unsigned long offset;
    unsigned long **sct;

    for (offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *)) {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *)sys_close) {
            return sct;
        }
    }
    return NULL;
}

static int __init syscall_interceptor_init(void) {
    sys_call_table = find_sys_call_table();

    if (!sys_call_table) {
        printk(KERN_ERR "syscall_interceptor: Couldn't find sys_call_table\n");
        return -1;
    }

    original_open = (void *)sys_call_table[__NR_open];
    original_read = (void *)sys_call_table[__NR_read];
    original_write = (void *)sys_call_table[__NR_write];

    write_cr0(read_cr0() & (~0x10000));
    sys_call_table[__NR_open] = (unsigned long *)new_open;
    sys_call_table[__NR_read] = (unsigned long *)new_read;
    sys_call_table[__NR_write] = (unsigned long *)new_write;
    write_cr0(read_cr0() | 0x10000);

    printk(KERN_INFO "syscall_interceptor: Module loaded\n");

    return 0;
}

static void __exit syscall_interceptor_exit(void) {
    if (sys_call_table) {
        write_cr0(read_cr0() & (~0x10000));
        sys_call_table[__NR_open] = (unsigned long *)original_open;
        sys_call_table[__NR_read] = (unsigned long *)original_read;
        sys_call_table[__NR_write] = (unsigned long *)original_write;
        write_cr0(read_cr0() | 0x10000);
    }

    printk(KERN_INFO "syscall_interceptor: Module unloaded\n");
}

module_init(syscall_interceptor_init);
module_exit(syscall_interceptor_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Umar");
MODULE_DESCRIPTION("A kernel module to intercept and log system calls");
MODULE_VERSION("1.0");
