#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
//#include <asm-generic/uaccess.h>
#include <linux/fs.h>

int init_module(void);
void cleanup_module(void);
static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "yanivdev" /* Dev name as it appears in /proc/devices */
#define BUF_LEN 80 


static int Major;
static int Device_Open = 0;
static char msg[BUF_LEN];
static char* msg_Ptr;

static struct file_operations fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};


int init_module(void)
{
    Major = register_chrdev(0, DEVICE_NAME, &fops);

    // check if device registered correctly. -1 if not.
    if(Major < 0){
        printk(KERN_ALERT "Error while registering device %d\n", Major);
        return Major;
    } 

    printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);
    printk(KERN_INFO "the driver, create a dev file with\n");
    printk(KERN_INFO "'mknod /dev/%s c %d 0'.\n", DEVICE_NAME, Major);
    printk(KERN_INFO "Try various minor numbers. Try to cat and echo to\n");
    printk(KERN_INFO "the device file.\n");
    printk(KERN_INFO "Remove the device file and module when done.\n");

    return SUCCESS;
}

void cleanup_module(void)
{
    unregister_chrdev(Major, DEVICE_NAME);
    printk(KERN_ALERT "Removed\n");
}


static int device_open(struct inode* i, struct file* flip)
{
    static int counter = 0;
    if(Device_Open){
        return -EBUSY;
    }

    Device_Open++;
    sprintf(msg, "the counter is %d\n", counter++);
    msg_Ptr = msg;
    try_module_get(THIS_MODULE);
    return SUCCESS;
}

static int device_release(struct inode* i, struct file* flip){
    Device_Open--;
    module_put(THIS_MODULE);
    return 0;
}

static ssize_t device_read(struct file *filp, char* buffer, size_t length, loff_t* offset)
{
    int bytes_read = 0;
    if(*msg_Ptr == 0)
        return 0;

    while(length && *msg_Ptr){
        put_user(*(msg_Ptr++), buffer++);
        length--;
        bytes_read++;
    }
    return bytes_read;
}

static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t *off)
{
    printk(KERN_ALERT "Opertion not supperted\n");
    return -EINVAL;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Simple Hello World Kernel Module");
