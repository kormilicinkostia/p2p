#include <linux/device.h>
#include <linux/cdev.h>
#include "dev.h"
#include "nodes.h"

static dev_t devno;
static struct cdev my_cdev;
static struct class *my_class;


static uint8_t response[1024];
static int response_offset = 0;
static int response_pos = 0;
static int response_flag = 0;

static uint16_t magic = 0xAABB;
#pragma pack(push, 1)
struct header
{
    uint16_t magic;
    uint8_t id;
    uint32_t size;
};
#pragma pack(pop)

#define PAGE_SIZE 2048

struct my_device_data 
{
    char buffer[PAGE_SIZE];  // буфер для накопления данных
    size_t buffer_len;        // сколько данных уже накоплено
    struct header pending_header; // частично полученный заголовок
    bool header_ready;        // заголовок полностью получен?
    size_t expected_data;     // ожидаемый размер данных
    spinlock_t lock;
};


static int mydev_open(struct inode *inode, struct file *file) 
{ 
    struct my_device_data *dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return -ENOMEM;
    
    spin_lock_init(&dev->lock);
    dev->buffer_len = 0;
    dev->header_ready = false;
    dev->expected_data = 0;
    
    file->private_data = dev;
    
    pr_info("mydev_open\n");
    return 0;
}
static int mydev_release(struct inode *inode, struct file *file) 
{ 
    kfree(file->private_data);
    pr_info("mydev_release\n");
    return 0; 
}

static void handle_complete_packet(struct header* cmd, uint8_t *data, size_t size)
{
    

    switch(cmd->id) 
    {
        case 0:
            {
                pr_info("get cmd list\n");
                struct client_info info [100];
                uint32_t count = client_request_list (info, 100);
                
                
                if ((sizeof(response) - response_offset) < (sizeof(struct header) + sizeof (struct client_info)))
                    break;
                uint32_t max_client = (sizeof(response) - response_offset - sizeof(struct header) ) /  sizeof (struct client_info);
                struct header* out = (struct header*)&response[response_offset];
                out->id = 0;
                if (count > max_client)
                    count = max_client;
                out->size = count * sizeof(struct client_info);
                response_offset += sizeof(struct header);
                
                for(int i = 0; i < count; i++)
                {
                    if (response_offset + sizeof(struct client_info) > sizeof(response))
                        break;
                    memcpy (&response[response_offset], info[i].id, sizeof(info[i].id));
                    response_offset += sizeof(info[i].id);
                    memcpy (&response[response_offset], info[i].dist, sizeof(info[i].dist));
                    response_offset += sizeof(info[i].dist);
                    memcpy (&response[response_offset], info[i].update, sizeof(info[i].update));
                    response_offset += sizeof(info[i].update);
                }
                response_flag = 1;
            }

            break;
       case 1:
        {
            // ИСПРАВЛЕНО: правильное приведение типов
            if (size < sizeof(uint32_t)) {
                pr_err("Invalid data size for cmd 1: %zu < %zu\n", size, sizeof(uint32_t));
                return;
            }
            
            uint32_t id = *(uint32_t*)data;
            size_t data_size = size - sizeof(uint32_t);
            
            pr_info("get cmd send: id=%u, data_size=%zu\n", id, data_size);
            
            if (data_size > 0) {
                pr_info("Data: %*ph\n", (int)data_size, data + sizeof(uint32_t));
            }
            
            clients_send(id, data + sizeof(uint32_t), data_size);
            break;
        }
        
        default:
            pr_warn("Unknown command id: %d\n", cmd->id);
            break;
    }
    
}


// Исправленная функция process_packet с передачей dev
static int process_packet(struct my_device_data *dev)
{
    size_t pos = 0;
    
    if (!dev) {
        pr_err("dev is NULL\n");
        return -EINVAL;
    }
    
    // Если заголовок еще не получен
    if (!dev->header_ready) {
        if (dev->buffer_len < sizeof(struct header))
            return 0; // ждем еще данных
            
        memcpy(&dev->pending_header, dev->buffer, sizeof(struct header));
        
        // Проверка magic (опционально)
        if (dev->pending_header.magic != 0xAABB) {
            pr_warn("Invalid magic: 0x%04X, expected 0xAABB\n", dev->pending_header.magic);
            // Сбросить буфер?
            dev->buffer_len = 0;
            dev->header_ready = false;
            return -EINVAL;
        }
        
        // Проверка размера
        if (dev->pending_header.size > PAGE_SIZE) {
            pr_err("Packet too large: %zu > %d\n", dev->pending_header.size, PAGE_SIZE);
            dev->buffer_len = 0;
            dev->header_ready = false;
            return -EINVAL;
        }
        
        dev->expected_data = dev->pending_header.size;
        dev->header_ready = true;
        pos = sizeof(struct header);
    }
    
    // Проверяем, пришли ли все данные
    if (dev->buffer_len - pos < dev->expected_data)
        return 0; // ждем еще данных
        
    // Полный пакет получен - обрабатываем
    handle_complete_packet(&dev->pending_header, (uint8_t*)&dev->buffer[pos], dev->expected_data);
    
    // Сдвигаем оставшиеся данные в начало буфера
    size_t consumed = pos + dev->expected_data;
    if (consumed < dev->buffer_len) {
        memmove(dev->buffer, dev->buffer + consumed, dev->buffer_len - consumed);
        dev->buffer_len -= consumed;
    } else {
        dev->buffer_len = 0;
    }
    
    dev->header_ready = false;
    return 1; // обработали один пакет
}

static ssize_t mydev_write(struct file *file, const char __user *buf,
                           size_t len, loff_t *off)
{
    struct my_device_data *dev = file->private_data;
    size_t remaining = len;
    size_t offset = 0;
    ssize_t ret = len;
    
    spin_lock(&dev->lock);
    
    while (remaining > 0) {
        size_t to_copy = min(remaining, PAGE_SIZE - dev->buffer_len);
        
        if (copy_from_user(dev->buffer + dev->buffer_len, buf + offset, to_copy)) {
            spin_unlock(&dev->lock);
            return -EFAULT;
        }
        
        dev->buffer_len += to_copy;
        offset += to_copy;
        remaining -= to_copy;
        
        // Пытаемся обработать полные пакеты
        while (process_packet(dev) > 0) {
            // продолжаем обработку
        }
    }
    
    spin_unlock(&dev->lock);
    return ret;
}





void dev_send(uint8_t* data, uint32_t size)
{
    if (response_offset + sizeof(struct header) + size > sizeof(response))
        return;

    struct header* out = (struct header*)&response[response_offset];
    out->id = 0;
    out->size = size;
    response_offset += sizeof(struct header);
    memcpy (&response[response_offset], data, size);
    response_offset += size;
    response_flag = 1;
}

static ssize_t mydev_read(struct file *file, char __user *buf,
                          size_t len, loff_t *offset) 
{
    size_t bytes_to_send;
    
    // Нет данных для отправки
    if (response_flag == 0 || response_pos >= response_offset) {
        return 0;
    }
    
    bytes_to_send = min(len, (size_t)(response_offset - response_pos));
    
    if (copy_to_user(buf, response + response_pos, bytes_to_send))
        return -EFAULT;
    
    response_pos += bytes_to_send;
    
    // Если прочитали всё - готовимся к следующей команде
    if (response_pos >= response_offset) 
    {
        response_offset = 0;
        response_pos = 0;
    }
    
    return bytes_to_send;
}

static struct file_operations mydev_fops = {
    .owner = THIS_MODULE,
    .open = mydev_open,
    .release = mydev_release,
    .write = mydev_write,
    .read = mydev_read,
};

void dev_init(void) 
{

    alloc_chrdev_region(&devno, 0, 1, "p2p");

    cdev_init(&my_cdev, &mydev_fops);
    cdev_add(&my_cdev, devno, 1);

    my_class = class_create("p2p");
    
    device_create(my_class, NULL, devno, NULL, "p2p");

    pr_info("create /dev/p2p\n");
}

void dev_deinit(void) 
{
    // Удаляем устройство и класс в обратном порядке
    device_destroy(my_class, devno);
    class_destroy(my_class);
    cdev_del(&my_cdev);
    unregister_chrdev_region(devno, 1);
    printk(KERN_INFO "delete /dev/p2p\n");
}
