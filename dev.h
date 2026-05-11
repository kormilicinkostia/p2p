#ifndef DEV_H
#define DEV_H

void dev_init(void) ;
void dev_deinit(void) ;
void dev_send(uint8_t* data, uint32_t size) ;
#endif