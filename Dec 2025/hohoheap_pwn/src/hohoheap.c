#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <stdint.h> 
#include <unistd.h>

#define GIFT_MAX 0x100
char * gift_arr[GIFT_MAX] = {0};
uint32_t gift_given[GIFT_MAX] = {0}; 
uint32_t gift_size[GIFT_MAX] = {0}; 
uint64_t gift_idx = 0; 

char * given_arr[GIFT_MAX] = {0}; 

// General stuff
void setup(void) {   
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void print_menu(void) {
    printf("============= HO HO HEAP =============\n"); 
    printf("1. Add a gift\n"); 
    printf("2. View a gift\n");
    printf("3. Modify a gift\n"); 
    printf("4. Remove a gift\n"); 
    printf("5. Ask Santa to send a gift\n"); 
    printf("6. Spread some Christmas cheer!\n"); 
    printf("7. Exit\n"); 
    printf("======================================\n"); 
}

int main(void) {
    uint64_t opcode = 0x0; 
    uint64_t size = 0; 
    uint64_t usr_idx = 0; 
    uint64_t give_count = 0; 
    char * gift = 0; 
    
    setup(); 
    
    while (1==1) {
        opcode = 0; 
        size = 0; 
        usr_idx = 0; 
        give_count = 0; 
        gift = 0; 
        
        print_menu(); 
        
        printf("Your choice: "); 
        scanf("%d", &opcode); 
        
        if (opcode == 1) { // Add a gift
            if (gift_idx >= GIFT_MAX) {
                printf("Maximum number of gifts reached\n"); 
            } else {
                printf("Gift size: "); 
                scanf("%d", &size); 
                
                if (size < 0x2000) {
                    gift = malloc(size); 
                    if (gift == 0x0) {
                        exit(-1); 
                    }
                    
                    gift_arr[gift_idx] = gift; 
                    gift_size[gift_idx] = size; 
                    
                    printf("Content: "); 
                    read(0, gift, size-1); 
                    
                    gift_idx += 1; 
                    printf("Success!\n"); 
                } else {
                    printf("Size too big!\n"); 
                }
            }
        
        } else if (opcode == 2) { // View a gift
            printf("Gift index: "); 
            scanf("%d", &usr_idx); 
            
            if (usr_idx >= gift_idx) {
                printf("Invalid index\n"); 
            } else {
                gift = gift_arr[usr_idx]; 
                
                if (gift == 0x0) {
                    printf("Gift does not exist\n"); 
                } else {
                    size = gift_size[usr_idx]; 
                    
                    printf("Gift content: "); 
                    write(1, gift, size-1); 
                    printf("Success!\n");
                } 
            }
        
        } else if (opcode == 3) { // Modify a gift
            printf("Gift index: "); 
            scanf("%d", &usr_idx); 
            
            if (usr_idx >= gift_idx) {
                printf("Invalid index\n"); 
            } else {
                gift = gift_arr[usr_idx]; 
                
                if (gift == 0x0) {
                    printf("Gift does not exist\n"); 
                } else {
                    size = gift_size[usr_idx]; 
                    
                    printf("Content: "); 
                    read(0, gift, size-1);
                    printf("Success!\n"); 
                }
            }
        
        } else if (opcode == 4) { // Remove a gift
            printf("Gift index: "); 
            scanf("%d", &usr_idx); 
            
            if (usr_idx >= gift_idx) {
                printf("Invalid index\n"); 
            } else {
                gift = gift_arr[usr_idx]; 
                
                if ((gift != 0x0) && (gift_given[usr_idx] == 0x0)) {
                    free(gift); 
                    gift_arr[usr_idx] = 0x0; 
                    gift_size[usr_idx] = 0x0;
                    gift_given[usr_idx] = 0x0; 
                    printf("Success!\n"); 
                } else {
                    printf("Unable to remove gift\n");
                }
            }
        
        } else if (opcode == 5) { // Send some gifts
            printf("Gift index: "); 
            scanf("%d", &usr_idx); 
            
            printf("How many gifts to give: "); 
            scanf("%d", &give_count);
            
            if (usr_idx >= gift_idx) {
                printf("Invalid index\n"); 
            } else {
                gift = gift_arr[usr_idx]; 
                
                if (gift != 0x0) {
                    gift_given[usr_idx] += give_count; 
                    
                    // Add gift into the given_arr
                    if (gift_given[usr_idx] != 0x0) {
                        given_arr[usr_idx] = gift; 
                    }
                    
                    printf("Gifts given!\n"); 
                } else {
                    printf("Gift does not exist\n"); 
                }
            }
        
        } else if (opcode == 6) { // Send all gifts
             for (int i = 0; i < GIFT_MAX; i++) {
                if (given_arr[i] != 0x0) {
                    printf("Gift %d sent! Merry Christmas!\n", i); 
                    
                    if (gift_given[usr_idx] == 0x0) {
                        free(given_arr[i]); 
                    }
                    
                    given_arr[i] = 0x0; 
                }
             }
            
        } else if (opcode == 7) { // Exit
            printf("Merry Christmas!\n"); 
            exit(0); 
            return 0; 
            
        } else {
            printf("Invalid command!\n"); 
        }
    }
    
    return 0; 
}












