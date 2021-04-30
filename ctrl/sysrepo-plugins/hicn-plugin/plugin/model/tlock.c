#include"tlock.h"


void ticket_init ( int Lock_Number , long int init ){

//__atomic_store( &En[Lock_Number] , &init , __ATOMIC_SEQ_CST );
//__atomic_store( &De[Lock_Number] , &init , __ATOMIC_SEQ_CST );
En[Lock_Number]=init;
De[Lock_Number]=init;
}

void tlock(int Lock_Number ){

 int my_ticket =   __sync_fetch_and_add(&En[Lock_Number] , 1  );
 while (    my_ticket != De[ Lock_Number ]  ) {};

}

void tunlock(int Lock_Number ){
De[Lock_Number]++;
}
