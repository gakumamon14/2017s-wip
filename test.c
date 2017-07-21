#include <vale_bpf.h>
#include <vale_bpf_ext_common.h>
struct eth {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
};

uint8_t mylookup(uint8_t *buf, uint16_t len, uint8_t sport) {
  struct eth *eth = (struct eth *)buf;


 uint8_t bcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
 int i=0;
 for( i=0;i<6;i++){
  
 if( eth->dst[i]==bcast[i]){
  }else{
    break;
 }
 }
 if(i==6){
    return VALE_BPF_BROADCAST;
  }
  uint64_t key1=0;
  uint64_t key2=0;
  uint64_t val=0;
  uint8_t *k=(uint8_t *)&key1;
  uint8_t *s=(uint8_t*)&key2;
  for(int i=0;i<6;i++){ 
    *(k+i)=eth->dst[i];
  }

  *(k+6)=0;
  *(k+7)=0;
  for(int i=0;i<6;i++){
    *(s+1)=eth->src[i];
  }
  *(s+6)=0;
  *(s+7)=0;
    

 val=vale_bpf_hash64_search_entry(key2);
  //送信元のアドレスの有無をアドレステーブルを見て確認
  if(val==UINT64_MAX){
    vale_bpf_hash64_add_entry(key2,val);

  //送信先アドレスがあるかどうかアドレステーブルを見る
    val=vale_bpf_hash64_search_entry(key1);
      if(val==UINT64_MAX) {
        return VALE_BPF_BROADCAST;
      }else {
        return val;
      }
  }else{
    //送信ポートが同じかどうか 
      if(sport==val){
      // 不変
      
  //送1信先アドレスがあるかどうかアドレステーブルを見る
        val=vale_bpf_hash64_search_entry(key1);

        if(val==UINT64_MAX) {
          return VALE_BPF_BROADCAST;
        }else {
          return val;
        }

      }else{
    //テーブルを更新
    vale_bpf_hash64_remove_entry(key2);
    vale_bpf_hash64_add_entry(key2,sport);
    
  //送1信先アドレスがあるかどうかアドレステーブルを見る
    val=vale_bpf_hash64_search_entry(key1);
    if(val==UINT64_MAX) {
      return VALE_BPF_BROADCAST;
      }else {
      return val;
            }
      }
  }

}





/*
val=vale_bpf_hash64_search(key);
val=vale_bpf_hash64_search(key);
val=vale_bpf_hash64_add(key,add);
val=vale_bpf_hash64_remove(key);
val=vale_bpf_hash64_add(val);
*/









