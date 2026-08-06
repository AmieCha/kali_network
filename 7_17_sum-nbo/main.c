#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>


int  main(int argc , char* argv[] )
{
	uint32_t sum = 0 ;

	for ( int i= 1; i < argc; i++){
		uint32_t n;
		FILE* fp = fopen(argv[i],"rb");

		//파일 오픈 예외 처리
		if( fp == NULL  ){
			perror(argv[i]);
		}
		else{
			// fread() 바이트 메모리 그대로 복사
			// 포인터 , 읽어올 사이즈,원소 총 개수, 대상 포인터
			size_t res = fread(&n , 4 , 1 ,fp);

			//4 바이트 작을때 에러 처리 
			if(res != 1){
				printf("%s: read error\n" , argv[i]);
			}else{
				// 빅인디안으로 변경
				n = ntohl(n);

				if(i>1) printf(" + ");
				printf(" %u(0x%08x)", n , n );

				sum += n ; 
			}
			fclose(fp);
		}
	}
	printf(" = %u(0x%08x)\n" ,sum , sum );
	return 0;
}
