OBJS = *.o
scrape: scrape.c  
	gcc -o scrape scrape.c -lpcap -lpthread
	gcc -o old scrape_old.c -lpcap -lpthread 

clean: 
	rm -f *.log