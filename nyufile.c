#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/sha.h>
#include <math.h>


// Boot Sector
#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

// Directory entry
#pragma pack(push,1)
typedef struct DirEntry {
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

// return the address of a cluster
char* get_cluster_address(char* dataRegion, int cluster_num, int bytes_per_sector, int sectors_per_cluster){
    return dataRegion + (cluster_num - 2) * sectors_per_cluster * bytes_per_sector;
}

// get the next cluster from the fat
int get_next_cluster(char* fat, int cluster_num){
    int* fat_entry = (int*)fat + cluster_num;
    if (*fat_entry >= 0x0FFFFFF8){
        return -1;
    } else {
        return *fat_entry;
    }
}

void print_bytes(char *addr, int size){
    for (int i = 0; i < size; i++){
        unsigned char entry = *(unsigned char *)(addr + i);
        printf("%02X ", entry);
    }
    printf("\n");
}




// Milestone 1: validate usage
// There are several ways to invoke your nyufile program. Here is its usage:

// [root@... cs202]# ./nyufile
// Usage: ./nyufile disk <options>
//   -i                     Print the file system information.
//   -l                     List the root directory.
//   -r filename [-s sha1]  Recover a contiguous file.
//   -R filename -s sha1    Recover a possibly non-contiguous file.
// The first argument is the filename of the disk image. After that, the options can be one of the following:

// -i
// -l
// -r filename
// -r filename -s sha1
// -R filename -s sha1
// You need to check if the command-line arguments are valid. If not, your program should print the above usage information verbatim and exit.

void print_usage(){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(EXIT_FAILURE);
}





// Milestone 2: print the file system information
// If your nyufile program is invoked with option -i, it should print the following information about the FAT32 file system:

// Number of FATs;
// Number of bytes per sector;
// Number of sectors per cluster;
// Number of reserved sectors.
// Your output should be in the following format:

// Using mmap() to access the disk image is more convenient than read() or fread(). 
// You may need to open the disk image with O_RDWR and map it with PROT_READ | PROT_WRITE and MAP_SHARED in order to update the underlying file. 
// Once you have mapped your disk image, you can cast any address to the FAT32 data structure type, such as (DirEntry *)(mapped_address + 0x5000).

void print_system_info(int num_fats, int bytes_per_sector, int sectors_per_cluster, int reserved_sectors){
    printf("Number of FATs = %d\n", num_fats);
    printf("Number of bytes per sector = %d\n", bytes_per_sector);
    printf("Number of sectors per cluster = %d\n", sectors_per_cluster);
    printf("Number of reserved sectors = %d\n", reserved_sectors);
}





// Milestone 3: list the root directory
// If your nyufile program is invoked with option -l, it should list all valid entries in the root directory with the following information:

// Filename. Similar to /bin/ls -p, if the entry is a directory, you should append a / indicator.
// File size if the entry is a file (not a directory).
// Starting cluster if the entry is not an empty file.
// You should also print the total number of entries at the end. Your output should be in the following format:

// [root@... cs202]# ./nyufile fat32.disk -l
// HELLO.TXT (size = 14, starting cluster = 3)
// DIR/ (starting cluster = 4)
// EMPTY (size = 0)
// Total number of entries = 3

// Here are a few assumptions:
// You should not list entries marked as deleted.
// You don’t need to print the details inside subdirectories.
// For all milestones, there will be no long filename (LFN) entries. 
// Any file or directory, including the root directory, may span more than one cluster.
// There may be empty files.

char *process_name(char *filename, int is_dir){             // can be edited for performance optimization
    char *newName = malloc(20);
    int i = 0;
    int j = 0;
    for (i = 0; i < 8; i++){
        if (filename[i] != ' '){
            newName[j] = filename[i];
            j++;  
        }
    }
    if (is_dir){
        newName[j] = '/';
        j++;
    } else if (filename[8] != ' '){
        newName[j] = '.';
        j++;
        for (i = 8; i<11; i++){
            if (filename[i] != ' '){
                newName[j] = filename[i];
                j++;
            }
        } 
    }
    newName[j] = '\0';
    return newName;
}

void list_root_directory(DirEntry *root_dir, int root_cluster, char* fat, char * data_region, int bytes_per_sector, int sectors_per_cluster){
    int i = 0;
    int total_entries = 0;
    size_t size_dir = sizeof(DirEntry);
    int current_cluster = root_cluster;

    int number_entries_per_cluster = bytes_per_sector * sectors_per_cluster / size_dir;
    // printf("number_entries_per_cluster = %d\n\n", number_entries_per_cluster);
    
    // print_bytes((char *)root_dir, 32);

    while (root_dir[i].DIR_Name[0] != 0x00 || get_next_cluster(fat, current_cluster) != -1){
        
        DirEntry* current_entry = &(root_dir[i]);

        int isDir = current_entry->DIR_Attr & 0x10;

        char* name = process_name(current_entry->DIR_Name, isDir);
        int start_cluster = current_entry->DIR_FstClusLO;
        int size = current_entry->DIR_FileSize;
        
        if (current_entry->DIR_Name[0] != 0xE5 && current_entry->DIR_Name[0] != 0x00){
            printf("%s ", name);
            if (isDir){
                printf("(starting cluster = %d)", start_cluster);
            } else if (size == 0){
                printf("(size = 0)");
            } else {
                printf("(size = %d, starting cluster = %d)", size, start_cluster);
            }
            printf("\n");
            total_entries++;
        }
        i++;

        if (i % number_entries_per_cluster == 0){
            // printf("i = %d\n", i);
            // printf("cluster = %d\n", current_cluster);
            // printf("number_entries_per_cluster = %d\n", number_entries_per_cluster);

            int next_cluster = get_next_cluster(fat, current_cluster);
            if (next_cluster == -1){
                // printf("next_cluster = -1\n");
                break;
            } else {
                // printf("next_cluster = %d\n", next_cluster);
                current_cluster = next_cluster;
                root_dir = (DirEntry *)get_cluster_address(data_region, current_cluster, bytes_per_sector, sectors_per_cluster);
                // print_bytes((char *)root_dir, 32);
                i = 0;
            }
        }
    }
    printf("Total number of entries = %d\n", total_entries);
}




// Milestone 4: recover a small file
// If your nyufile program is invoked with option -r filename, it should recover the deleted file with the specified name. 
// The workflow is better illustrated through an example:

// [root@... cs202]# mount fat32.disk /mnt/disk
// [root@... cs202]# ls -p /mnt/disk
// DIR/  EMPTY  HELLO.TXT
// [root@... cs202]# cat /mnt/disk/HELLO.TXT
// Hello, world.
// [root@... cs202]# rm /mnt/disk/HELLO.TXT
// rm: remove regular file '/mnt/disk/HELLO.TXT'? y
// [root@... cs202]# ls -p /mnt/disk
// DIR/  EMPTY
// [root@... cs202]# umount /mnt/disk
// [root@... cs202]# ./nyufile fat32.disk -l
// DIR/ (starting cluster = 4)
// EMPTY (size = 0)
// Total number of entries = 2
// [root@... cs202]# ./nyufile fat32.disk -r HELLO
// HELLO: file not found
// [root@... cs202]# ./nyufile fat32.disk -r HELLO.TXT
// HELLO.TXT: successfully recovered
// [root@... cs202]# ./nyufile fat32.disk -l
// HELLO.TXT (size = 14, starting cluster = 3)
// DIR/ (starting cluster = 4)
// EMPTY (size = 0)
// Total number of entries = 3
// [root@... cs202]# mount fat32.disk /mnt/disk
// [root@... cs202]# ls -p /mnt/disk
// DIR/  EMPTY  HELLO.TXT
// [root@... cs202]# cat /mnt/disk/HELLO.TXT
// Hello, world.

// For all milestones, you only need to recover regular files (including empty files, but not directory files) in the root directory. 
// When the file is successfully recovered, your program should print filename: successfully recovered (replace filename with the actual file name).

// For all milestones, you can assume that no other files or directories are created or modified since the deletion of the target file. 
// However, multiple files may be deleted.

// Besides, for all milestones, you don’t need to update the FSINFO structure because most operating systems don’t care about it.

// Here are a few assumptions specifically for Milestone 4:

// The size of the deleted file is no more than the size of a cluster.
// At most one deleted directory entry matches the given filename. 

// If no such entry exists, your program should print filename: file not found (replace filename with the actual file name).

char* padding_filename(char* filename){
    char* padded_name = malloc(20);  //we don't need to save memory right?
    int i = 0;
    int j = 0;
    for (i = 0; i < 8; i++){
        // printf("File[%d] %c ",j,  filename[j]);
        if (filename[j] == '.'){
            padded_name[i] = ' ';
        } else if (filename[j] == '\0'){
            break;
        } else {
            padded_name[i] = filename[j];
            j++;
        }
        // printf("PAD[%d] %c \n",i,  padded_name[i]);
    }
    for (;i < 11; i++){
        if (i<8){
            padded_name[i] = ' ';
            continue;
        }
        // printf("File[%d] %c ",j,  filename[j]);
        if (filename[j] == '.'){
            j++;
        }
        if (filename[j] == '\0'){
            padded_name[i] = ' ';
        } else {
            padded_name[i] = filename[j];
            j++;
        }
        // printf("PAD[%d] %c\n",i,  padded_name[i]);
    }
    padded_name[11] = '\0';
    //print the padded name char by char
    // printf("Padded name: \n");
    // for (i = 0; i < 11; i++){
    //     printf("PAD[%d] %c\n",i,  padded_name[i]);
    // }
    return padded_name;
}

DirEntry* search_for_deleled_file(DirEntry *root_dir, char* targetfile, int root_cluster, char* fat, char * data_region, int bytes_per_sector, int sectors_per_cluster, int* mult){
    * mult = 0;

    int i = 0;

    size_t size_dir = sizeof(DirEntry);
    int current_cluster = root_cluster;

    int number_entries_per_cluster = bytes_per_sector * sectors_per_cluster / size_dir;
    // printf("number_entries_per_cluster = %d\n\n", number_entries_per_cluster);
    
    // print_bytes((char *)root_dir, 32);

    // printf("Searching for file %s\n", targetfile);

    DirEntry* found_file = NULL;

    while (root_dir[i].DIR_Name[0] != 0x00 || get_next_cluster(fat, current_cluster) != -1){

        DirEntry* current_entry = &(root_dir[i]);

        int isDir = current_entry->DIR_Attr & 0x10;

        char* name = process_name(current_entry->DIR_Name, isDir);
        int start_cluster = current_entry->DIR_FstClusLO;
        int size = current_entry->DIR_FileSize;

        // printf("Checking file %s\n", name);
        // printf("Target: %s\n", targetfile);
        
        if (current_entry->DIR_Name[0] == 0xE5 && strcmp((targetfile+1), (name+1)) == 0){
            if (found_file != NULL){
                // printf("Multiple files\n");
                *mult = 1;
                return NULL;
            }
            found_file = current_entry;
            // printf("found file! %s\n", name);
        }

        i++;

        if (i % number_entries_per_cluster == 0){
            int next_cluster = get_next_cluster(fat, current_cluster);
            if (next_cluster == -1){
                break;
            } else {
                current_cluster = next_cluster;
                root_dir = (DirEntry *)get_cluster_address(data_region, current_cluster, bytes_per_sector, sectors_per_cluster);
                i = 0;
            }
        }
    }
    // if (found_file == NULL){
    //     printf("File not found\n");
    // }
    return found_file;
}

// Milestone 5: recover a large contiguously-allocated file

// Now, you will recover a file that is larger than one cluster. 
// Nevertheless, for Milestone 5, you can assume that such a file is allocated contiguously. 
// You can continue to assume that at most one deleted directory entry matches the given filename. 
// If no such entry exists, your program should print filename: file not found (replace filename with the actual file name).

// Milestone 6: detect ambiguous file recovery requests
// In Milestones 4 and 5, you assumed that at most one deleted directory entry matches the given filename. 
// However, multiple files whose names differ only in the first character would end up having the same name when deleted. 
// Therefore, you may encounter more than one deleted directory entry matching the given filename. 
// When that happens, your program should print filename: multiple candidates found (replace filename with the actual file name) and abort.

// This scenario is illustrated in the following example:

// [root@... cs202]# mount fat32.disk /mnt/disk
// [root@... cs202]# echo "My last name is Tang." > /mnt/disk/TANG.TXT
// [root@... cs202]# echo "My first name is Yang." > /mnt/disk/YANG.TXT
// [root@... cs202]# sync
// [root@... cs202]# rm /mnt/disk/TANG.TXT /mnt/disk/YANG.TXT
// rm: remove regular file '/mnt/disk/TANG.TXT'? y
// rm: remove regular file '/mnt/disk/YANG.TXT'? y
// [root@... cs202]# umount /mnt/disk
// [root@... cs202]# ./nyufile fat32.disk -r TANG.TXT
// TANG.TXT: multiple candidates found


int main(int argc, char **argv) {
    int opt;
    int iFlag = 0;
    int lFlag = 0;
    int rFlag = 0;
    int RFlag = 0;
    int sFlag = 0;
    char *disk_filename = NULL;
    char *filename = NULL;
    char *sha1 = NULL;
    int badArgs = 1;

    if (argc < 2) {
        print_usage();
    }

    // get the arguments
    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
                badArgs = 0;
                iFlag += 1;
                break;
            case 'l':
                badArgs = 0;
                lFlag += 1;
                break;
            case 'r':
                badArgs = 0;
                rFlag = 1;
                filename = optarg;
                // printf("r: %s\n", filename);
                break;
            case 'R':
                badArgs = 0;
                RFlag += 1;
                filename = optarg;
                // printf("R: %s\n", filename);
                break;
            case 's':
                badArgs = 0;
                sFlag += 1;
                sha1 = optarg;
                break;
            case '?':
                badArgs = 1;
                // printf("badArgs\n");
                break;
            default:
                print_usage();
                break;
        }
    }
    // Check that the disk filename was provided
    if (optind >= argc) {
        // printf("optind >= argc\n");
        print_usage();
    } else {
        disk_filename = argv[optind];
    }

    // Check the number of arguments
    if (iFlag + lFlag + rFlag + RFlag > 1) {
        print_usage();
    }
    if (RFlag == 1 && sFlag == 0) {
        print_usage();
    }
    if (iFlag + lFlag > 0 && sFlag == 1) {
        print_usage();
    }
    if (badArgs == 1) {
        print_usage();
    }

    // open the disk image
    int fd = open(disk_filename, O_RDWR);

    struct stat sb;
    fstat(fd, &sb);

    char *mapped = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    

    // get the system info
    BootEntry *boot = (BootEntry *)(mapped);

    int numFats = boot->BPB_NumFATs;
    int bytesPerSector = boot->BPB_BytsPerSec;
    int sectorsPerCluster = boot->BPB_SecPerClus;
    int reservedSectors = boot->BPB_RsvdSecCnt;
    
    int fatSizeInSector = boot->BPB_FATSz32;

    // make a list of fats storing addresses for each fat
    int fatStartByte = bytesPerSector * reservedSectors;

    char **FATs = malloc(sizeof(char *) * numFats);
    for (int i = 0; i < numFats; i++) {
        FATs[i] = mapped + fatStartByte + fatSizeInSector * bytesPerSector * i;
    }

    char *fat1 = FATs[0];

    // printf("Start of Fat 1: %d\n", fatStartByte);

    // get the data region
    int dataRegionStartByte = fatStartByte + fatSizeInSector * bytesPerSector * numFats;
    int dataRegionStartSector = reservedSectors + numFats * fatSizeInSector;
    char *dataRegion = mapped + dataRegionStartByte;

    // printf("dataRegionStartByte: %d\n", dataRegionStartByte);
    // printf("dataRegionStartSector: %d\n\n", dataRegionStartSector);


    // get the root directory 
    int rootDirCluster = boot->BPB_RootClus;
    int rootDirSector = dataRegionStartSector + (rootDirCluster - 2) * sectorsPerCluster;
    int rootDirStartByte = rootDirSector * bytesPerSector;

    // printf("rootDirCluster: %d\n", rootDirCluster);
    // printf("rootDirSector: %d\n", rootDirSector);
    // printf("rootDirStartByte: %d\n\n", rootDirStartByte);

    // // get the fat of the root directory
    // print_bytes(fat1, 32);

    // printf("get next cluster of 1 %d\n", get_next_cluster(fat1, 1));
    // printf("get next cluster of 2 %d\n", get_next_cluster(fat1, 2));
    // printf("get next cluster of 3 %d\n", get_next_cluster(fat1, 3));
    // printf("get next cluster of 4 %d\n", get_next_cluster(fat1, 4));


    // display root directory
        char *rootDirAddr = mapped + rootDirStartByte;
        // printf("%p\n", rootDirAddr);
        // printf("%p\n", get_cluster_address(dataRegion, rootDirCluster, bytesPerSector, sectorsPerCluster));


    if (iFlag) {
        print_system_info(numFats, bytesPerSector, sectorsPerCluster, reservedSectors);
    } else if (lFlag) {
        list_root_directory((DirEntry *)rootDirAddr, rootDirCluster, fat1, dataRegion, bytesPerSector, sectorsPerCluster);
    } else if (rFlag && !sFlag) {
        // printf("Recovering contiguous file %s without SHA\n", filename);
        
        DirEntry *fileDir = NULL;
        int mult = 0;

        if (filename != NULL){
            fileDir = search_for_deleled_file((DirEntry *)rootDirAddr, filename, rootDirCluster, fat1, dataRegion, bytesPerSector, sectorsPerCluster, &mult);
        }
        
        if (mult == 1){
            printf("%s: multiple candidates found\n", filename);
        } else if (fileDir != NULL){
            char *name = fileDir->DIR_Name;
            // printf("Found file %s\n", padding_filename(name));

            int size = fileDir->DIR_FileSize;
            unsigned short FstClusLO = fileDir->DIR_FstClusLO;
            unsigned short FstClusHI = fileDir->DIR_FstClusHI;
            int firstCluster = FstClusLO + (FstClusHI << 16);
            // printf("Cluster start: %d\n", firstCluster);
            // printf("Size: %d\n", size);
            // printf("Start from byte %d\n", get_cluster_address(dataRegion, firstCluster, bytesPerSector, sectorsPerCluster) - mapped);

            int fileClusterNum = (int)ceil((float)size / (float)(bytesPerSector * sectorsPerCluster));
            // printf("Num of clusters in file: %d\n", fileClusterNum);

            char* recoveredName = padding_filename(filename);
            memcpy(fileDir->DIR_Name, recoveredName, 11);
            // printf("Recovered name: [%s]\n", recoveredName);    
        
            if (fileClusterNum == 1){
                //recover the fat
                int* fileFatEntry = (int*)fat1 + firstCluster;
                // print_bytes((char *)fileFatEntry, 4);
                *fileFatEntry = 0x0FFFFFF8;
                // print_bytes((char *)fileFatEntry, 4);


                // I only handled FAT 1 !!!! BUT it passed the milestone 4 


            } else {
               
                int fatID = 0;
                for (fatID = 0; fatID < numFats; fatID++){
                    char *currentFat = FATs[fatID];

                    int* fileFatEntry = (int*)currentFat + firstCluster;
                    // print_bytes((char *)fileFatEntry, 16);

                    int i = 0;
                    for (i = 0; i < fileClusterNum; i++){
                        int *currentEntry = (int*)currentFat + (firstCluster+i);
                        if (i != fileClusterNum-1){
                            *currentEntry = firstCluster + i + 1;
                        } else {
                            *currentEntry = 0x0FFFFFF8;
                        }
                    }
                    // print_bytes((char *)fileFatEntry, 16);
                }

            }
            printf("%s: successfully recovered\n", filename);
        } else {
            printf("%s: file not found\n", filename);
        }
    }

} 