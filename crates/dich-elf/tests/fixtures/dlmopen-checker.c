#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) { if (argc != 4) return 2; void *dep=dlmopen(LM_ID_NEWLM,argv[1],RTLD_NOW|RTLD_LOCAL); if(!dep){fprintf(stderr,"dep: %s\n",dlerror());return 3;} Lmid_t ns; if(dlinfo(dep,RTLD_DI_LMID,&ns)!=0)return 4; void *plugin=dlmopen(ns,argv[2],RTLD_NOW|RTLD_LOCAL); if(!plugin){fprintf(stderr,"plugin: %s\n",dlerror());return 5;} int (*value)(void)=(int(*)(void))dlsym(plugin,"plugin_value"); if(!value)return 6; int got=value(), want=atoi(argv[3]); if(got!=want){fprintf(stderr,"got %d want %d\n",got,want);return 7;} dlclose(plugin); dlclose(dep); return 0; }
